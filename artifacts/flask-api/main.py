import json
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta

import psycopg2
import psycopg2.extras
from flask import Flask, g, jsonify, request, send_from_directory
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

PREFIX = ""

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Paths served without authentication (no API key and no dashboard login).
PUBLIC_PATHS = {"/api/healthz", "/", "/favicon.ico", "/api/dashboard/login"}

# Write endpoints a non-owner (DM / store) account may still call (POST only).
# Everything else that mutates data is owner-only. DMs/stores can request point
# redemptions for their own stores; an owner approves them.
NON_OWNER_WRITE_ALLOWED = {"/api/redemptions", "/api/me/password"}
WRITE_METHODS = {"POST", "PATCH", "PUT", "DELETE"}

# Dashboard sessions: a short-lived token signed with SESSION_SECRET, encoding the
# user id + role. The real API key is never sent to the browser.
DASHBOARD_TOKEN_MAX_AGE = 60 * 60 * 12  # 12 hours
_SESSION_SECRET = os.environ.get("SESSION_SECRET")
if not _SESSION_SECRET:
    raise RuntimeError("SESSION_SECRET must be set for dashboard authentication")
_token_serializer = URLSafeTimedSerializer(_SESSION_SECRET, salt="dashboard-auth")

# Brute-force throttle for the login endpoint, stored in Postgres so the limit
# holds across all gunicorn workers (in-memory counters would be per-worker).
LOGIN_FAIL_WINDOW = 300   # seconds
LOGIN_MAX_FAILS = 10      # failed attempts per IP within the window

# platform_admin = Slicework operator (cross-org); the other three live inside one org.
ROLES = {"platform_admin", "owner", "dm", "store"}
ORG_ROLES = {"owner", "dm", "store"}
SUPERVISOR_ROLES = {"platform_admin", "owner"}


def _client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    return fwd.split(",")[0].strip() if fwd else (request.remote_addr or "unknown")


def issue_dashboard_token(user_id, role):
    return _token_serializer.dumps({"uid": user_id, "role": role})


def get_db():
    if "db" not in g:
        g.db = psycopg2.connect(
            os.environ["DATABASE_URL"],
            cursor_factory=psycopg2.extras.RealDictCursor,
        )
        g.db.autocommit = False
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        if exc is not None:
            db.rollback()
        db.close()


def rows_to_list(cursor):
    return [dict(r) for r in cursor.fetchall()]


def row_to_dict(cursor):
    row = cursor.fetchone()
    return dict(row) if row else None


# ── Schema setup ──────────────────────────────────────────────────────────────

def init_db():
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            employee_id  TEXT PRIMARY KEY,
            name         TEXT NOT NULL,
            position     TEXT,
            store        TEXT,
            created_at   TIMESTAMP DEFAULT NOW()
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS attendance_logs (
            id               SERIAL PRIMARY KEY,
            employee_id      TEXT REFERENCES employees(employee_id) ON DELETE CASCADE,
            date             TEXT,
            clock_in         TEXT,
            clock_out        TEXT,
            hours            NUMERIC,
            status           TEXT,
            scheduled_start  TEXT,
            minutes_late     INTEGER,
            notes            TEXT,
            created_at       TIMESTAMP DEFAULT NOW()
        )
    """)
    cur.execute(
        "ALTER TABLE attendance_logs ADD COLUMN IF NOT EXISTS manual_points NUMERIC"
    )
    # Soft-deactivation (termination): inactive employees keep their history but
    # drop out of stats, stage math, and attention views.
    cur.execute(
        "ALTER TABLE employees ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE"
    )
    cur.execute("ALTER TABLE employees ADD COLUMN IF NOT EXISTS terminated_at DATE")
    cur.execute("ALTER TABLE employees ADD COLUMN IF NOT EXISTS terminated_by TEXT")
    cur.execute("ALTER TABLE employees ADD COLUMN IF NOT EXISTS terminated_note TEXT")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS shift_swaps (
            id              SERIAL PRIMARY KEY,
            requester_id    TEXT REFERENCES employees(employee_id) ON DELETE CASCADE,
            recipient_id    TEXT REFERENCES employees(employee_id) ON DELETE CASCADE,
            shift_date      TEXT,
            original_shift  TEXT,
            swapped_shift   TEXT,
            status          TEXT DEFAULT 'pending',
            notes           TEXT,
            created_at      TIMESTAMP DEFAULT NOW()
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id            SERIAL PRIMARY KEY,
            ip            TEXT NOT NULL,
            attempted_at  TIMESTAMP DEFAULT NOW()
        )
    """)
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time "
        "ON login_attempts (ip, attempted_at)"
    )
    cur.execute("""
        CREATE TABLE IF NOT EXISTS point_redemptions (
            id               SERIAL PRIMARY KEY,
            employee_id      TEXT REFERENCES employees(employee_id) ON DELETE CASCADE,
            redemption_type  TEXT NOT NULL,
            points_removed   NUMERIC NOT NULL,
            date             TEXT NOT NULL,
            notes            TEXT,
            status           TEXT DEFAULT 'pending',
            submitted_by     TEXT,
            reviewed_by      TEXT,
            created_at       TIMESTAMP DEFAULT NOW()
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS point_resets (
            id           SERIAL PRIMARY KEY,
            store        TEXT NOT NULL,
            reset_date   TEXT NOT NULL,
            reason       TEXT,
            created_by   TEXT,
            created_at   TIMESTAMP DEFAULT NOW()
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS imported_batches (
            store        TEXT,
            date         TEXT,
            imported_at  TIMESTAMP DEFAULT NOW(),
            PRIMARY KEY (store, date)
        )
    """)
    cur.execute("SELECT COUNT(*) AS n FROM imported_batches")
    if cur.fetchone()["n"] == 0:
        cur.execute("""
            INSERT INTO imported_batches (store, date)
            SELECT DISTINCT e.store, l.date
            FROM attendance_logs l
            JOIN employees e ON l.employee_id = e.employee_id
            WHERE e.store IS NOT NULL AND l.date IS NOT NULL
            ON CONFLICT DO NOTHING
        """)

    # ── User hierarchy: owner / dm / store ──────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            SERIAL PRIMARY KEY,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL,
            store         TEXT,
            created_at    TIMESTAMP DEFAULT NOW()
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS stores (
            store       TEXT PRIMARY KEY,
            name        TEXT,
            dm_user_id  INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_at  TIMESTAMP DEFAULT NOW()
        )
    """)
    # Seed the store list from whatever stores already have employees.
    cur.execute(
        "INSERT INTO stores (store) SELECT DISTINCT store FROM employees "
        "WHERE store IS NOT NULL ON CONFLICT DO NOTHING"
    )
    # Seed the first owner so there is a way in. Reuses the existing
    # SUPERVISOR_PASSWORD (or OWNER_PASSWORD) and username OWNER_USERNAME ('owner').
    cur.execute("SELECT COUNT(*) AS n FROM users WHERE role = 'owner'")
    if cur.fetchone()["n"] == 0:
        owner_user = (os.environ.get("OWNER_USERNAME") or "owner").strip().lower()
        owner_pw = os.environ.get("OWNER_PASSWORD") or os.environ.get("SUPERVISOR_PASSWORD")
        if owner_pw:
            cur.execute(
                "INSERT INTO users (username, password_hash, role) "
                "VALUES (%s, %s, 'owner') ON CONFLICT (username) DO NOTHING",
                (owner_user, generate_password_hash(owner_pw)),
            )

    # ── Multi-tenancy: organizations (franchisee groups) ────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS orgs (
            id          SERIAL PRIMARY KEY,
            name        TEXT NOT NULL,
            slug        TEXT UNIQUE NOT NULL,
            created_at  TIMESTAMP DEFAULT NOW()
        )
    """)
    cur.execute(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
        "org_id INTEGER REFERENCES orgs(id) ON DELETE SET NULL"
    )
    cur.execute(
        "ALTER TABLE stores ADD COLUMN IF NOT EXISTS "
        "org_id INTEGER REFERENCES orgs(id) ON DELETE SET NULL"
    )
    # Per-org Pulse (PWR) credentials. The password is RSA-encrypted with the
    # scrape worker's PUBLIC key at submission time; this server never holds a
    # decryption key, so the stored value is unreadable to the web app.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS pulse_credentials (
            id               SERIAL PRIMARY KEY,
            org_id           INTEGER UNIQUE NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            pwr_username     TEXT NOT NULL,
            enc_password     TEXT NOT NULL,
            status           TEXT DEFAULT 'pending',
            status_detail    TEXT,
            updated_by       TEXT,
            updated_at       TIMESTAMP DEFAULT NOW(),
            last_checked_at  TIMESTAMP
        )
    """)
    # Scrape health ledger: one row per (org, store, business date) attempt,
    # reported by the worker. Powers the in-app data-freshness display.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scrape_runs (
            id             SERIAL PRIMARY KEY,
            org_id         INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            store          TEXT NOT NULL,
            run_date       TEXT NOT NULL,
            status         TEXT NOT NULL,
            rows_imported  INTEGER,
            error          TEXT,
            started_at     TIMESTAMP,
            finished_at    TIMESTAMP,
            reported_at    TIMESTAMP DEFAULT NOW()
        )
    """)
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_scrape_runs_store_date "
        "ON scrape_runs (org_id, store, run_date DESC)"
    )
    # Per-org point rules (JSON overrides merged over DEFAULT_POINT_CONFIG).
    cur.execute("ALTER TABLE orgs ADD COLUMN IF NOT EXISTS point_config JSONB")
    # Per-org feature switches (JSON overrides merged over DEFAULT_FEATURES).
    cur.execute("ALTER TABLE orgs ADD COLUMN IF NOT EXISTS features JSONB")
    # Written-documentation obligations: one open row per employee while they
    # sit in a disciplinary stage that requires a documented write-up (only
    # for orgs with the written_docs feature on). Non-open rows are the audit
    # trail: resolved = someone attested the write-up happened; lapsed = the
    # employee dropped out of a documentation stage before it was done;
    # superseded = replaced by an obligation at a different stage.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS doc_obligations (
            id           SERIAL PRIMARY KEY,
            org_id       INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
            employee_id  TEXT REFERENCES employees(employee_id) ON DELETE CASCADE,
            store        TEXT,
            stage        TEXT NOT NULL,
            points       NUMERIC,
            status       TEXT DEFAULT 'open',
            opened_at    TIMESTAMP DEFAULT NOW(),
            resolved_by  TEXT,
            resolved_at  TIMESTAMP,
            method       TEXT,
            note         TEXT
        )
    """)
    cur.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_doc_obligations_one_open "
        "ON doc_obligations (employee_id) WHERE status = 'open'"
    )
    # Operational alerts surfaced on the dashboard (e.g. a terminated employee
    # clocking in). Rows stay until someone acknowledges them.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id               SERIAL PRIMARY KEY,
            org_id           INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
            store            TEXT,
            employee_id      TEXT REFERENCES employees(employee_id) ON DELETE CASCADE,
            kind             TEXT NOT NULL,
            message          TEXT,
            created_at       TIMESTAMPTZ DEFAULT NOW(),
            acknowledged_at  TIMESTAMPTZ,
            acknowledged_by  TEXT
        )
    """)
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_unacked "
        "ON alerts (store) WHERE acknowledged_at IS NULL"
    )
    # How many people actually had a scheduled shift that store/day, reported
    # by the worker alongside imports. Logs can't answer this: they are
    # exception-based, so a clean day produces no rows at all.
    cur.execute(
        "ALTER TABLE imported_batches ADD COLUMN IF NOT EXISTS scheduled_count INTEGER"
    )
    # On-demand scrape queue: platform admin queues targeted pulls (e.g. only
    # stores whose data is missing/stale); the worker polls and executes them.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scrape_requests (
            id            SERIAL PRIMARY KEY,
            org_id        INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
            stores        TEXT[] NOT NULL,
            run_date      TEXT NOT NULL,
            status        TEXT DEFAULT 'pending',
            detail        TEXT,
            requested_by  TEXT,
            created_at    TIMESTAMP DEFAULT NOW(),
            started_at    TIMESTAMP,
            finished_at   TIMESTAMP
        )
    """)
    # Migrate single-tenant data: anything without an org joins the default org.
    cur.execute("SELECT COUNT(*) AS n FROM orgs")
    if cur.fetchone()["n"] == 0:
        default_name = os.environ.get("DEFAULT_ORG_NAME", "DTID Pizza")
        default_slug = re.sub(r"[^a-z0-9]+", "-", default_name.lower()).strip("-") or "default"
        cur.execute("INSERT INTO orgs (name, slug) VALUES (%s, %s)", (default_name, default_slug))
    cur.execute("SELECT id FROM orgs ORDER BY id LIMIT 1")
    default_org = cur.fetchone()["id"]
    cur.execute("UPDATE stores SET org_id = %s WHERE org_id IS NULL", (default_org,))
    cur.execute(
        "UPDATE users SET org_id = %s WHERE org_id IS NULL AND role != 'platform_admin'",
        (default_org,),
    )
    db.commit()


# ── Auth ──────────────────────────────────────────────────────────────────────

def load_user_from_token(token):
    if not token:
        return None
    try:
        data = _token_serializer.loads(token, max_age=DASHBOARD_TOKEN_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None
    uid = data.get("uid") if isinstance(data, dict) else None
    if not uid:
        return None
    cur = get_db().cursor()
    cur.execute(
        "SELECT u.id, u.username, u.role, u.store, u.org_id, o.name AS org_name "
        "FROM users u LEFT JOIN orgs o ON o.id = u.org_id WHERE u.id = %s",
        (uid,),
    )
    return row_to_dict(cur)


@app.before_request
def require_auth():
    if request.path in PUBLIC_PATHS:
        return None

    # 1) Dashboard user (signed token)
    user = load_user_from_token(request.headers.get("X-Dashboard-Token"))
    if user:
        g.user = user
        if user["role"] not in SUPERVISOR_ROLES and request.method in WRITE_METHODS:
            allowed = request.path in NON_OWNER_WRITE_ALLOWED and request.method == "POST"
            # GMs and DMs may attest that a required write-up was completed
            # for their own stores; the store-scope check lives in the endpoint.
            if request.method == "POST" and re.fullmatch(r"/api/doc-obligations/\d+/resolve", request.path):
                allowed = True
            # DMs may also correct attendance logs and approve/deny redemptions
            # for their own stores; the store-scope check lives in the endpoint.
            if user["role"] == "dm" and request.method in ("PATCH", "DELETE"):
                if re.fullmatch(r"/api/logs/\d+", request.path):
                    allowed = True
                elif re.fullmatch(r"/api/redemptions/\d+", request.path):
                    allowed = True
            # DMs may terminate/reactivate employees and acknowledge alerts for
            # their own stores; the store-scope check lives in the endpoint.
            if user["role"] == "dm" and request.method == "POST":
                if re.fullmatch(r"/api/employees/[^/]+/(terminate|reactivate)", request.path):
                    allowed = True
                elif re.fullmatch(r"/api/alerts/\d+/ack", request.path):
                    allowed = True
            if not allowed:
                return jsonify({"error": "You don't have permission to make changes."}), 403
        return None

    # 2) Service account (the agent) via API key = full access, no store scoping
    api_key = os.environ.get("ATTENDANCE_API_KEY")
    if not api_key:
        return jsonify({"error": "Server misconfiguration: ATTENDANCE_API_KEY not set"}), 500
    if request.headers.get("X-API-Key") != api_key:
        return jsonify({"error": "Unauthorized: missing or invalid credentials"}), 401
    g.user = None
    return None


def current_user():
    return getattr(g, "user", None)


# Hardcoded, additive store access for specific DM accounts, keyed by lowercase
# username. This grants access WITHOUT touching `stores.dm_user_id`, so it never
# displaces the store's normal assigned DM. Used for automation/agent accounts
# that need a fixed multi-store scope independent of the single-DM-per-store
# assignment mechanism.
HARDCODED_DM_STORE_ACCESS = {
    "c3po": {"2501", "2545", "2556", "2557"},
}


def org_view_id():
    """Optional org filter for platform-admin sessions: the X-Org-View header
    (set by the dashboard's org switcher) narrows a platform admin's view to
    one organization. Ignored for every other caller, including the API key,
    so worker/import semantics are untouched."""
    user = getattr(g, "user", None)
    if user is None or user["role"] != "platform_admin":
        return None
    raw = request.headers.get("X-Org-View") or request.args.get("org_view")
    try:
        return int(raw) if raw else None
    except (TypeError, ValueError):
        return None


def allowed_stores():
    """Set of store numbers the caller may see, or None for full access
    (platform admin / API key). Org owners are scoped to their org's stores —
    this is the tenant-isolation chokepoint every data query flows through."""
    if hasattr(g, "_allowed"):
        return g._allowed
    user = getattr(g, "user", None)
    if user is None:
        g._allowed = None
    elif user["role"] == "platform_admin":
        org_view = org_view_id()
        if org_view:
            cur = get_db().cursor()
            cur.execute("SELECT store FROM stores WHERE org_id = %s", (org_view,))
            g._allowed = {r["store"] for r in cur.fetchall()}
        else:
            g._allowed = None
    elif user["role"] == "owner":
        cur = get_db().cursor()
        cur.execute("SELECT store FROM stores WHERE org_id = %s", (user.get("org_id"),))
        g._allowed = {r["store"] for r in cur.fetchall()}
    elif user["role"] == "store":
        g._allowed = {user["store"]} if user.get("store") else set()
    elif user["role"] == "dm":
        cur = get_db().cursor()
        cur.execute("SELECT store FROM stores WHERE dm_user_id = %s", (user["id"],))
        allowed = {r["store"] for r in cur.fetchall()}
        allowed |= HARDCODED_DM_STORE_ACCESS.get(user["username"].lower(), set())
        g._allowed = allowed
    else:
        g._allowed = set()
    return g._allowed


def store_scope_clause(column):
    """Return (sql_fragment, params) to AND a store-scope filter into a query.
    Empty fragment when the caller has full access."""
    allowed = allowed_stores()
    if allowed is None:
        return "", []
    return f" AND {column} = ANY(%s)", [list(allowed)]


def require_owner():
    user = current_user()
    if user is None:  # API key = full access
        return None
    if user["role"] not in SUPERVISOR_ROLES:
        return jsonify({"error": "Owner access required"}), 403
    return None


def require_platform_admin():
    user = current_user()
    if user is None:  # API key = platform scope
        return None
    if user["role"] != "platform_admin":
        return jsonify({"error": "Platform admin access required"}), 403
    return None


# ── Dashboard (public page) ───────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def dashboard():
    return send_from_directory(BASE_DIR, "dashboard.html")


@app.route("/api/dashboard/login", methods=["POST"])
def dashboard_login():
    ip = _client_ip()
    db = get_db()
    cur = db.cursor()
    cutoff = datetime.utcnow() - timedelta(seconds=LOGIN_FAIL_WINDOW)
    cur.execute("DELETE FROM login_attempts WHERE attempted_at < %s", (cutoff,))
    cur.execute(
        "SELECT COUNT(*) AS n FROM login_attempts WHERE ip = %s AND attempted_at >= %s",
        (ip, cutoff),
    )
    if cur.fetchone()["n"] >= LOGIN_MAX_FAILS:
        db.commit()
        return jsonify({"error": "Too many attempts. Please wait a few minutes and try again."}), 429

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    supplied = data.get("password", "")
    if not isinstance(supplied, str):
        supplied = ""

    cur.execute(
        "SELECT u.id, u.username, u.password_hash, u.role, u.org_id, o.name AS org_name "
        "FROM users u LEFT JOIN orgs o ON o.id = u.org_id WHERE u.username = %s",
        (username,),
    )
    user = cur.fetchone()
    if not user or not check_password_hash(user["password_hash"], supplied):
        cur.execute("INSERT INTO login_attempts (ip) VALUES (%s)", (ip,))
        db.commit()
        return jsonify({"error": "Invalid username or password"}), 401

    cur.execute("DELETE FROM login_attempts WHERE ip = %s", (ip,))
    db.commit()
    return jsonify({
        "token": issue_dashboard_token(user["id"], user["role"]),
        "role": user["role"],
        "username": user["username"],
        "org_id": user["org_id"],
        "org_name": user["org_name"],
        "expires_in": DASHBOARD_TOKEN_MAX_AGE,
    })


# ── Health ────────────────────────────────────────────────────────────────────

@app.route("/api/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat()})


# ── Import ────────────────────────────────────────────────────────────────────

def _resolve_import_org():
    """Org that incoming data belongs to. Dashboard callers use their own org.
    API-key callers pass X-Org-Slug (multi-tenant worker); with no header the
    default (oldest) org is used so the legacy single-org pipeline keeps working.
    Returns (org_id, error_response)."""
    user = current_user()
    if user is not None and user.get("org_id"):
        return user["org_id"], None
    cur = get_db().cursor()
    slug = (request.headers.get("X-Org-Slug") or "").strip().lower()
    if slug:
        cur.execute("SELECT id FROM orgs WHERE slug = %s", (slug,))
        row = cur.fetchone()
        if not row:
            return None, (jsonify({"error": f"Unknown org slug: {slug}"}), 400)
        return row["id"], None
    cur.execute("SELECT id FROM orgs ORDER BY id LIMIT 1")
    row = cur.fetchone()
    if not row:
        return None, (jsonify({"error": "No organizations exist yet"}), 400)
    return row["id"], None


def _ensure_store(cur, store, org_id):
    """Upsert a store row for an import. The first time a store appears for an
    org, also provision its dashboard login: username = password = the store
    number (role 'store', scoped to that store). GMs change the password from
    the key icon in the top bar. Never touches existing usernames."""
    cur.execute("SELECT store FROM stores WHERE store = %s", (store,))
    is_new = cur.fetchone() is None
    cur.execute(
        "INSERT INTO stores (store, org_id) VALUES (%s, %s) "
        "ON CONFLICT (store) DO UPDATE SET org_id = COALESCE(stores.org_id, EXCLUDED.org_id)",
        (store, org_id),
    )
    if is_new and org_id:
        cur.execute(
            "INSERT INTO users (username, password_hash, role, store, org_id) "
            "VALUES (%s, %s, 'store', %s, %s) ON CONFLICT (username) DO NOTHING",
            (store, generate_password_hash(store), store, org_id),
        )


@app.route("/api/import", methods=["POST"])
def import_attendance():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    records = data if isinstance(data, list) else data.get("records", [])
    if not isinstance(records, list):
        return jsonify({"error": "Expected a JSON array or {records: [...]}"}), 400

    org_id, org_err = _resolve_import_org()
    if org_err:
        return org_err

    db = get_db()
    cur = db.cursor()

    cur.execute("SELECT store, date FROM imported_batches")
    already_imported = {(r["store"], r["date"]) for r in cur.fetchall()}

    imported_employees = 0
    imported_logs = 0
    skipped_logs = 0
    new_batches = set()
    seen_stores = set()
    errors = []

    alerts_created = 0

    for i, record in enumerate(records):
        employee_id = record.get("employee_id") or record.get("employeeId")
        name = record.get("name")

        if not employee_id or not name:
            errors.append({"index": i, "error": "employee_id and name are required"})
            continue

        store = record.get("store")
        if store and store not in seen_stores:
            seen_stores.add(store)
            _ensure_store(cur, store, org_id)

        cur.execute(
            """
            INSERT INTO employees (employee_id, name, position, store)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (employee_id) DO UPDATE SET
                name     = EXCLUDED.name,
                position = COALESCE(EXCLUDED.position, employees.position),
                store    = COALESCE(EXCLUDED.store, employees.store)
            RETURNING name, store, active, terminated_at
            """,
            (employee_id, name, record.get("position"), store),
        )
        emp_row = row_to_dict(cur)
        imported_employees += 1

        for log in record.get("logs", []):
            date = log.get("date")
            if not date:
                continue
            if (store, date) in already_imported:
                skipped_logs += 1
                continue
            # A terminated employee showing up in a punch/violation log on or
            # after their last day means someone clocked them in anyway: raise
            # a DM-facing alert instead of silently importing the row.
            if (emp_row and not emp_row["active"] and emp_row["terminated_at"]
                    and date >= str(emp_row["terminated_at"])):
                alerts_created += _terminated_clock_in_alert(cur, org_id, emp_row, employee_id, date)
                skipped_logs += 1
                continue

            clock_in = log.get("clock_in") or log.get("clockIn")
            scheduled_start = log.get("scheduled_start") or log.get("scheduledStart")
            minutes_late = log.get("minutes_late") or log.get("minutesLate")
            if minutes_late is None:
                minutes_late = calc_minutes_late(scheduled_start, clock_in)

            cur.execute(
                """
                INSERT INTO attendance_logs
                    (employee_id, date, clock_in, clock_out, hours,
                     status, scheduled_start, minutes_late, notes)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    employee_id, date, clock_in,
                    log.get("clock_out") or log.get("clockOut"),
                    log.get("hours"), log.get("status"),
                    scheduled_start, minutes_late, log.get("notes"),
                ),
            )
            imported_logs += 1
            if store is not None:
                new_batches.add((store, date))

    for store, date in new_batches:
        cur.execute(
            "INSERT INTO imported_batches (store, date) VALUES (%s, %s) ON CONFLICT DO NOTHING",
            (store, date),
        )

    # Per-store/day scheduled headcounts. Upserted independently of the
    # duplicate-log guard: a violation-free day still gets its batch row, and
    # a re-pull refreshes the count.
    day_stats = data.get("day_stats") if isinstance(data, dict) else None
    for ds in day_stats or []:
        store, date = ds.get("store"), ds.get("date")
        count = ds.get("scheduled_count")
        if not store or not date or count is None:
            continue
        _ensure_store(cur, store, org_id)
        cur.execute(
            "INSERT INTO imported_batches (store, date, scheduled_count) VALUES (%s, %s, %s) "
            "ON CONFLICT (store, date) DO UPDATE SET scheduled_count = EXCLUDED.scheduled_count",
            (store, date, int(count)),
        )

    db.commit()
    response = {
        "imported_employees": imported_employees,
        "imported_logs": imported_logs,
        "skipped_logs": skipped_logs,
        "alerts_created": alerts_created,
    }
    if errors:
        response["errors"] = errors
    return jsonify(response), 201


def _terminated_clock_in_alert(cur, org_id, emp, employee_id, date):
    """Record a 'terminated employee clocked in' alert, deduped: repeated
    imports of the same day's data must not stack duplicates, so skip when an
    unacknowledged alert for the same employee/day (identical message) already
    exists. Returns how many alerts were created (0 or 1)."""
    message = (
        f"Terminated employee {emp['name']} ({employee_id}) has an attendance "
        f"record at store {emp['store']} on {date} — their last day was "
        f"{emp['terminated_at']}."
    )
    cur.execute(
        "SELECT 1 FROM alerts WHERE kind = 'terminated_clock_in' "
        "AND employee_id = %s AND message = %s AND acknowledged_at IS NULL",
        (employee_id, message),
    )
    if cur.fetchone():
        return 0
    cur.execute(
        "INSERT INTO alerts (org_id, store, employee_id, kind, message) "
        "VALUES (%s, %s, %s, 'terminated_clock_in', %s)",
        (org_id, emp["store"], employee_id, message),
    )
    return 1


# ── Helpers ───────────────────────────────────────────────────────────────────

def calc_minutes_late(scheduled_start, clock_in):
    if not scheduled_start or not clock_in:
        return None
    try:
        fmt = "%H:%M"
        sched = datetime.strptime(scheduled_start.strip(), fmt)
        actual = datetime.strptime(clock_in.strip(), fmt)
        diff = int((actual - sched).total_seconds() / 60)
        return max(0, diff)
    except ValueError:
        return None


# ── Employees ─────────────────────────────────────────────────────────────────

@app.route("/api/employees", methods=["GET"])
def get_employees():
    db = get_db()
    cur = db.cursor()
    store = request.args.get("store")
    position = request.args.get("position")
    query = "SELECT * FROM employees WHERE TRUE"
    params = []
    if store:
        query += " AND store = %s"
        params.append(store)
    if position:
        query += " AND position = %s"
        params.append(position)
    scope, scope_params = store_scope_clause("store")
    query += scope
    params += scope_params
    query += " ORDER BY name"
    cur.execute(query, params)
    return jsonify(rows_to_list(cur))


@app.route("/api/employees", methods=["POST"])
def create_employee():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400
    employee_id = data.get("employee_id") or data.get("employeeId")
    name = data.get("name")
    if not employee_id or not name:
        return jsonify({"error": "employee_id and name are required"}), 400
    db = get_db()
    cur = db.cursor()
    cur.execute(
        """
        INSERT INTO employees (employee_id, name, position, store)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (employee_id) DO UPDATE SET
            name     = EXCLUDED.name,
            position = COALESCE(EXCLUDED.position, employees.position),
            store    = COALESCE(EXCLUDED.store, employees.store)
        RETURNING *
        """,
        (employee_id, name, data.get("position"), data.get("store")),
    )
    emp = row_to_dict(cur)
    db.commit()
    return jsonify(emp), 201


@app.route("/api/employees/<employee_id>", methods=["PATCH"])
def update_employee(employee_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM employees WHERE employee_id = %s", (employee_id,))
    if not cur.fetchone():
        return jsonify({"error": f"Employee {employee_id} not found"}), 404
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400
    allowed = {"name", "position", "store"}
    updates = {k: v for k, v in data.items() if k in allowed}
    if not updates:
        return jsonify({"error": f"No updatable fields. Allowed: {sorted(allowed)}"}), 400
    set_clause = ", ".join(f"{col} = %s" for col in updates)
    values = list(updates.values()) + [employee_id]
    cur.execute(f"UPDATE employees SET {set_clause} WHERE employee_id = %s RETURNING *", values)
    emp = row_to_dict(cur)
    db.commit()
    return jsonify(emp)


@app.route("/api/employees/<employee_id>", methods=["DELETE"])
def delete_employee(employee_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM employees WHERE employee_id = %s", (employee_id,))
    if not cur.fetchone():
        return jsonify({"error": f"Employee {employee_id} not found"}), 404
    cur.execute("DELETE FROM employees WHERE employee_id = %s", (employee_id,))
    db.commit()
    return jsonify({"deleted": True, "employee_id": employee_id})


def _terminable_employee(cur, employee_id):
    """Look up an employee for terminate/reactivate and enforce who may do it:
    platform admin, owner, and DMs for their own stores (the before_request
    carve-out lets DM POSTs through; store accounts never get here).
    Returns (employee_row, error_response)."""
    user = current_user()
    if user is not None and user["role"] not in ("platform_admin", "owner", "dm"):
        return None, (jsonify({"error": "You don't have permission to make changes."}), 403)
    cur.execute("SELECT * FROM employees WHERE employee_id = %s", (employee_id,))
    emp = row_to_dict(cur)
    if not emp:
        return None, (jsonify({"error": f"Employee {employee_id} not found"}), 404)
    allowed = allowed_stores()
    if allowed is not None and emp["store"] not in allowed:
        return None, (jsonify({"error": "That employee is outside your assigned stores"}), 403)
    return emp, None


@app.route("/api/employees/<employee_id>/terminate", methods=["POST"])
def terminate_employee(employee_id):
    db = get_db()
    cur = db.cursor()
    emp, err = _terminable_employee(cur, employee_id)
    if err:
        return err
    data = request.get_json(silent=True) or {}
    last_day = (data.get("last_day") or "").strip() or datetime.utcnow().strftime("%Y-%m-%d")
    try:
        datetime.strptime(last_day, "%Y-%m-%d")
    except ValueError:
        return jsonify({"error": "last_day must be YYYY-MM-DD"}), 400
    note = (data.get("note") or "").strip() or None
    user = current_user()
    cur.execute(
        "UPDATE employees SET active = FALSE, terminated_at = %s, "
        "terminated_by = %s, terminated_note = %s WHERE employee_id = %s RETURNING *",
        (last_day, user["username"] if user else "api", note, employee_id),
    )
    emp = row_to_dict(cur)
    # An open write-up obligation is moot once the employee is gone.
    cur.execute(
        "UPDATE doc_obligations SET status = 'lapsed' WHERE employee_id = %s AND status = 'open'",
        (employee_id,),
    )
    db.commit()
    return jsonify(emp)


@app.route("/api/employees/<employee_id>/reactivate", methods=["POST"])
def reactivate_employee(employee_id):
    db = get_db()
    cur = db.cursor()
    emp, err = _terminable_employee(cur, employee_id)
    if err:
        return err
    cur.execute(
        "UPDATE employees SET active = TRUE, terminated_at = NULL, "
        "terminated_by = NULL, terminated_note = NULL WHERE employee_id = %s RETURNING *",
        (employee_id,),
    )
    emp = row_to_dict(cur)
    db.commit()
    return jsonify(emp)


# ── Alerts (dm / owner / platform admin) ──────────────────────────────────────

ALERT_ROLES = ("platform_admin", "owner", "dm")


@app.route("/api/alerts", methods=["GET"])
def list_alerts():
    """Unacknowledged operational alerts for the caller's stores (?all=1 for
    the full history). Store accounts don't see alerts — they are aimed at the
    DM/owner level."""
    user = current_user()
    if user is not None and user["role"] not in ALERT_ROLES:
        return jsonify({"error": "You don't have permission to view alerts."}), 403
    db = get_db()
    cur = db.cursor()
    query = (
        "SELECT a.*, e.name AS employee_name FROM alerts a "
        "LEFT JOIN employees e ON e.employee_id = a.employee_id WHERE TRUE"
    )
    params = []
    if request.args.get("all") not in ("1", "true"):
        query += " AND a.acknowledged_at IS NULL"
    scope, scope_params = store_scope_clause("a.store")
    query += scope
    params += scope_params
    query += " ORDER BY a.created_at DESC"
    cur.execute(query, params)
    return jsonify(rows_to_list(cur))


@app.route("/api/alerts/<int:aid>/ack", methods=["POST"])
def ack_alert(aid):
    user = current_user()
    if user is not None and user["role"] not in ALERT_ROLES:
        return jsonify({"error": "You don't have permission to make changes."}), 403
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM alerts WHERE id = %s", (aid,))
    alert = row_to_dict(cur)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    allowed = allowed_stores()
    if allowed is not None and alert["store"] not in allowed:
        return jsonify({"error": "Alert not found"}), 404
    if alert["acknowledged_at"]:
        return jsonify({"error": "This alert was already acknowledged."}), 409
    cur.execute(
        "UPDATE alerts SET acknowledged_at = NOW(), acknowledged_by = %s WHERE id = %s",
        (user["username"] if user else "api", aid),
    )
    db.commit()
    return jsonify({"ok": True, "id": aid})


# ── Attendance logs ───────────────────────────────────────────────────────────

@app.route("/api/logs", methods=["GET"])
def get_logs():
    db = get_db()
    cur = db.cursor()
    employee_id = request.args.get("employee_id")
    date_from = request.args.get("date_from")
    date_to = request.args.get("date_to")
    status = request.args.get("status")
    store = request.args.get("store")
    query = (
        "SELECT l.*, e.name AS employee_name, e.store AS employee_store, "
        "e.position AS employee_position, e.active AS employee_active "
        "FROM attendance_logs l "
        "LEFT JOIN employees e ON l.employee_id = e.employee_id "
        "WHERE TRUE"
    )
    params = []
    if employee_id:
        query += " AND l.employee_id = %s"
        params.append(employee_id)
    if date_from:
        query += " AND l.date >= %s"
        params.append(date_from)
    if date_to:
        query += " AND l.date <= %s"
        params.append(date_to)
    if status:
        query += " AND l.status = %s"
        params.append(status)
    if store:
        query += " AND e.store = %s"
        params.append(store)
    scope, scope_params = store_scope_clause("e.store")
    query += scope
    params += scope_params
    query += " ORDER BY l.date DESC, l.employee_id"
    cur.execute(query, params)
    return jsonify(rows_to_list(cur))


@app.route("/api/logs", methods=["POST"])
def create_log():
    data = request.get_json(silent=True) or {}
    employee_id = (data.get("employee_id") or "").strip()
    status = (data.get("status") or "").strip()
    date_str = (data.get("date") or "").strip()
    if not employee_id or not status or not date_str:
        return jsonify({"error": "employee_id, status, and date are required"}), 400
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT employee_id FROM employees WHERE employee_id = %s", (employee_id,))
    if not cur.fetchone():
        return jsonify({"error": "Employee not found"}), 404
    clock_in = (data.get("clock_in") or "").strip() or None
    clock_out = (data.get("clock_out") or "").strip() or None
    hours = data.get("hours")
    scheduled_start = (data.get("scheduled_start") or "").strip() or None
    minutes_late = data.get("minutes_late")
    notes = (data.get("notes") or "").strip() or None
    manual_points_val = data.get("manual_points")
    if minutes_late is None and clock_in and scheduled_start:
        minutes_late = calc_minutes_late(scheduled_start, clock_in)
    cur.execute(
        "INSERT INTO attendance_logs "
        "(employee_id, date, clock_in, clock_out, hours, status, "
        "scheduled_start, minutes_late, notes, manual_points) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
        (employee_id, date_str, clock_in, clock_out, hours, status,
         scheduled_start, minutes_late, notes, manual_points_val),
    )
    new_id = cur.fetchone()["id"]
    db.commit()
    cur.execute(
        "SELECT l.*, e.name AS employee_name FROM attendance_logs l "
        "JOIN employees e ON l.employee_id = e.employee_id WHERE l.id = %s",
        (new_id,),
    )
    return jsonify(row_to_dict(cur)), 201


ALLOWED_LOG_FIELDS = {"date", "clock_in", "clock_out", "hours", "status",
                      "scheduled_start", "minutes_late", "notes", "manual_points"}


@app.route("/api/logs/<int:log_id>", methods=["PATCH", "DELETE"])
def update_or_delete_log(log_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM attendance_logs WHERE id = %s", (log_id,))
    log = row_to_dict(cur)
    if not log:
        return jsonify({"error": f"Log {log_id} not found"}), 404
    # Scoped callers (DMs) may only modify logs for employees in their stores.
    allowed = allowed_stores()
    if allowed is not None:
        cur.execute("SELECT store FROM employees WHERE employee_id = %s", (log["employee_id"],))
        row = cur.fetchone()
        if not row or row["store"] not in allowed:
            return jsonify({"error": "That log is outside your assigned stores"}), 403
    if request.method == "DELETE":
        cur.execute("DELETE FROM attendance_logs WHERE id = %s", (log_id,))
        db.commit()
        return jsonify({"deleted": True, "id": log_id})
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400
    updates = {k: v for k, v in data.items() if k in ALLOWED_LOG_FIELDS}
    if not updates:
        return jsonify({"error": f"No updatable fields. Allowed: {sorted(ALLOWED_LOG_FIELDS)}"}), 400
    if "minutes_late" not in updates:
        new_clock_in = updates.get("clock_in", log["clock_in"])
        new_scheduled = updates.get("scheduled_start", log["scheduled_start"])
        computed = calc_minutes_late(new_scheduled, new_clock_in)
        if computed is not None:
            updates["minutes_late"] = computed
    set_clause = ", ".join(f"{col} = %s" for col in updates)
    values = list(updates.values()) + [log_id]
    cur.execute(f"UPDATE attendance_logs SET {set_clause} WHERE id = %s", values)
    db.commit()
    cur.execute("SELECT * FROM attendance_logs WHERE id = %s", (log_id,))
    return jsonify(row_to_dict(cur))


# ── Shift swaps ───────────────────────────────────────────────────────────────

@app.route("/api/swap", methods=["POST"])
def record_swap():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400
    requester_id = data.get("requester_id") or data.get("requesterId")
    recipient_id = data.get("recipient_id") or data.get("recipientId")
    shift_date = data.get("shift_date") or data.get("shiftDate")
    missing = [f for f, v in [
        ("requester_id", requester_id),
        ("recipient_id", recipient_id),
        ("shift_date", shift_date),
    ] if not v]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400
    status = data.get("status", "pending")
    valid_statuses = {"pending", "approved", "rejected", "completed"}
    if status not in valid_statuses:
        return jsonify({"error": f"status must be one of: {', '.join(sorted(valid_statuses))}"}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(
            """
            INSERT INTO shift_swaps
                (requester_id, recipient_id, shift_date, original_shift, swapped_shift, status, notes)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING *
            """,
            (
                requester_id, recipient_id, shift_date,
                data.get("original_shift") or data.get("originalShift"),
                data.get("swapped_shift") or data.get("swappedShift"),
                status, data.get("notes"),
            ),
        )
    except psycopg2.errors.ForeignKeyViolation:
        db.rollback()
        return jsonify({"error": "One or both employee IDs do not exist"}), 400
    swap = row_to_dict(cur)
    db.commit()
    return jsonify(swap), 201


@app.route("/api/swaps", methods=["GET"])
def get_swaps():
    db = get_db()
    cur = db.cursor()
    employee_id = request.args.get("employee_id")
    status = request.args.get("status")
    query = "SELECT * FROM shift_swaps WHERE TRUE"
    params = []
    if employee_id:
        query += " AND (requester_id = %s OR recipient_id = %s)"
        params.extend([employee_id, employee_id])
    if status:
        query += " AND status = %s"
        params.append(status)
    allowed = allowed_stores()
    if allowed is not None:
        query += (" AND (requester_id IN (SELECT employee_id FROM employees WHERE store = ANY(%s))"
                  " OR recipient_id IN (SELECT employee_id FROM employees WHERE store = ANY(%s)))")
        params.extend([list(allowed), list(allowed)])
    query += " ORDER BY created_at DESC"
    cur.execute(query, params)
    return jsonify(rows_to_list(cur))


ALLOWED_SWAP_FIELDS = {"status", "notes", "original_shift", "swapped_shift", "shift_date"}


@app.route("/api/swap/<int:swap_id>", methods=["PATCH"])
def update_swap(swap_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM shift_swaps WHERE id = %s", (swap_id,))
    if not cur.fetchone():
        return jsonify({"error": f"Swap {swap_id} not found"}), 404
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400
    updates = {k: v for k, v in data.items() if k in ALLOWED_SWAP_FIELDS}
    if not updates:
        return jsonify({"error": f"No updatable fields. Allowed: {sorted(ALLOWED_SWAP_FIELDS)}"}), 400
    if "status" in updates:
        valid_statuses = {"pending", "approved", "rejected", "completed"}
        if updates["status"] not in valid_statuses:
            return jsonify({"error": f"status must be one of: {', '.join(sorted(valid_statuses))}"}), 400
    set_clause = ", ".join(f"{col} = %s" for col in updates)
    values = list(updates.values()) + [swap_id]
    cur.execute(f"UPDATE shift_swaps SET {set_clause} WHERE id = %s RETURNING *", values)
    swap = row_to_dict(cur)
    db.commit()
    return jsonify(swap)


# ── Stats ─────────────────────────────────────────────────────────────────────

WEEKEND_DAYS = {4, 5, 6}  # Friday=4, Saturday=5, Sunday=6
NCNS_STATUSES = {"no_call_no_show", "ncns"}
CALLED_IN_STATUSES = {"called_in", "call_in", "call-in"}
DISCIPLINARY_STAGES = [
    (0,  7,  "Good Standing"),
    (7,  9,  "Hours May Be Reduced"),
    (9,  10, "Written Warning"),
    (10, 13, "Final Written Warning"),
    (13, None, "Termination"),
]


def disciplinary_stage(points, has_ncns=False):
    if has_ncns:
        return "Automatic Termination"
    for lo, hi, label in DISCIPLINARY_STAGES:
        if hi is None or points < hi:
            if points >= lo:
                return label
    return "Termination"


# Point rules an org may override (Admin → Point settings; platform admin or
# org owner only). Stored as JSON overrides in orgs.point_config and merged
# over these defaults, so orgs only persist what they changed and new rule
# keys pick up defaults automatically. ncns_points: None = automatic
# termination (the classic rule); a number = that many points instead.
DEFAULT_POINT_CONFIG = {
    "late_points": 1.0,
    "late_major_points": 2.0,
    "late_major_threshold_minutes": 60,
    "called_in_points": 2.0,
    "weekend_multiplier": 2.0,
    "ncns_points": None,
}


def merged_point_config(overrides):
    cfg = dict(DEFAULT_POINT_CONFIG)
    if isinstance(overrides, dict):
        cfg.update({k: v for k, v in overrides.items() if k in DEFAULT_POINT_CONFIG})
    return cfg


# Feature switches an org may toggle (Admin; platform admin or org owner only).
# Stored as JSON overrides in orgs.features, merged over these defaults.
DEFAULT_FEATURES = {
    "written_docs": False,
}

# Stages that require a written write-up when written_docs is on. "Automatic
# Termination" is deliberately excluded: fresh NCNS rows sit there until the
# GM disposition lands, which would flood the action list with noise.
DOC_REQUIRED_STAGES = {"Written Warning", "Final Written Warning", "Termination"}


def merged_features(overrides):
    cfg = dict(DEFAULT_FEATURES)
    if isinstance(overrides, dict):
        cfg.update({k: bool(v) for k, v in overrides.items() if k in DEFAULT_FEATURES})
    return cfg


def org_point_configs(cur):
    """org_id -> merged point config for every org."""
    cur.execute("SELECT id, point_config FROM orgs")
    return {r["id"]: merged_point_config(r["point_config"]) for r in rows_to_list(cur)}


def base_points_for_log(status, minutes_late, cfg=DEFAULT_POINT_CONFIG):
    status = (status or "").lower().strip()
    if status in NCNS_STATUSES:
        ncns = cfg.get("ncns_points")
        return None if ncns is None else float(ncns)
    if status in CALLED_IN_STATUSES:
        return float(cfg["called_in_points"])
    if status == "exempted":
        return 0.0
    if minutes_late is not None and minutes_late > 0:
        threshold = float(cfg["late_major_threshold_minutes"])
        return float(cfg["late_points"]) if minutes_late <= threshold else float(cfg["late_major_points"])
    if status == "late":
        return float(cfg["late_points"])
    if status in {"late_major", "late_1hr", "late_2hr"}:
        return float(cfg["late_major_points"])
    return 0.0


def is_weekend(date_str):
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").weekday() in WEEKEND_DAYS
    except ValueError:
        return False


@app.route("/api/stats", methods=["GET"])
def get_stats():
    return jsonify(compute_stats(
        employee_id=request.args.get("employee_id"),
        store=request.args.get("store"),
        window_days=int(request.args.get("window_days", 90)),
    ))


def compute_stats(employee_id=None, store=None, window_days=90):
    """Point totals + disciplinary stage for every employee in the caller's
    store scope. Shared by /api/stats and the doc-obligation sync so both
    always agree on who is in which stage."""
    db = get_db()
    cur = db.cursor()
    since = (datetime.utcnow() - timedelta(days=window_days)).strftime("%Y-%m-%d")
    emp_query = "SELECT * FROM employees WHERE active"
    emp_params = []
    if employee_id:
        emp_query += " AND employee_id = %s"
        emp_params.append(employee_id)
    if store:
        emp_query += " AND store = %s"
        emp_params.append(store)
    scope, scope_params = store_scope_clause("store")
    emp_query += scope
    emp_params += scope_params
    emp_query += " ORDER BY name"
    cur.execute(emp_query, emp_params)
    employees = rows_to_list(cur)

    cur.execute(
        "SELECT store, MAX(reset_date) AS reset_date FROM point_resets GROUP BY store"
    )
    store_resets = {r["store"]: r["reset_date"] for r in rows_to_list(cur)}

    # Each employee is scored under their org's point rules (store -> org -> config).
    cur.execute("SELECT store, org_id FROM stores")
    store_org = {r["store"]: r["org_id"] for r in rows_to_list(cur)}
    org_configs = org_point_configs(cur)

    employee_ids = [emp["employee_id"] for emp in employees]
    logs_by_emp = defaultdict(list)
    redemptions_by_emp = defaultdict(list)
    if employee_ids:
        # Fetch once for everyone since >= `since` (effective_since is always >= since,
        # so per-employee filtering below is a safe subset of this batch).
        cur.execute(
            "SELECT employee_id, id, status, date, minutes_late, manual_points "
            "FROM attendance_logs WHERE employee_id = ANY(%s) AND date >= %s "
            "ORDER BY employee_id, date",
            (employee_ids, since),
        )
        for log in rows_to_list(cur):
            logs_by_emp[log["employee_id"]].append(log)

        cur.execute(
            "SELECT employee_id, date, points_removed FROM point_redemptions "
            "WHERE employee_id = ANY(%s) AND status = 'approved' AND date >= %s",
            (employee_ids, since),
        )
        for r in rows_to_list(cur):
            redemptions_by_emp[r["employee_id"]].append(r)

    results = []
    for emp in employees:
        eid = emp["employee_id"]
        cfg = org_configs.get(store_org.get(emp["store"]), DEFAULT_POINT_CONFIG)
        reset_date = store_resets.get(emp["store"])
        effective_since = max(since, reset_date) if reset_date else since
        logs = [l for l in logs_by_emp.get(eid, []) if l["date"] >= effective_since]
        total_points = 0.0
        has_ncns = False
        point_log = []
        for log in logs:
            status = (log["status"] or "").lower().strip()
            date_str = log["date"] or ""
            minutes_late = log["minutes_late"]
            if status == "manual_addition":
                mp = float(log.get("manual_points") or 0)
                if mp > 0:
                    total_points += mp
                    point_log.append({
                        "log_id": log["id"], "date": date_str,
                        "status": "manual_addition", "base_points": mp,
                        "weekend": False, "points_applied": mp,
                    })
                continue
            base = base_points_for_log(status, minutes_late, cfg)
            if base is None:
                has_ncns = True
                point_log.append({
                    "log_id": log["id"], "date": date_str, "status": status,
                    "base_points": "NCNS", "weekend": is_weekend(date_str),
                    "points_applied": "Automatic Termination",
                })
                continue
            if base == 0.0:
                continue
            weekend = is_weekend(date_str)
            applied = base * float(cfg["weekend_multiplier"]) if weekend else base
            total_points += applied
            point_log.append({
                "log_id": log["id"], "date": date_str, "status": status,
                "minutes_late": minutes_late, "base_points": base,
                "weekend": weekend, "points_applied": applied,
            })
        total_points = round(total_points, 2)
        redeemed = sum(
            float(r["points_removed"] or 0)
            for r in redemptions_by_emp.get(eid, [])
            if r["date"] >= effective_since
        )
        if redeemed > 0:
            total_points = round(max(0.0, total_points - redeemed), 2)
        results.append({
            "employee_id": eid, "name": emp["name"],
            "position": emp["position"], "store": emp["store"],
            "active_points": total_points, "has_ncns": has_ncns,
            "disciplinary_stage": disciplinary_stage(total_points, has_ncns),
            "point_log": point_log, "window_days": window_days,
            "window_since": effective_since, "logs_evaluated": len(logs),
            "points_reset_on": reset_date,
        })
    return results


@app.route("/api/streaks", methods=["GET"])
def get_streaks():
    """Top 10 employees by consecutive on-time, no-missed-shift streak.

    Attendance is exception-based in this system: a log row only gets
    created when something notable happens (late, called in, no-call/
    no-show, exempted, covered_shift). A normal on-time shift produces
    NO log row at all — so "on_time" as a literal status essentially
    never occurs in real data and can't be used to detect streaks.

    Instead, we treat every date a store reported attendance for
    (`imported_batches`) as a "shift day" for its employees, and count
    backwards from the most recent one: a shift day with no logged
    exception for that employee is a clean shift (streak continues);
    any logged exception (of any status, other than the purely
    informational "manual_addition") breaks the streak. Days before the
    employee's own hire date are excluded so new hires aren't credited
    with a streak that predates them.

    Caveat: because there's no per-employee schedule, a day the
    employee had off (but the store still reported attendance from
    other staff) can't be distinguished from a day they worked cleanly,
    so this is a best-effort approximation, not an exact shift count.
    """
    err = require_owner()
    if err:
        return err

    db = get_db()
    cur = db.cursor()
    limit = int(request.args.get("limit", 10))

    emp_query = "SELECT * FROM employees WHERE active"
    emp_params = []
    scope, scope_params = store_scope_clause("store")
    emp_query += scope
    emp_params += scope_params
    emp_query += " ORDER BY name"
    cur.execute(emp_query, emp_params)
    employees = rows_to_list(cur)

    employee_ids = [emp["employee_id"] for emp in employees]
    stores = list({emp["store"] for emp in employees if emp["store"]})

    batches_by_store = defaultdict(list)
    if stores:
        cur.execute(
            "SELECT store, date FROM imported_batches WHERE store = ANY(%s) "
            "ORDER BY store, date DESC",
            (stores,),
        )
        for row in rows_to_list(cur):
            batches_by_store[row["store"]].append(row["date"])

    exception_dates_by_emp = defaultdict(set)
    if employee_ids:
        cur.execute(
            "SELECT employee_id, date FROM attendance_logs "
            "WHERE employee_id = ANY(%s) AND status != 'manual_addition'",
            (employee_ids,),
        )
        for row in rows_to_list(cur):
            exception_dates_by_emp[row["employee_id"]].add(row["date"])

    def hire_date_str(emp):
        created = emp.get("created_at")
        if not created:
            return None
        return created.strftime("%Y-%m-%d") if hasattr(created, "strftime") else str(created)[:10]

    results = []
    for emp in employees:
        eid = emp["employee_id"]
        shift_days = batches_by_store.get(emp["store"], [])
        exception_dates = exception_dates_by_emp.get(eid, set())
        hired = hire_date_str(emp)
        streak = 0
        last_date = None
        for d in shift_days:
            if hired and d < hired:
                break
            if d in exception_dates:
                break
            streak += 1
            last_date = d
        if streak > 0:
            results.append({
                "employee_id": eid,
                "name": emp["name"],
                "store": emp["store"],
                "streak": streak,
                "last_shift_date": last_date,
            })

    results.sort(key=lambda r: r["streak"], reverse=True)
    return jsonify(results[:limit])


# ── Point Redemptions ─────────────────────────────────────────────────────────

REDEMPTION_TYPES = {
    "came_in_day_off": 2.0,
    "came_in_weekend_day_off": 3.0,
    "came_in_early": 1.0,
}


@app.route("/api/redemptions", methods=["POST"])
def create_redemption():
    data = request.get_json(silent=True) or {}
    employee_id = (data.get("employee_id") or "").strip()
    redemption_type = (data.get("redemption_type") or "").strip()
    date_str = (data.get("date") or "").strip()
    notes = (data.get("notes") or "").strip() or None

    if not employee_id or redemption_type not in REDEMPTION_TYPES or not date_str:
        return jsonify({"error": "employee_id, redemption_type, and date are required"}), 400

    points_removed = REDEMPTION_TYPES[redemption_type]
    user = current_user()
    submitted_by = user["username"] if user else "api"

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT store FROM employees WHERE employee_id = %s", (employee_id,))
    row = cur.fetchone()
    if not row:
        return jsonify({"error": "Employee not found"}), 404

    # Non-owners may only request redemptions for employees in their own stores.
    allowed = allowed_stores()
    if allowed is not None and row["store"] not in allowed:
        return jsonify({"error": "That employee is outside your assigned stores"}), 403

    cur.execute(
        "INSERT INTO point_redemptions "
        "(employee_id, redemption_type, points_removed, date, notes, status, submitted_by) "
        "VALUES (%s, %s, %s, %s, %s, 'pending', %s) RETURNING id",
        (employee_id, redemption_type, points_removed, date_str, notes, submitted_by),
    )
    new_id = cur.fetchone()["id"]
    db.commit()
    return jsonify({"id": new_id, "status": "pending"}), 201


@app.route("/api/redemptions", methods=["GET"])
def list_redemptions():
    status_filter = request.args.get("status")
    db = get_db()
    cur = db.cursor()
    query = (
        "SELECT r.*, e.name AS employee_name, e.store AS employee_store "
        "FROM point_redemptions r "
        "JOIN employees e ON r.employee_id = e.employee_id "
        "WHERE TRUE"
    )
    params = []
    if status_filter:
        query += " AND r.status = %s"
        params.append(status_filter)
    scope, scope_params = store_scope_clause("e.store")
    query += scope
    params += scope_params
    query += " ORDER BY r.created_at DESC"
    cur.execute(query, params)
    return jsonify(rows_to_list(cur))


@app.route("/api/redemptions/<int:rid>", methods=["PATCH"])
def update_redemption(rid):
    # Owners may approve/deny any redemption. DMs may approve/deny redemptions
    # for employees in their own (assigned or hardcoded) stores only.
    data = request.get_json(silent=True) or {}
    action = (data.get("action") or "").strip()
    if action not in ("approve", "deny"):
        return jsonify({"error": "action must be 'approve' or 'deny'"}), 400

    user = current_user()
    reviewed_by = user["username"] if user else "api"
    new_status = "approved" if action == "approve" else "denied"

    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT r.id, r.status, e.store FROM point_redemptions r "
        "JOIN employees e ON r.employee_id = e.employee_id WHERE r.id = %s",
        (rid,),
    )
    row = cur.fetchone()
    if not row:
        return jsonify({"error": "Redemption not found"}), 404

    allowed = allowed_stores()
    if allowed is not None and row["store"] not in allowed:
        return jsonify({"error": "That redemption is outside your assigned stores"}), 403

    if row["status"] != "pending":
        return jsonify({"error": "Only pending redemptions can be approved or denied"}), 409

    cur.execute(
        "UPDATE point_redemptions SET status = %s, reviewed_by = %s WHERE id = %s",
        (new_status, reviewed_by, rid),
    )
    db.commit()
    return jsonify({"id": rid, "status": new_status})


# ── Stores (list + DM assignment) ─────────────────────────────────────────────

@app.route("/api/stores", methods=["GET"])
def list_stores():
    db = get_db()
    cur = db.cursor()
    scope, params = store_scope_clause("s.store")
    cur.execute(
        "SELECT s.store, s.name, s.dm_user_id, u.username AS dm_username "
        "FROM stores s LEFT JOIN users u ON u.id = s.dm_user_id "
        "WHERE TRUE" + scope + " ORDER BY s.store",
        params,
    )
    rows = rows_to_list(cur)
    user = current_user()
    if not (user is None or user["role"] == "owner"):
        for r in rows:
            r.pop("dm_user_id", None)
            r.pop("dm_username", None)
    return jsonify(rows)


@app.route("/api/stores/<store>", methods=["PATCH"])
def update_store(store):
    err = require_owner()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT store, org_id FROM stores WHERE store = %s", (store,))
    existing = cur.fetchone()
    if existing is None:
        # New store joins the caller's org (platform-level callers may pass org_id).
        user = current_user()
        new_org = (user or {}).get("org_id") or data.get("org_id")
        if not new_org:
            return jsonify({"error": "org_id is required to create a store as a platform-level caller"}), 400
        cur.execute("INSERT INTO stores (store, org_id) VALUES (%s, %s)", (store, new_org))
        store_org = new_org
    else:
        allowed = allowed_stores()
        if allowed is not None and store not in allowed:
            return jsonify({"error": "That store is outside your organization"}), 403
        store_org = existing["org_id"]
    updates = {}
    if "dm_user_id" in data:
        dm = data.get("dm_user_id")
        if dm is not None:
            cur.execute("SELECT id, role, org_id FROM users WHERE id = %s", (dm,))
            r = cur.fetchone()
            if not r or r["role"] != "dm":
                return jsonify({"error": "dm_user_id must reference a DM user"}), 400
            if store_org and r["org_id"] != store_org:
                return jsonify({"error": "That DM belongs to a different organization"}), 400
        updates["dm_user_id"] = dm
    if "name" in data:
        updates["name"] = data.get("name")
    if not updates:
        return jsonify({"error": "Nothing to update"}), 400
    set_clause = ", ".join(f"{col} = %s" for col in updates)
    values = list(updates.values()) + [store]
    cur.execute(f"UPDATE stores SET {set_clause} WHERE store = %s", values)
    db.commit()
    return jsonify({"updated": True, "store": store})


@app.route("/api/stores/<store>", methods=["DELETE"])
def delete_store(store):
    """Remove a store and its per-store bookkeeping (freshness history, scrape
    runs, point resets, doc obligations). Refuses while employees still
    reference the store so real rosters can't be dropped by accident."""
    err = require_platform_admin()
    if err:
        return err
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT store FROM stores WHERE store = %s", (store,))
    if cur.fetchone() is None:
        return jsonify({"error": f"Store {store} not found"}), 404
    cur.execute("SELECT COUNT(*) AS n FROM employees WHERE store = %s", (store,))
    n = cur.fetchone()["n"]
    if n:
        return jsonify({"error": f"Store {store} still has {n} employee(s) — move or delete them first"}), 409
    for table in ("imported_batches", "scrape_runs", "point_resets", "doc_obligations"):
        cur.execute(f"DELETE FROM {table} WHERE store = %s", (store,))
    cur.execute("DELETE FROM stores WHERE store = %s", (store,))
    db.commit()
    return jsonify({"deleted": True, "store": store})


@app.route("/api/stores/<store>/reset-points", methods=["POST"])
def reset_store_points(store):
    err = require_owner()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    reason = (data.get("reason") or "").strip()
    if not reason:
        return jsonify({"error": "A reason is required"}), 400
    allowed = allowed_stores()
    if allowed is not None and store not in allowed:
        return jsonify({"error": "That store is outside your organization"}), 403
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT 1 FROM employees WHERE store = %s LIMIT 1", (store,))
    if not cur.fetchone():
        return jsonify({"error": "Unknown store"}), 404
    user = current_user()
    created_by = user["username"] if user else "api-key"
    reset_date = datetime.utcnow().strftime("%Y-%m-%d")
    cur.execute(
        "INSERT INTO point_resets (store, reset_date, reason, created_by) "
        "VALUES (%s, %s, %s, %s) RETURNING id, store, reset_date, reason, created_by, created_at",
        (store, reset_date, reason, created_by),
    )
    row = rows_to_list(cur)[0]
    db.commit()
    return jsonify(row), 201


@app.route("/api/point-resets", methods=["GET"])
def list_point_resets():
    err = require_owner()
    if err:
        return err
    db = get_db()
    cur = db.cursor()
    scope, params = store_scope_clause("store")
    cur.execute(
        "SELECT id, store, reset_date, reason, created_by, created_at "
        "FROM point_resets WHERE TRUE" + scope + " ORDER BY created_at DESC",
        params,
    )
    return jsonify(rows_to_list(cur))


# ── Users (owner-only account management) ─────────────────────────────────────

@app.route("/api/users", methods=["GET", "POST"])
def users_collection():
    err = require_owner()
    if err:
        return err
    db = get_db()
    cur = db.cursor()

    caller = current_user()
    caller_is_org_owner = caller is not None and caller["role"] == "owner"

    if request.method == "GET":
        where = ""
        params = []
        if caller_is_org_owner:
            where = "WHERE u.org_id = %s AND u.role != 'platform_admin' "
            params = [caller["org_id"]]
        else:
            org_view = org_view_id()
            if org_view:
                where = "WHERE u.org_id = %s "
                params = [org_view]
        cur.execute(
            "SELECT u.id, u.username, u.role, u.store, u.org_id, o.name AS org_name, u.created_at, "
            "COALESCE(array_agg(s.store ORDER BY s.store) "
            "         FILTER (WHERE s.store IS NOT NULL), '{}') AS dm_stores "
            "FROM users u LEFT JOIN orgs o ON o.id = u.org_id "
            "LEFT JOIN stores s ON s.dm_user_id = u.id "
            + where +
            "GROUP BY u.id, o.name ORDER BY u.role, u.username",
            params,
        )
        return jsonify(rows_to_list(cur))

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""
    role = (data.get("role") or "").strip()
    store = (data.get("store") or "").strip() or None
    valid_roles = ORG_ROLES if caller_is_org_owner else ROLES
    if not username or not password or role not in valid_roles:
        return jsonify({"error": f"username, password, and a valid role ({'/'.join(sorted(valid_roles))}) are required"}), 400
    if role == "store" and not store:
        return jsonify({"error": "A store-role account must specify a store"}), 400
    # Org attribution: owners create users inside their own org, always.
    # Platform admins / the API key pass org_id (platform_admin accounts have none).
    if role == "platform_admin":
        org_id = None
    elif caller_is_org_owner:
        org_id = caller["org_id"]
    else:
        org_id = data.get("org_id")
        if not org_id:
            return jsonify({"error": "org_id is required when creating org-level users as a platform caller"}), 400
        cur.execute("SELECT id FROM orgs WHERE id = %s", (org_id,))
        if not cur.fetchone():
            return jsonify({"error": "Unknown org_id"}), 400
    if role == "store" and org_id:
        cur.execute("SELECT 1 FROM stores WHERE store = %s AND org_id = %s", (store, org_id))
        if not cur.fetchone():
            return jsonify({"error": "That store does not belong to this organization"}), 400
    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, role, store, org_id) "
            "VALUES (%s, %s, %s, %s, %s) RETURNING id, username, role, store, org_id",
            (username, generate_password_hash(password), role,
             store if role == "store" else None, org_id),
        )
    except psycopg2.errors.UniqueViolation:
        db.rollback()
        return jsonify({"error": "That username already exists"}), 409
    new_user = row_to_dict(cur)
    db.commit()
    return jsonify(new_user), 201


@app.route("/api/users/<int:uid>", methods=["PATCH", "DELETE"])
def user_item(uid):
    err = require_owner()
    if err:
        return err
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, role, org_id FROM users WHERE id = %s", (uid,))
    target = cur.fetchone()
    if not target:
        return jsonify({"error": "User not found"}), 404

    caller = current_user()
    caller_is_org_owner = caller is not None and caller["role"] == "owner"
    if caller_is_org_owner:
        if target["role"] == "platform_admin" or target["org_id"] != caller["org_id"]:
            return jsonify({"error": "That user is outside your organization"}), 403

    if request.method == "DELETE":
        if target["role"] == "owner":
            cur.execute(
                "SELECT COUNT(*) AS n FROM users WHERE role = 'owner' AND org_id = %s",
                (target["org_id"],),
            )
            if cur.fetchone()["n"] <= 1:
                return jsonify({"error": "Cannot delete the last owner account"}), 409
        cur.execute("DELETE FROM users WHERE id = %s", (uid,))
        db.commit()
        return jsonify({"deleted": True, "id": uid})

    data = request.get_json(silent=True) or {}
    valid_roles = ORG_ROLES if caller_is_org_owner else ROLES
    sets, params = [], []
    if data.get("password"):
        sets.append("password_hash = %s")
        params.append(generate_password_hash(data["password"]))
    if data.get("role") in valid_roles:
        sets.append("role = %s")
        params.append(data["role"])
    if "store" in data:
        sets.append("store = %s")
        params.append((data.get("store") or "").strip() or None)
    if not sets:
        return jsonify({"error": "Nothing to update"}), 400
    params.append(uid)
    cur.execute(f"UPDATE users SET {', '.join(sets)} WHERE id = %s", params)
    db.commit()
    return jsonify({"updated": True, "id": uid})


@app.route("/api/me/password", methods=["POST"])
def change_own_password():
    """Any logged-in dashboard user may change their own password (store
    accounts start with the store number as the default)."""
    user = current_user()
    if user is None:
        return jsonify({"error": "API-key callers have no password"}), 400
    data = request.get_json(silent=True) or {}
    current = data.get("current_password") or ""
    new = data.get("new_password") or ""
    if len(new) < 6:
        return jsonify({"error": "New password must be at least 6 characters"}), 400
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT password_hash FROM users WHERE id = %s", (user["id"],))
    row = row_to_dict(cur)
    if not row or not check_password_hash(row["password_hash"], current):
        return jsonify({"error": "Current password is incorrect"}), 403
    cur.execute(
        "UPDATE users SET password_hash = %s WHERE id = %s",
        (generate_password_hash(new), user["id"]),
    )
    db.commit()
    return jsonify({"ok": True})


# ── Organizations (platform admin only) ───────────────────────────────────────

@app.route("/api/orgs", methods=["GET", "POST"])
def orgs_collection():
    err = require_platform_admin()
    if err:
        return err
    db = get_db()
    cur = db.cursor()
    if request.method == "GET":
        cur.execute("""
            SELECT o.id, o.name, o.slug, o.created_at,
                   (SELECT COUNT(*) FROM stores s WHERE s.org_id = o.id) AS store_count,
                   (SELECT COUNT(*) FROM users u WHERE u.org_id = o.id) AS user_count,
                   COALESCE((SELECT pc.status FROM pulse_credentials pc
                             WHERE pc.org_id = o.id), 'not_configured') AS pulse_status
            FROM orgs o ORDER BY o.id
        """)
        return jsonify(rows_to_list(cur))
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    slug = (data.get("slug") or "").strip().lower() or re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    if not slug:
        return jsonify({"error": "Could not derive a slug; pass one explicitly"}), 400
    try:
        cur.execute("INSERT INTO orgs (name, slug) VALUES (%s, %s) RETURNING *", (name, slug))
    except psycopg2.errors.UniqueViolation:
        db.rollback()
        return jsonify({"error": "That slug already exists"}), 409
    org = row_to_dict(cur)
    db.commit()
    return jsonify(org), 201


@app.route("/api/orgs/<int:org_id>", methods=["PATCH"])
def update_org(org_id):
    err = require_platform_admin()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE orgs SET name = %s WHERE id = %s RETURNING *", (name, org_id))
    org = row_to_dict(cur)
    if not org:
        return jsonify({"error": "Org not found"}), 404
    db.commit()
    return jsonify(org)


# ── Pulse (PWR) credentials vault ─────────────────────────────────────────────
# Passwords are encrypted with the scrape worker's PUBLIC key before storage.
# The matching private key exists only on the worker machine — this server
# cannot decrypt what it stores.

def _worker_public_key():
    from cryptography.hazmat.primitives import serialization
    pem = os.environ.get("WORKER_PUBLIC_KEY")
    if pem:
        return serialization.load_pem_public_key(pem.encode())
    with open(os.path.join(BASE_DIR, "worker_public_key.pem"), "rb") as f:
        return serialization.load_pem_public_key(f.read())


def encrypt_for_worker(plaintext):
    import base64
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    ciphertext = _worker_public_key().encrypt(
        plaintext.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )
    return base64.b64encode(ciphertext).decode()


def _credentials_org_id():
    """Org whose credentials are being managed. Owners always operate on their
    own org; platform admins / the API key must name one explicitly."""
    user = current_user()
    if user is not None and user["role"] == "owner":
        return user.get("org_id")
    org_id = request.args.get("org_id", type=int)
    if not org_id:
        data = request.get_json(silent=True) or {}
        org_id = data.get("org_id")
    return org_id or org_view_id()


@app.route("/api/org/pulse-credentials", methods=["GET", "POST", "DELETE"])
def org_pulse_credentials():
    err = require_owner()
    if err:
        return err
    org_id = _credentials_org_id()
    if not org_id:
        return jsonify({"error": "org_id is required for platform-level callers"}), 400
    db = get_db()
    cur = db.cursor()
    if request.method == "GET":
        cur.execute(
            "SELECT org_id, pwr_username, status, status_detail, updated_at, last_checked_at "
            "FROM pulse_credentials WHERE org_id = %s",
            (org_id,),
        )
        row = row_to_dict(cur)
        return jsonify(row or {"org_id": org_id, "status": "not_configured"})
    if request.method == "DELETE":
        cur.execute("DELETE FROM pulse_credentials WHERE org_id = %s", (org_id,))
        db.commit()
        return jsonify({"deleted": True, "org_id": org_id})
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400
    try:
        enc = encrypt_for_worker(password)
    except Exception:
        return jsonify({"error": "Credential encryption is not configured on the server"}), 500
    user = current_user()
    cur.execute(
        """
        INSERT INTO pulse_credentials
            (org_id, pwr_username, enc_password, status, status_detail, updated_by, updated_at)
        VALUES (%s, %s, %s, 'pending', NULL, %s, NOW())
        ON CONFLICT (org_id) DO UPDATE SET
            pwr_username = EXCLUDED.pwr_username,
            enc_password = EXCLUDED.enc_password,
            status = 'pending', status_detail = NULL,
            updated_by = EXCLUDED.updated_by, updated_at = NOW()
        """,
        (org_id, username, enc, user["username"] if user else "api"),
    )
    db.commit()
    return jsonify({"org_id": org_id, "status": "pending"}), 201


# ── Per-org point settings (platform admin / org owner only) ─────────────────

@app.route("/api/org/point-config", methods=["GET", "PUT"])
def org_point_config():
    err = require_owner()
    if err:
        return err
    org_id = _credentials_org_id()
    if not org_id:
        return jsonify({"error": "org_id is required for platform-level callers"}), 400
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, point_config FROM orgs WHERE id = %s", (org_id,))
    row = row_to_dict(cur)
    if not row:
        return jsonify({"error": "Organization not found"}), 404
    if request.method == "GET":
        return jsonify({
            "org_id": org_id,
            "config": merged_point_config(row["point_config"]),
            "defaults": DEFAULT_POINT_CONFIG,
        })
    data = request.get_json(silent=True) or {}
    # Partial updates merge over what the org already customized, so setting
    # one rule never silently resets the others back to defaults.
    existing = row["point_config"] if isinstance(row["point_config"], dict) else {}
    overrides = {k: v for k, v in existing.items() if k in DEFAULT_POINT_CONFIG}
    for key in DEFAULT_POINT_CONFIG:
        if key not in data:
            continue
        val = data[key]
        if key == "ncns_points" and val is None:
            overrides[key] = None
            continue
        try:
            val = float(val)
        except (TypeError, ValueError):
            return jsonify({"error": f"{key} must be a number"}), 400
        if val < 0:
            return jsonify({"error": f"{key} cannot be negative"}), 400
        if key == "weekend_multiplier" and val < 1:
            return jsonify({"error": "weekend_multiplier must be at least 1 (1 = no weekend extra)"}), 400
        overrides[key] = val
    unknown = set(data) - set(DEFAULT_POINT_CONFIG)
    if unknown:
        return jsonify({"error": f"Unknown point-config keys: {', '.join(sorted(unknown))}"}), 400
    cur.execute(
        "UPDATE orgs SET point_config = %s WHERE id = %s",
        (json.dumps(overrides), org_id),
    )
    db.commit()
    return jsonify({"org_id": org_id, "config": merged_point_config(overrides)})


@app.route("/api/org/features", methods=["GET", "PUT"])
def org_features():
    err = require_owner()
    if err:
        return err
    org_id = _credentials_org_id()
    if not org_id:
        return jsonify({"error": "org_id is required for platform-level callers"}), 400
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, features FROM orgs WHERE id = %s", (org_id,))
    row = row_to_dict(cur)
    if not row:
        return jsonify({"error": "Organization not found"}), 404
    if request.method == "GET":
        return jsonify({"org_id": org_id, "features": merged_features(row["features"])})
    data = request.get_json(silent=True) or {}
    unknown = set(data) - set(DEFAULT_FEATURES) - {"org_id"}
    if unknown:
        return jsonify({"error": f"Unknown feature keys: {', '.join(sorted(unknown))}"}), 400
    existing = row["features"] if isinstance(row["features"], dict) else {}
    overrides = {k: bool(v) for k, v in existing.items() if k in DEFAULT_FEATURES}
    for key in DEFAULT_FEATURES:
        if key in data:
            overrides[key] = bool(data[key])
    cur.execute("UPDATE orgs SET features = %s WHERE id = %s", (json.dumps(overrides), org_id))
    db.commit()
    return jsonify({"org_id": org_id, "features": merged_features(overrides)})


# ── Written-documentation obligations ─────────────────────────────────────────

def _sync_doc_obligations(cur, stats, store_org, enabled_orgs):
    """Reconcile doc_obligations with current disciplinary stages: open an
    obligation when an employee (in a written_docs org) sits in a stage that
    requires paperwork, lapse it when they drop out, supersede it when their
    stage changes. A stage an employee was already documented at once is not
    re-opened."""
    emp_ids = [s["employee_id"] for s in stats]
    if not emp_ids:
        return
    cur.execute(
        "SELECT * FROM doc_obligations WHERE employee_id = ANY(%s) AND status = 'open'",
        (emp_ids,),
    )
    open_by_emp = {r["employee_id"]: r for r in rows_to_list(cur)}
    cur.execute(
        "SELECT DISTINCT employee_id, stage FROM doc_obligations "
        "WHERE employee_id = ANY(%s) AND status = 'resolved'",
        (emp_ids,),
    )
    documented = {(r["employee_id"], r["stage"]) for r in rows_to_list(cur)}

    def open_obligation(s, stage):
        cur.execute(
            "INSERT INTO doc_obligations (org_id, employee_id, store, stage, points) "
            "VALUES (%s, %s, %s, %s, %s)",
            (store_org.get(s["store"]), s["employee_id"], s["store"], stage,
             s["active_points"]),
        )

    for s in stats:
        if store_org.get(s["store"]) not in enabled_orgs:
            continue
        eid, stage = s["employee_id"], s["disciplinary_stage"]
        needs_doc = stage in DOC_REQUIRED_STAGES and (eid, stage) not in documented
        existing = open_by_emp.get(eid)
        if existing:
            if stage not in DOC_REQUIRED_STAGES:
                cur.execute(
                    "UPDATE doc_obligations SET status = 'lapsed' WHERE id = %s",
                    (existing["id"],),
                )
            elif existing["stage"] != stage:
                cur.execute(
                    "UPDATE doc_obligations SET status = 'superseded' WHERE id = %s",
                    (existing["id"],),
                )
                if needs_doc:
                    open_obligation(s, stage)
        elif needs_doc:
            open_obligation(s, stage)


@app.route("/api/doc-obligations", methods=["GET"])
def doc_obligations():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, features FROM orgs")
    enabled_orgs = {
        r["id"] for r in rows_to_list(cur)
        if merged_features(r["features"])["written_docs"]
    }
    if not enabled_orgs:
        return jsonify({"enabled": False, "items": []})
    cur.execute("SELECT store, org_id FROM stores")
    store_org = {r["store"]: r["org_id"] for r in rows_to_list(cur)}
    # Sync covers the caller's scope: whoever can see a store keeps its
    # obligations current just by loading the dashboard.
    _sync_doc_obligations(cur, compute_stats(), store_org, enabled_orgs)
    db.commit()
    query = (
        "SELECT d.id, d.employee_id, e.name, d.store, d.stage, d.points, "
        "d.opened_at FROM doc_obligations d "
        "JOIN employees e ON e.employee_id = d.employee_id "
        "WHERE d.status = 'open'"
    )
    params = []
    scope, scope_params = store_scope_clause("d.store")
    query += scope
    params += scope_params
    query += " ORDER BY d.opened_at, e.name"
    cur.execute(query, params)
    return jsonify({"enabled": True, "items": rows_to_list(cur)})


@app.route("/api/doc-obligations/<int:oid>/resolve", methods=["POST"])
def resolve_doc_obligation(oid):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM doc_obligations WHERE id = %s", (oid,))
    row = row_to_dict(cur)
    if not row:
        return jsonify({"error": "Obligation not found"}), 404
    allowed = allowed_stores()
    if allowed is not None and row["store"] not in allowed:
        return jsonify({"error": "Obligation not found"}), 404
    if row["status"] != "open":
        return jsonify({"error": "This item was already handled."}), 409
    data = request.get_json(silent=True) or {}
    method = (data.get("method") or "other").strip().lower()
    note = (data.get("note") or "").strip() or None
    user = current_user()
    cur.execute(
        "UPDATE doc_obligations SET status = 'resolved', resolved_by = %s, "
        "resolved_at = NOW(), method = %s, note = %s WHERE id = %s",
        (user["username"] if user else "api", method, note, oid),
    )
    db.commit()
    return jsonify({"ok": True, "id": oid})


# ── On-demand scrape requests (platform admin queues; worker executes) ───────

def _missing_stores_by_org(cur, org_id=None):
    """Stores whose data is not current through yesterday, grouped by org.
    Only orgs with a connected Pulse credential are considered (no credential
    = nothing the worker could do). Mirrors /api/freshness: newest successful
    scrape_runs date, imported_batches as legacy fallback."""
    yesterday = (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%d")
    params = []
    org_filter = ""
    if org_id:
        org_filter = " AND s.org_id = %s"
        params.append(org_id)
    cur.execute(
        """
        SELECT s.store, s.org_id
        FROM stores s
        JOIN pulse_credentials pc ON pc.org_id = s.org_id AND pc.status = 'connected'
        WHERE s.org_id IS NOT NULL
        """ + org_filter + " ORDER BY s.store",
        params,
    )
    stores = rows_to_list(cur)
    names = [s["store"] for s in stores]
    best = {}
    if names:
        cur.execute(
            "SELECT store, MAX(run_date) AS d FROM scrape_runs "
            "WHERE store = ANY(%s) AND status = 'success' GROUP BY store",
            (names,),
        )
        for r in rows_to_list(cur):
            best[r["store"]] = r["d"]
        cur.execute(
            "SELECT store, MAX(date) AS d FROM imported_batches "
            "WHERE store = ANY(%s) GROUP BY store",
            (names,),
        )
        for r in rows_to_list(cur):
            if not best.get(r["store"]) or r["d"] > best[r["store"]]:
                best[r["store"]] = max(best.get(r["store"]) or "", r["d"])
    missing = defaultdict(list)
    for s in stores:
        d = best.get(s["store"])
        if not d or d < yesterday:
            missing[s["org_id"]].append(s["store"])
    return missing, yesterday


@app.route("/api/admin/scrape-requests", methods=["GET", "POST"])
def admin_scrape_requests():
    err = require_platform_admin()
    if err:
        return err
    db = get_db()
    cur = db.cursor()
    if request.method == "GET":
        cur.execute(
            """
            SELECT sr.id, sr.org_id, o.name AS org_name, sr.stores, sr.run_date,
                   sr.status, sr.detail, sr.requested_by, sr.created_at, sr.finished_at
            FROM scrape_requests sr JOIN orgs o ON o.id = sr.org_id
            ORDER BY sr.id DESC LIMIT 20
            """
        )
        return jsonify(rows_to_list(cur))
    data = request.get_json(silent=True) or {}
    org_id = data.get("org_id") or org_view_id()
    missing, run_date = _missing_stores_by_org(cur, org_id)
    # One open request per org at a time: don't stack duplicates onto the queue.
    cur.execute(
        "SELECT org_id FROM scrape_requests WHERE status IN ('pending', 'running')"
    )
    open_orgs = {r["org_id"] for r in rows_to_list(cur)}
    user = current_user()
    created = []
    skipped = []
    for oid, store_list in sorted(missing.items()):
        if oid in open_orgs:
            skipped.append({"org_id": oid, "reason": "request already queued"})
            continue
        cur.execute(
            "INSERT INTO scrape_requests (org_id, stores, run_date, requested_by) "
            "VALUES (%s, %s, %s, %s) RETURNING id",
            (oid, store_list, run_date, user["username"] if user else "api"),
        )
        created.append({
            "id": cur.fetchone()["id"], "org_id": oid,
            "stores": store_list, "run_date": run_date,
        })
    db.commit()
    return jsonify({
        "created": created,
        "skipped": skipped,
        "message": ("Nothing to pull — every store with a connected credential is current."
                    if not created and not skipped else None),
    }), 201 if created else 200


# ── Worker endpoints (scrape worker via API key only) ─────────────────────────

def require_worker():
    if current_user() is not None:
        return jsonify({"error": "Worker API key required"}), 403
    return None


@app.route("/api/worker/credentials", methods=["GET"])
def worker_credentials():
    err = require_worker()
    if err:
        return err
    cur = get_db().cursor()
    cur.execute("""
        SELECT pc.org_id, o.slug AS org_slug, o.name AS org_name,
               pc.pwr_username, pc.enc_password, pc.status, pc.updated_at
        FROM pulse_credentials pc JOIN orgs o ON o.id = pc.org_id
        ORDER BY pc.org_id
    """)
    return jsonify(rows_to_list(cur))


@app.route("/api/worker/credential-status", methods=["POST"])
def worker_credential_status():
    err = require_worker()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    org_id = data.get("org_id")
    status = (data.get("status") or "").strip()
    if not org_id or status not in {"connected", "login_failed", "error"}:
        return jsonify({"error": "org_id and status (connected|login_failed|error) are required"}), 400
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "UPDATE pulse_credentials SET status = %s, status_detail = %s, last_checked_at = NOW() "
        "WHERE org_id = %s",
        (status, (data.get("detail") or "").strip() or None, org_id),
    )
    updated = cur.rowcount
    db.commit()
    return jsonify({"updated": bool(updated), "org_id": org_id, "status": status})


@app.route("/api/worker/scrape-requests", methods=["GET"])
def worker_scrape_requests():
    err = require_worker()
    if err:
        return err
    cur = get_db().cursor()
    cur.execute(
        """
        SELECT sr.id, sr.org_id, o.slug AS org_slug, sr.stores, sr.run_date
        FROM scrape_requests sr JOIN orgs o ON o.id = sr.org_id
        WHERE sr.status = 'pending' ORDER BY sr.id
        """
    )
    return jsonify(rows_to_list(cur))


@app.route("/api/worker/scrape-requests/<int:rid>", methods=["POST"])
def worker_scrape_request_status(rid):
    err = require_worker()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    status = (data.get("status") or "").strip()
    if status not in {"running", "done", "error"}:
        return jsonify({"error": "status (running|done|error) is required"}), 400
    db = get_db()
    cur = db.cursor()
    stamps = "started_at = NOW()" if status == "running" else "finished_at = NOW()"
    cur.execute(
        f"UPDATE scrape_requests SET status = %s, detail = %s, {stamps} WHERE id = %s",
        (status, (data.get("detail") or "").strip() or None, rid),
    )
    updated = cur.rowcount
    db.commit()
    if not updated:
        return jsonify({"error": "Unknown request id"}), 404
    return jsonify({"id": rid, "status": status})


@app.route("/api/worker/scrape-runs", methods=["POST"])
def worker_scrape_runs():
    err = require_worker()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    runs = data.get("runs")
    if runs is None:
        runs = [data] if data.get("store") else []
    if not isinstance(runs, list) or not runs:
        return jsonify({"error": "Expected {runs: [...]} or a single run object"}), 400
    db = get_db()
    cur = db.cursor()
    slug_cache = {}
    recorded = 0
    errors = []
    for i, r in enumerate(runs):
        org_id = r.get("org_id")
        slug = (r.get("org_slug") or "").strip().lower()
        if not org_id and slug:
            if slug not in slug_cache:
                cur.execute("SELECT id FROM orgs WHERE slug = %s", (slug,))
                row = cur.fetchone()
                slug_cache[slug] = row["id"] if row else None
            org_id = slug_cache[slug]
        store = (r.get("store") or "").strip()
        run_date = (r.get("run_date") or "").strip()
        status = (r.get("status") or "").strip()
        if not org_id or not store or not run_date or status not in {"success", "failed", "missing"}:
            errors.append({"index": i, "error": "org_id/org_slug, store, run_date, and status (success|failed|missing) are required"})
            continue
        cur.execute(
            "INSERT INTO scrape_runs (org_id, store, run_date, status, rows_imported, error, started_at, finished_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (org_id, store, run_date, status, r.get("rows_imported"),
             (r.get("error") or "").strip() or None, r.get("started_at"), r.get("finished_at")),
        )
        recorded += 1
    db.commit()
    resp = {"recorded": recorded}
    if errors:
        resp["errors"] = errors
    return jsonify(resp), 201 if recorded else 400


# ── Day stats (all dashboard roles; store-scoped) ─────────────────────────────

@app.route("/api/day-stats", methods=["GET"])
def get_day_stats():
    """Scheduled-headcount per visible store for one date (default yesterday).
    scheduled_count is null for batches that predate the worker reporting it."""
    date = (request.args.get("date") or "").strip()
    if not date:
        date = (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%d")
    cur = get_db().cursor()
    scope, params = store_scope_clause("store")
    cur.execute(
        "SELECT store, scheduled_count FROM imported_batches WHERE date = %s" + scope,
        [date] + params,
    )
    return jsonify({"date": date, "stores": rows_to_list(cur)})


# ── Data freshness (all dashboard roles) ──────────────────────────────────────

@app.route("/api/freshness", methods=["GET"])
def get_freshness():
    """Per-store data freshness for the caller's visible stores, computed from
    the worker's scrape_runs ledger with imported_batches as a legacy fallback
    for stores that predate the ledger."""
    db = get_db()
    cur = db.cursor()
    scope, params = store_scope_clause("s.store")
    cur.execute(
        "SELECT s.store, s.name, s.org_id FROM stores s WHERE TRUE" + scope + " ORDER BY s.store",
        params,
    )
    stores = rows_to_list(cur)
    names = [s["store"] for s in stores]
    latest_success = {}
    latest_attempt = {}
    legacy = {}
    has_ledger = set()
    if names:
        cur.execute(
            "SELECT store, MAX(run_date) AS run_date FROM scrape_runs "
            "WHERE store = ANY(%s) AND status = 'success' GROUP BY store",
            (names,),
        )
        for r in rows_to_list(cur):
            latest_success[r["store"]] = r["run_date"]
        cur.execute(
            "SELECT DISTINCT ON (store) store, run_date, status, error, reported_at "
            "FROM scrape_runs WHERE store = ANY(%s) ORDER BY store, reported_at DESC",
            (names,),
        )
        for r in rows_to_list(cur):
            has_ledger.add(r["store"])
            latest_attempt[r["store"]] = r
        cur.execute(
            "SELECT store, MAX(date) AS date FROM imported_batches "
            "WHERE store = ANY(%s) GROUP BY store",
            (names,),
        )
        for r in rows_to_list(cur):
            legacy[r["store"]] = r["date"]
    yesterday = (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%d")
    out = []
    for s in stores:
        st = s["store"]
        best = latest_success.get(st) or legacy.get(st)
        attempt = latest_attempt.get(st)
        if best and best >= yesterday:
            status = "current"
        elif attempt and attempt["status"] != "success":
            status = "failed"
        elif best:
            status = "behind"
        else:
            status = "unknown"
        out.append({
            "store": st,
            "name": s["name"],
            "status": status,
            "data_through": best,
            "last_attempt_status": attempt["status"] if attempt else None,
            "last_attempt_date": attempt["run_date"] if attempt else None,
            "tracked_by_worker": st in has_ledger,
        })
    return jsonify({
        "stores": out,
        "all_current": bool(out) and all(s["status"] == "current" for s in out),
        "as_of": datetime.utcnow().isoformat(),
    })


# ── Startup ───────────────────────────────────────────────────────────────────

with app.app_context():
    init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
