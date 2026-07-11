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
NON_OWNER_WRITE_ALLOWED = {"/api/redemptions"}
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
            # DMs may also correct attendance logs and approve/deny redemptions
            # for their own stores; the store-scope check lives in the endpoint.
            if user["role"] == "dm" and request.method in ("PATCH", "DELETE"):
                if re.fullmatch(r"/api/logs/\d+", request.path):
                    allowed = True
                elif re.fullmatch(r"/api/redemptions/\d+", request.path):
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
    "leo": {"2501", "2545", "2556", "2557"},
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

    for i, record in enumerate(records):
        employee_id = record.get("employee_id") or record.get("employeeId")
        name = record.get("name")

        if not employee_id or not name:
            errors.append({"index": i, "error": "employee_id and name are required"})
            continue

        store = record.get("store")
        if store and store not in seen_stores:
            seen_stores.add(store)
            cur.execute(
                "INSERT INTO stores (store, org_id) VALUES (%s, %s) "
                "ON CONFLICT (store) DO UPDATE SET org_id = COALESCE(stores.org_id, EXCLUDED.org_id)",
                (store, org_id),
            )

        cur.execute(
            """
            INSERT INTO employees (employee_id, name, position, store)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (employee_id) DO UPDATE SET
                name     = EXCLUDED.name,
                position = COALESCE(EXCLUDED.position, employees.position),
                store    = COALESCE(EXCLUDED.store, employees.store)
            """,
            (employee_id, name, record.get("position"), store),
        )
        imported_employees += 1

        for log in record.get("logs", []):
            date = log.get("date")
            if not date:
                continue
            if (store, date) in already_imported:
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

    db.commit()
    response = {
        "imported_employees": imported_employees,
        "imported_logs": imported_logs,
        "skipped_logs": skipped_logs,
    }
    if errors:
        response["errors"] = errors
    return jsonify(response), 201


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
        "e.position AS employee_position "
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


def base_points_for_log(status, minutes_late):
    status = (status or "").lower().strip()
    if status in NCNS_STATUSES:
        return None
    if status in CALLED_IN_STATUSES:
        return 2.0
    if status == "exempted":
        return 0.0
    if minutes_late is not None and minutes_late > 0:
        return 1.0 if minutes_late <= 60 else 2.0
    if status == "late":
        return 1.0
    if status in {"late_major", "late_1hr", "late_2hr"}:
        return 2.0
    return 0.0


def is_weekend(date_str):
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").weekday() in WEEKEND_DAYS
    except ValueError:
        return False


@app.route("/api/stats", methods=["GET"])
def get_stats():
    db = get_db()
    cur = db.cursor()
    window_days = int(request.args.get("window_days", 90))
    since = (datetime.utcnow() - timedelta(days=window_days)).strftime("%Y-%m-%d")
    employee_id = request.args.get("employee_id")
    store = request.args.get("store")
    emp_query = "SELECT * FROM employees WHERE TRUE"
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
            base = base_points_for_log(status, minutes_late)
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
            applied = base * 2 if weekend else base
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
    return jsonify(results)


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

    emp_query = "SELECT * FROM employees WHERE TRUE"
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
