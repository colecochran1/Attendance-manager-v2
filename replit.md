# Flask Attendance API

A standalone Flask REST API for tracking employee attendance, point-based disciplinary status, and shift swaps. Backed by PostgreSQL, served by gunicorn, and deployable as a Replit `web` artifact.

## Run & Operate

- Workflow `artifacts/flask-api: web` runs the API via gunicorn (managed by the artifact).
- Manual run: `cd artifacts/flask-api && gunicorn --bind 0.0.0.0:${PORT:-20888} --workers 2 --preload main:app`
- Health check: `GET /api/healthz` (public, no auth)
- All other `/api/*` routes require **either** the `X-API-Key` header (matching `ATTENDANCE_API_KEY`, for programmatic use) **or** a valid dashboard session token in the `X-Dashboard-Token` header (issued to the web dashboard after password login).
- Required env/secrets: `DATABASE_URL` (auto-provisioned Postgres), `ATTENDANCE_API_KEY`, `SUPERVISOR_PASSWORD` (full-access account), `MANAGER_PASSWORD` (read-only account), `SESSION_SECRET` (signs dashboard tokens — **required**, the app refuses to start without it). All must be present in production.

## Stack

- Python 3.11, Flask, gunicorn
- PostgreSQL via psycopg2 (raw SQL, no ORM)
- Single-file app: `artifacts/flask-api/main.py`

## Where things live

- `artifacts/flask-api/main.py` — the entire Flask app (schema init, routes, auth)
- `artifacts/flask-api/requirements.txt` — Python dependencies
- `artifacts/flask-api/.replit-artifact/artifact.toml` — artifact + deployment config (gunicorn process, health check)

## Architecture decisions

- Deployed as a `kind = "web"` artifact (the only deployable/publishable kind) but configured as a pure gunicorn process — no static serving, no `publicDir`, no JS build.
- `--preload` is required: it loads the app (and runs `init_db()`) once in the master before forking workers, avoiding a multi-worker race on `CREATE TABLE`.
- Run command is CWD-resilient (`cd artifacts/flask-api 2>/dev/null; exec gunicorn ...`) so it works whether started from the artifact dir (dev workflow) or repo root (production).
- Tables are created at startup via `init_db()`; there is no migration tool.

## Web dashboard

- `GET /` serves `dashboard.html` — a mobile-friendly, single-file (HTML/CSS/JS) manager dashboard. It is **public** (no API key) because the page itself prompts for the key and stores it in `sessionStorage`, sending it as `X-API-Key` on every `/api/*` call.
- Public (keyless) paths are listed in `PUBLIC_PATHS` in `main.py` (`/`, `/dashboard.html`, `/api/healthz`, `/favicon.ico`); everything else requires the key.
- Dashboard tabs: Overview (summary cards + flagged list from `/api/stats`), Employees (points + stage), Attendance (logs), Swaps (approve/reject pending shift swaps via `PATCH /api/swap/<id>`).

## API surface

- `POST /api/import` — bulk import attendance data
- `GET/POST /api/employees`, `PATCH/DELETE /api/employees/<id>`
- `GET /api/logs`, `PATCH/DELETE /api/logs/<id>`
- `POST /api/swap`, `GET /api/swaps`, `PATCH /api/swap/<id>`
- `GET /api/stats` — attendance points / disciplinary stage summary

## Gotchas

- Every non-health route returns `401` without a valid `X-API-Key`, and `500` if `ATTENDANCE_API_KEY` is unset on the server.
- Artifact-managed workflows run from inside the artifact directory, not the repo root — do not assume CWD.
- `$REPLIT_DOMAINS` is the **dev** workspace domain, not the production URL — always use `getDeploymentInfo().primaryUrl` when testing/operating against the real production deployment. Dev and production use separate databases.
- **Attendance logging is exception-based, not comprehensive**: `attendance_logs` only gets a row when something notable happens (late, called_in, ncns, exempted, covered_shift). A normal on-time shift is never logged — its absence IS the "on time" signal. Never write logic that expects/creates an `on_time` status; it doesn't exist. `imported_batches` (store, date) is the only proxy for "this store had a shift day," and is what `/api/streaks` uses as the universe of shift days per store, since there's no per-employee schedule table (day-off vs. clean-shift is not distinguishable).

## Agent / automation accounts

- `HARDCODED_DM_STORE_ACCESS` in `main.py` grants specific DM-role usernames (e.g. `leo`) a fixed, hardcoded set of store scopes, additively merged in `allowed_stores()`. This is separate from the normal per-store `stores.dm_user_id` assignment, so it never displaces another DM's store assignment and isn't affected by reassigning stores to other DMs.
- Currently: `leo` → stores `2501`, `2545`, `2556`, `2557` (the same stores normally assigned to DM `ccochran`; both have independent full access).
- See `artifacts/flask-api/LEO_API_GUIDE.md` for the API reference given to the Leo agent (auth flow, endpoints, error handling).

## Pointers

- See the `pnpm-workspace` skill for workspace structure and artifact conventions.
- See the `deployment` skill for how production config in `artifact.toml` drives publishing.

## Multi-tenancy (Slicework)

This app is becoming **Slicework** — a multi-tenant platform for franchisee groups.

- `orgs` table = franchisee groups. `users.org_id` and `stores.org_id` attribute everything; employees/logs/redemptions derive their org through their store. Legacy data was migrated into the default org (`DEFAULT_ORG_NAME`, default "DTID Pizza") on first boot.
- Roles: `platform_admin` (Slicework operator, cross-org, org_id NULL) > `owner` (their org only) > `dm` > `store`. Tenant isolation is enforced in `allowed_stores()` — org owners get their org's store set, and every data query flows through `store_scope_clause()`.
- **Pulse credentials vault**: `POST /api/org/pulse-credentials` RSA-OAEP-encrypts the PWR password with the worker's public key (`worker_public_key.pem`, or `WORKER_PUBLIC_KEY` env). The private key lives only on the scrape worker machine — this server cannot decrypt stored credentials.
- **Worker endpoints** (X-API-Key only, rejected for dashboard tokens): `GET /api/worker/credentials`, `POST /api/worker/credential-status`, `POST /api/worker/scrape-runs`.
- **Scrape health**: `scrape_runs` ledger per (org, store, business date); `GET /api/freshness` computes per-store status (current/behind/failed/unknown) with `imported_batches` as legacy fallback. Dashboard shows chips + a banner; deliberately NO user-facing re-run button.
- `POST /api/import` accepts `X-Org-Slug` to attribute data; without it, data goes to the default (oldest) org for legacy pipeline compatibility.
- Test suite: `slicework_test.py` pattern (embedded Postgres via `pgserver`, Flask test client) exercises isolation + vault + freshness end to end.
