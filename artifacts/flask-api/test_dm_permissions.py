"""DM carve-outs: manual points, store-scoped termination, store-account
password resets.

Run with: /opt/homebrew/bin/python3.11 test_dm_permissions.py
(embedded Postgres via pgserver — same harness as test_org_view.py)
"""
import os, sys, tempfile

import pgserver

tmp = tempfile.mkdtemp(prefix="sw_pg_")
pg = pgserver.get_server(tmp)
os.environ["DATABASE_URL"] = pg.get_uri()
os.environ["SESSION_SECRET"] = "test-secret"
os.environ["ATTENDANCE_API_KEY"] = "test-api-key"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import main  # noqa: E402

with main.app.app_context():
    main.init_db()
    main.get_db().commit()

c = main.app.test_client()
KEY = {"X-API-Key": "test-api-key"}
passed = failed = 0

def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ok: {name}")
    else: failed += 1; print(f"FAIL: {name}")

# ── Seed: one org, three stores, a DM on two of them ──
r = c.post("/api/orgs", headers=KEY, json={"name": "Gamma Pizza"})
gamma = r.get_json()["id"]
r = c.post("/api/orgs", headers=KEY, json={"name": "Delta Pizza"})
delta = r.get_json()["id"]
for store, org in [("3001", gamma), ("3002", gamma), ("3003", gamma), ("4001", delta)]:
    r = c.patch(f"/api/stores/{store}", headers=KEY, json={"org_id": org, "name": f"Store {store}"})
    assert r.status_code in (200, 201), r.get_data()

c.post("/api/users", headers=KEY, json={"username": "gamma-own", "password": "x", "role": "owner", "org_id": gamma})
c.post("/api/users", headers=KEY, json={"username": "gamma-dm", "password": "x", "role": "dm", "org_id": gamma})
users = c.get("/api/users", headers=KEY).get_json()
dm_id = [u["id"] for u in users if u["username"] == "gamma-dm"][0]
own_id = [u["id"] for u in users if u["username"] == "gamma-own"][0]
for store in ("3001", "3002"):
    r = c.patch(f"/api/stores/{store}", headers=KEY, json={"dm_user_id": dm_id})
    assert r.status_code == 200, r.get_data()

c.post("/api/employees", headers=KEY, json={"employee_id": "G1", "name": "Gil", "store": "3001"})
c.post("/api/employees", headers=KEY, json={"employee_id": "G3", "name": "Gus", "store": "3003"})
c.post("/api/employees", headers=KEY, json={"employee_id": "D1", "name": "Deb", "store": "4001"})

# Store accounts (auto-provision path not exercised; create directly)
for store, org in [("3001", gamma), ("3002", gamma), ("3003", gamma), ("4001", delta)]:
    c.post("/api/users", headers=KEY, json={"username": store, "password": store, "role": "store", "store": store, "org_id": org})
users = c.get("/api/users", headers=KEY).get_json()
acct = {u["username"]: u["id"] for u in users}

def login(u, pw="x"):
    r = c.post("/api/dashboard/login", json={"username": u, "password": pw})
    assert r.status_code == 200, r.get_data()
    return {"X-Dashboard-Token": r.get_json()["token"]}

dm = login("gamma-dm")
store_hdr = login("3001", "3001")

# ── 1. Manual points (POST /api/logs) ──
r = c.post("/api/logs", headers=dm, json={
    "employee_id": "G1", "status": "manual_addition", "date": "2026-07-13",
    "manual_points": 1.5, "clock_in": "Repeated tardiness", "notes": "test"})
check("dm can add manual points at assigned store", r.status_code == 201)
r = c.post("/api/logs", headers=dm, json={
    "employee_id": "G3", "status": "manual_addition", "date": "2026-07-13", "manual_points": 1})
check("dm blocked from manual points outside assigned stores", r.status_code == 403)
r = c.post("/api/logs", headers=store_hdr, json={
    "employee_id": "G1", "status": "manual_addition", "date": "2026-07-13", "manual_points": 1})
check("store account still cannot add manual points", r.status_code == 403)

# ── 2. Termination scope (already live; regression guard) ──
r = c.post("/api/employees/G1/terminate", headers=dm, json={})
check("dm can terminate at assigned store", r.status_code == 200)
r = c.post("/api/employees/G3/terminate", headers=dm, json={})
check("dm blocked from terminating outside assigned stores", r.status_code == 403)
c.post("/api/employees/G1/reactivate", headers=dm, json={})

# ── 3. Store-account visibility (GET /api/users as dm) ──
r = c.get("/api/users", headers=dm)
check("dm may list users", r.status_code == 200)
listed = r.get_json()
check("dm sees only assigned stores' store accounts",
      {u["username"] for u in listed} == {"3001", "3002"})
check("dm listing contains no owner/dm/platform accounts",
      all(u["role"] == "store" for u in listed))

# ── 4. Password resets (PATCH /api/users/<id> as dm) ──
r = c.patch(f"/api/users/{acct['3002']}", headers=dm, json={"password": "newpw3002"})
check("dm can reset assigned store account password", r.status_code == 200)
r = c.post("/api/dashboard/login", json={"username": "3002", "password": "newpw3002"})
check("new password works", r.status_code == 200)
r = c.patch(f"/api/users/{acct['3003']}", headers=dm, json={"password": "x"})
check("dm blocked from other-store store account", r.status_code == 403)
r = c.patch(f"/api/users/{acct['4001']}", headers=dm, json={"password": "x"})
check("dm blocked from other-org store account", r.status_code == 403)
r = c.patch(f"/api/users/{own_id}", headers=dm, json={"password": "x"})
check("dm blocked from owner account", r.status_code == 403)
r = c.patch(f"/api/users/{acct['3001']}", headers=dm, json={"password": "x", "role": "dm"})
check("dm cannot change anything besides the password", r.status_code == 403)
r = c.delete(f"/api/users/{acct['3001']}", headers=dm)
check("dm cannot delete accounts", r.status_code == 403)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
