"""Written-documentation feature: org toggle + Overview action items.

Run with: /opt/homebrew/bin/python3.11 test_doc_obligations.py
(embedded Postgres via pgserver — same harness as test_org_view.py)
"""
import os, sys, tempfile
from datetime import datetime, timedelta

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

# ── Seed: two orgs, stores, users, employees ─────────────────────────────────
alpha = c.post("/api/orgs", headers=KEY, json={"name": "Alpha Pizza"}).get_json()["id"]
beta = c.post("/api/orgs", headers=KEY, json={"name": "Beta Pizza"}).get_json()["id"]
for store, org in [("1001", alpha), ("1002", alpha), ("2001", beta)]:
    r = c.patch(f"/api/stores/{store}", headers=KEY, json={"org_id": org, "name": f"Store {store}"})
    assert r.status_code in (200, 201), r.get_data()

c.post("/api/users", headers=KEY, json={"username": "alpha-own", "password": "x", "role": "owner", "org_id": alpha})
c.post("/api/users", headers=KEY, json={"username": "beta-own", "password": "x", "role": "owner", "org_id": beta})
c.post("/api/users", headers=KEY, json={"username": "gm1001", "password": "x", "role": "store", "store": "1001", "org_id": alpha})
c.post("/api/users", headers=KEY, json={"username": "gm1002", "password": "x", "role": "store", "store": "1002", "org_id": alpha})
dm_id = None
r = c.post("/api/users", headers=KEY, json={"username": "alpha-dm", "password": "x", "role": "dm", "org_id": alpha})
dm_id = r.get_json()["id"]
c.patch("/api/stores/1001", headers=KEY, json={"dm_user_id": dm_id})

c.post("/api/employees", headers=KEY, json={"employee_id": "A1", "name": "Al Written", "store": "1001"})
c.post("/api/employees", headers=KEY, json={"employee_id": "A2", "name": "Amy Good", "store": "1001"})
c.post("/api/employees", headers=KEY, json={"employee_id": "A3", "name": "Ann Lapse", "store": "1002"})
c.post("/api/employees", headers=KEY, json={"employee_id": "B1", "name": "Bea Written", "store": "2001"})

recent = (datetime.utcnow() - timedelta(days=3)).strftime("%Y-%m-%d")

def add_points(emp, pts):
    r = c.post("/api/logs", headers=KEY, json={
        "employee_id": emp, "date": recent, "status": "manual_addition",
        "manual_points": pts,
    })
    assert r.status_code == 201, r.get_data()
    return r.get_json()["id"]

# A1 and B1 land in Written Warning (9–10); A2 stays in Good Standing.
add_points("A1", 9.5)
add_points("B1", 9.5)
a3_log = add_points("A3", 9.5)

def login(u):
    r = c.post("/api/dashboard/login", json={"username": u, "password": "x"})
    assert r.status_code == 200, r.get_data()
    return {"X-Dashboard-Token": r.get_json()["token"]}

alpha_own = login("alpha-own")
beta_own = login("beta-own")
gm1001 = login("gm1001")
gm1002 = login("gm1002")
alpha_dm = login("alpha-dm")

# ── Feature toggle ───────────────────────────────────────────────────────────
r = c.get("/api/org/features", headers=alpha_own)
check("features default: written_docs off", r.status_code == 200 and r.get_json()["features"]["written_docs"] is False)

r = c.get("/api/doc-obligations", headers=alpha_own)
check("no orgs enabled -> enabled false, no items", r.get_json() == {"enabled": False, "items": []})

r = c.put("/api/org/features", headers=alpha_own, json={"written_docs": True})
check("owner can enable written_docs", r.status_code == 200 and r.get_json()["features"]["written_docs"] is True)

r = c.put("/api/org/features", headers=gm1001, json={"written_docs": False})
check("store account cannot toggle features", r.status_code == 403)

r = c.put("/api/org/features", headers=alpha_own, json={"nope": True})
check("unknown feature key rejected", r.status_code == 400)

# ── Obligation creation + visibility ─────────────────────────────────────────
r = c.get("/api/doc-obligations", headers=alpha_own)
items = r.get_json()["items"]
check("alpha owner sees exactly A1 + A3 obligations",
      sorted(i["employee_id"] for i in items) == ["A1", "A3"])
check("obligation carries stage + points",
      all(i["stage"] == "Written Warning" and float(i["points"]) == 9.5 for i in items))

r = c.get("/api/doc-obligations", headers=beta_own)
check("beta org disabled -> beta owner sees nothing", r.get_json()["items"] == [])

r = c.get("/api/doc-obligations", headers=gm1001)
check("GM sees own store's obligation only",
      [i["employee_id"] for i in r.get_json()["items"]] == ["A1"])

r = c.get("/api/doc-obligations", headers=alpha_dm)
check("DM sees assigned store's obligation",
      [i["employee_id"] for i in r.get_json()["items"]] == ["A1"])

a1_oid = [i for i in items if i["employee_id"] == "A1"][0]["id"]
a3_oid = [i for i in items if i["employee_id"] == "A3"][0]["id"]

# ── Resolution ───────────────────────────────────────────────────────────────
r = c.post(f"/api/doc-obligations/{a1_oid}/resolve", headers=beta_own, json={"method": "zenput"})
check("other org's owner cannot resolve", r.status_code == 404)

r = c.post(f"/api/doc-obligations/{a1_oid}/resolve", headers=gm1001,
           json={"method": "zenput", "note": "submission #123"})
check("GM can resolve own store's obligation", r.status_code == 200)

r = c.post(f"/api/doc-obligations/{a1_oid}/resolve", headers=gm1001, json={"method": "paper"})
check("double-resolve rejected", r.status_code == 409)

r = c.get("/api/doc-obligations", headers=gm1001)
check("resolved item leaves the GM's list", r.get_json()["items"] == [])

# Same stage does not re-open once documented...
r = c.get("/api/doc-obligations", headers=alpha_own)
check("documented stage does not re-open", "A1" not in [i["employee_id"] for i in r.get_json()["items"]])

# ...but crossing into a higher stage opens a new obligation.
add_points("A1", 1.0)  # 10.5 -> Final Written Warning
r = c.get("/api/doc-obligations", headers=alpha_own)
a1_items = [i for i in r.get_json()["items"] if i["employee_id"] == "A1"]
check("next stage opens a fresh obligation",
      len(a1_items) == 1 and a1_items[0]["stage"] == "Final Written Warning")

# ── Lapse: dropping below the stage clears the open item ─────────────────────
r = c.patch(f"/api/logs/{a3_log}", headers=KEY, json={"manual_points": 2.0})
assert r.status_code == 200, r.get_data()
r = c.get("/api/doc-obligations", headers=alpha_own)
check("employee back in good standing -> obligation lapses",
      "A3" not in [i["employee_id"] for i in r.get_json()["items"]])

# ── Enabling beta later picks up its existing employee ───────────────────────
r = c.put("/api/org/features", headers=KEY, json={"org_id": beta, "written_docs": True})
check("platform-level toggle by org_id works", r.status_code == 200)
r = c.get("/api/doc-obligations", headers=beta_own)
check("beta obligation appears once enabled",
      [i["employee_id"] for i in r.get_json()["items"]] == ["B1"])

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
