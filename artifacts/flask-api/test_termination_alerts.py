"""Termination (soft-deactivate) + terminated-clock-in alerts.

Run with: /opt/homebrew/bin/python3.11 test_termination_alerts.py
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
r = c.post("/api/users", headers=KEY, json={"username": "alpha-dm", "password": "x", "role": "dm", "org_id": alpha})
dm_id = r.get_json()["id"]
c.patch("/api/stores/1001", headers=KEY, json={"dm_user_id": dm_id})  # DM covers 1001 only

c.post("/api/employees", headers=KEY, json={"employee_id": "A1", "name": "Al Gone", "store": "1001"})
c.post("/api/employees", headers=KEY, json={"employee_id": "A2", "name": "Amy Other", "store": "1002"})
c.post("/api/employees", headers=KEY, json={"employee_id": "B1", "name": "Bea Beta", "store": "2001"})

recent = (datetime.utcnow() - timedelta(days=3)).strftime("%Y-%m-%d")

def add_points(emp, pts):
    r = c.post("/api/logs", headers=KEY, json={
        "employee_id": emp, "date": recent, "status": "manual_addition",
        "manual_points": pts,
    })
    assert r.status_code == 201, r.get_data()
    return r.get_json()["id"]

add_points("A1", 9.5)  # Written Warning

def login(u):
    r = c.post("/api/dashboard/login", json={"username": u, "password": "x"})
    assert r.status_code == 200, r.get_data()
    return {"X-Dashboard-Token": r.get_json()["token"]}

alpha_own = login("alpha-own")
beta_own = login("beta-own")
gm1001 = login("gm1001")
alpha_dm = login("alpha-dm")

def stats_ids(headers):
    return {s["employee_id"] for s in c.get("/api/stats", headers=headers).get_json()}

# ── Access control on terminate / reactivate ─────────────────────────────────
r = c.post("/api/employees/A1/terminate", headers=gm1001, json={})
check("store account cannot terminate", r.status_code == 403)

r = c.post("/api/employees/A2/terminate", headers=alpha_dm, json={})
check("dm cannot terminate outside assigned stores", r.status_code == 403)

r = c.post("/api/employees/NOPE/terminate", headers=alpha_own, json={})
check("unknown employee 404s", r.status_code == 404)

r = c.post("/api/employees/A1/terminate", headers=alpha_own, json={"last_day": "not-a-date"})
check("bad last_day rejected", r.status_code == 400)

# ── Doc obligation lapses on termination ─────────────────────────────────────
c.put("/api/org/features", headers=alpha_own, json={"written_docs": True})
r = c.get("/api/doc-obligations", headers=alpha_own)
check("A1 has an open write-up obligation before termination",
      "A1" in {i["employee_id"] for i in r.get_json()["items"]})

r = c.post("/api/employees/A1/terminate", headers=alpha_dm, json={"note": "walked out"})
body = r.get_json()
check("dm terminates own-store employee", r.status_code == 200 and body["active"] is False)
check("termination records who and note",
      body["terminated_by"] == "alpha-dm" and body["terminated_note"] == "walked out")

check("terminated employee drops out of stats", "A1" not in stats_ids(alpha_own))
r = c.get("/api/doc-obligations", headers=alpha_own)
check("open obligation lapses on termination",
      "A1" not in {i["employee_id"] for i in r.get_json()["items"]})

r = c.get("/api/streaks", headers=alpha_own)
check("terminated employee absent from streaks",
      "A1" not in {s["employee_id"] for s in r.get_json()})

r = c.get("/api/logs", headers=alpha_own)
a1_logs = [l for l in r.get_json() if l["employee_id"] == "A1"]
check("history kept; logs flag employee_active=false",
      a1_logs and all(l["employee_active"] is False for l in a1_logs))

# ── Reactivate ───────────────────────────────────────────────────────────────
r = c.post("/api/employees/A1/reactivate", headers=alpha_dm, json={})
check("dm can reactivate", r.status_code == 200 and r.get_json()["active"] is True)
check("reactivated employee back in stats", "A1" in stats_ids(alpha_own))

# ── Post-termination clock-in → alert on import ──────────────────────────────
last_day = (datetime.utcnow() - timedelta(days=5)).strftime("%Y-%m-%d")
before = (datetime.utcnow() - timedelta(days=8)).strftime("%Y-%m-%d")
after = (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%d")
r = c.post("/api/employees/A1/terminate", headers=alpha_own, json={"last_day": last_day})
assert r.status_code == 200, r.get_data()

payload = {"records": [{"employee_id": "A1", "name": "Al Gone", "store": "1001",
                        "logs": [{"date": after, "status": "late", "minutes_late": 20}]}]}
r = c.post("/api/import", headers=dict(KEY, **{"X-Org-Slug": "alpha-pizza"}), json=payload)
body = r.get_json()
check("import diverts post-termination log to an alert",
      r.status_code == 201 and body["alerts_created"] == 1 and body["imported_logs"] == 0)

r = c.get("/api/logs", headers=alpha_own)
check("the post-termination log itself was not imported",
      not any(l["employee_id"] == "A1" and l["date"] == after for l in r.get_json()))

r = c.post("/api/import", headers=dict(KEY, **{"X-Org-Slug": "alpha-pizza"}), json=payload)
check("re-import does not duplicate the alert", r.get_json()["alerts_created"] == 0)

r = c.post("/api/import", headers=dict(KEY, **{"X-Org-Slug": "alpha-pizza"}), json={
    "records": [{"employee_id": "A1", "name": "Al Gone", "store": "1001",
                 "logs": [{"date": before, "status": "late", "minutes_late": 10}]}]})
body = r.get_json()
check("log before the last day imports normally, no alert",
      body["imported_logs"] == 1 and body["alerts_created"] == 0)

# ── Alert visibility + scoping ───────────────────────────────────────────────
r = c.get("/api/alerts", headers=alpha_dm)
items = r.get_json()
check("dm sees the unacked alert", r.status_code == 200 and len(items) == 1)
al = items[0]
check("alert carries kind/store/employee",
      al["kind"] == "terminated_clock_in" and al["store"] == "1001"
      and al["employee_id"] == "A1" and after in al["message"])

check("owner sees it too", len(c.get("/api/alerts", headers=alpha_own).get_json()) == 1)
check("other org's owner sees nothing", c.get("/api/alerts", headers=beta_own).get_json() == [])
check("store account cannot list alerts", c.get("/api/alerts", headers=gm1001).status_code == 403)

# ── Acknowledge ──────────────────────────────────────────────────────────────
check("store account cannot ack", c.post(f"/api/alerts/{al['id']}/ack", headers=gm1001).status_code == 403)
check("other org's owner cannot ack", c.post(f"/api/alerts/{al['id']}/ack", headers=beta_own).status_code == 404)

r = c.post(f"/api/alerts/{al['id']}/ack", headers=alpha_dm)
check("dm acks own-store alert", r.status_code == 200)
check("double-ack rejected", c.post(f"/api/alerts/{al['id']}/ack", headers=alpha_dm).status_code == 409)
check("acked alert leaves the default list", c.get("/api/alerts", headers=alpha_dm).get_json() == [])

r = c.get("/api/alerts?all=1", headers=alpha_dm)
hist = r.get_json()
check("?all=1 shows history with acknowledged_by",
      len(hist) == 1 and hist[0]["acknowledged_by"] == "alpha-dm"
      and hist[0]["acknowledged_at"] is not None)

# After acking, a fresh import of the same day may alert again (new incident
# data) — the dedupe only guards unacked duplicates.
r = c.post("/api/import", headers=dict(KEY, **{"X-Org-Slug": "alpha-pizza"}), json=payload)
check("post-ack re-import raises a fresh alert", r.get_json()["alerts_created"] == 1)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
