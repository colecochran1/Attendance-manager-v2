"""Per-org point settings + on-demand scrape-request queue.

Run with: /opt/homebrew/bin/python3.11 test_point_config_and_pulls.py
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

# ── Seed: two orgs, stores, users, one employee per org with a weekend late ──
alpha = c.post("/api/orgs", headers=KEY, json={"name": "Alpha Pizza"}).get_json()["id"]
beta = c.post("/api/orgs", headers=KEY, json={"name": "Beta Pizza"}).get_json()["id"]
for store, org in [("1001", alpha), ("1002", alpha), ("2001", beta)]:
    r = c.patch(f"/api/stores/{store}", headers=KEY, json={"org_id": org, "name": f"Store {store}"})
    assert r.status_code in (200, 201), r.get_data()

c.post("/api/users", headers=KEY, json={"username": "padmin", "password": "x", "role": "platform_admin"})
c.post("/api/users", headers=KEY, json={"username": "alpha-own", "password": "x", "role": "owner", "org_id": alpha})
c.post("/api/users", headers=KEY, json={"username": "alpha-dm", "password": "x", "role": "dm", "org_id": alpha})
c.post("/api/employees", headers=KEY, json={"employee_id": "A1", "name": "Al", "store": "1001"})
c.post("/api/employees", headers=KEY, json={"employee_id": "B1", "name": "Bea", "store": "2001"})

# Most recent Friday (weekend rule day) safely inside the 90-day stats window.
d = datetime.utcnow() - timedelta(days=2)
while d.weekday() != 4:
    d -= timedelta(days=1)
friday = d.strftime("%Y-%m-%d")
for emp in ("A1", "B1"):
    r = c.post("/api/logs", headers=KEY, json={
        "employee_id": emp, "date": friday, "status": "late", "minutes_late": 30,
    })
    assert r.status_code == 201, r.get_data()

def login(u):
    r = c.post("/api/dashboard/login", json={"username": u, "password": "x"})
    assert r.status_code == 200, r.get_data()
    return {"X-Dashboard-Token": r.get_json()["token"]}

pa = login("padmin")
pa_alpha = dict(pa, **{"X-Org-View": str(alpha)})
own_a = login("alpha-own")
dm_a = login("alpha-dm")

def stats_for(emp):
    rows = c.get(f"/api/stats?employee_id={emp}", headers=KEY).get_json()
    return rows[0]

# ── 1. Defaults: 30-min Friday late = 1.0 base x2 weekend ──
r = c.get("/api/org/point-config", headers=own_a)
check("owner GET returns defaults", r.status_code == 200 and r.get_json()["config"] == main.DEFAULT_POINT_CONFIG)
check("default stats: weekend late = 2.0", stats_for("A1")["active_points"] == 2.0)

# ── 2. Owner updates their org; stats change; other org untouched ──
r = c.put("/api/org/point-config", headers=own_a, json={"late_points": 3, "weekend_multiplier": 1})
check("owner PUT accepted", r.status_code == 200 and r.get_json()["config"]["late_points"] == 3.0)
check("alpha stats use org rules (3 x1)", stats_for("A1")["active_points"] == 3.0)
check("beta stats still on defaults (1 x2)", stats_for("B1")["active_points"] == 2.0)

# ── 3. Access control ──
r = c.put("/api/org/point-config", headers=dm_a, json={"late_points": 0})
check("dm cannot edit point settings", r.status_code == 403)
r = c.get("/api/org/point-config", headers=dm_a)
check("dm cannot read point settings", r.status_code == 403)
r = c.put("/api/org/point-config", headers=pa_alpha, json={"called_in_points": 5})
check("platform admin edits via org view", r.status_code == 200 and r.get_json()["config"]["called_in_points"] == 5.0)
check("platform edit kept owner's earlier override", r.get_json()["config"]["late_points"] == 3.0 if r.status_code == 200 else False)
r = c.put("/api/org/point-config", headers=pa, json={"late_points": 1})
check("platform admin without org view gets 400", r.status_code == 400)

# ── 4. Validation ──
check("negative rejected", c.put("/api/org/point-config", headers=own_a, json={"late_points": -1}).status_code == 400)
check("weekend multiplier < 1 rejected", c.put("/api/org/point-config", headers=own_a, json={"weekend_multiplier": 0.5}).status_code == 400)
check("unknown key rejected", c.put("/api/org/point-config", headers=own_a, json={"bogus": 1}).status_code == 400)

# ── 5. NCNS: auto-termination by default, points when configured ──
c.post("/api/logs", headers=KEY, json={"employee_id": "A1", "date": friday, "status": "no_call_no_show"})
c.put("/api/org/point-config", headers=own_a, json={"late_points": 3, "weekend_multiplier": 1})
s = stats_for("A1")
check("NCNS default = automatic termination", s["has_ncns"] and s["disciplinary_stage"] == "Automatic Termination")
c.put("/api/org/point-config", headers=own_a, json={"late_points": 3, "weekend_multiplier": 1, "ncns_points": 4})
s = stats_for("A1")
check("NCNS-as-points: no auto-termination", not s["has_ncns"])
check("NCNS-as-points: points added (3 + 4)", s["active_points"] == 7.0)

# ── 6. Scrape requests: only missing stores, only connected orgs ──
c.post("/api/org/pulse-credentials", headers=pa_alpha, json={"username": "pwr-a", "password": "pw"})
r = c.post("/api/admin/scrape-requests", headers=pa_alpha, json={})
check("pending credential = nothing to pull", r.get_json()["created"] == [])
c.post("/api/worker/credential-status", headers=KEY, json={"org_id": alpha, "status": "connected"})
r = c.post("/api/admin/scrape-requests", headers=pa_alpha, json={})
body = r.get_json()
check("queues one request for alpha", r.status_code == 201 and len(body["created"]) == 1)
check("request covers both missing alpha stores", sorted(body["created"][0]["stores"]) == ["1001", "1002"])
rid = body["created"][0]["id"]
r = c.post("/api/admin/scrape-requests", headers=pa_alpha, json={})
check("no duplicate while request is open", r.get_json()["created"] == [] and r.get_json()["skipped"])

# ── 7. Worker consumes the queue ──
r = c.get("/api/worker/scrape-requests", headers=KEY)
reqs = r.get_json()
check("worker sees pending request with slug", len(reqs) == 1 and reqs[0]["org_slug"] == "alpha-pizza")
check("worker marks running", c.post(f"/api/worker/scrape-requests/{rid}", headers=KEY, json={"status": "running"}).status_code == 200)
check("running request hidden from worker queue", c.get("/api/worker/scrape-requests", headers=KEY).get_json() == [])
yesterday = (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%d")
c.post("/api/worker/scrape-runs", headers=KEY, json={"runs": [
    {"org_id": alpha, "store": "1001", "run_date": yesterday, "status": "success", "rows_imported": 5}]})
check("worker marks done", c.post(f"/api/worker/scrape-requests/{rid}", headers=KEY, json={"status": "done", "detail": "1/2"}).status_code == 200)
r = c.post("/api/admin/scrape-requests", headers=pa_alpha, json={})
body = r.get_json()
check("next pull only queues the still-missing store", len(body["created"]) == 1 and body["created"][0]["stores"] == ["1002"])

# ── 8. Access control on the queue endpoints ──
check("owner cannot queue pulls", c.post("/api/admin/scrape-requests", headers=own_a, json={}).status_code == 403)
check("owner cannot list pulls", c.get("/api/admin/scrape-requests", headers=own_a).status_code == 403)
check("dashboard token rejected on worker queue", c.get("/api/worker/scrape-requests", headers=pa).status_code == 403)
r = c.get("/api/admin/scrape-requests", headers=pa)
check("platform admin lists request history", r.status_code == 200 and len(r.get_json()) >= 2)

# ── 9. Day stats: scheduled headcount flows import -> /api/day-stats ──
r = c.post("/api/import", headers=dict(KEY, **{"X-Org-Slug": "alpha-pizza"}), json={
    "records": [{"employee_id": "A2", "name": "Ann", "store": "1001",
                 "logs": [{"date": yesterday, "status": "late", "minutes_late": 10}]}],
    "day_stats": [{"store": "1001", "date": yesterday, "scheduled_count": 14},
                  {"store": "1002", "date": yesterday, "scheduled_count": 9}],
})
check("import accepts day_stats", r.status_code == 201)
r = c.get(f"/api/day-stats?date={yesterday}", headers=own_a)
counts = {s["store"]: s["scheduled_count"] for s in r.get_json()["stores"]}
check("day-stats returns scheduled counts", counts.get("1001") == 14 and counts.get("1002") == 9)
check("violation-free store still got a batch row", "1002" in counts)
r = c.post("/api/import", headers=dict(KEY, **{"X-Org-Slug": "alpha-pizza"}), json={
    "records": [], "day_stats": [{"store": "1001", "date": yesterday, "scheduled_count": 15}]})
r = c.get(f"/api/day-stats?date={yesterday}", headers=own_a)
counts = {s["store"]: s["scheduled_count"] for s in r.get_json()["stores"]}
check("re-import refreshes the count", counts.get("1001") == 15)
c.post("/api/users", headers=KEY, json={"username": "beta-own", "password": "x", "role": "owner", "org_id": beta})
own_b = login("beta-own")
r = c.get(f"/api/day-stats?date={yesterday}", headers=own_b)
check("day-stats is store-scoped (beta sees no alpha stores)",
      {s["store"] for s in r.get_json()["stores"]}.isdisjoint({"1001", "1002"}))

# ── Store deletion ───────────────────────────────────────────────────────────
r = c.patch("/api/stores/9999", headers=KEY, json={"org_id": alpha, "name": "Test Store"})
assert r.status_code in (200, 201), r.get_data()
c.post("/api/employees", headers=KEY, json={"employee_id": "T9", "name": "Tess T", "store": "9999"})
r = c.delete("/api/stores/9999", headers=own_a)
check("owner cannot delete a store", r.status_code == 403)
r = c.delete("/api/stores/9999", headers=KEY)
check("delete refused while employees remain", r.status_code == 409)
c.delete("/api/employees/T9", headers=KEY)
r = c.delete("/api/stores/9999", headers=KEY)
check("platform-level delete works once empty", r.status_code == 200)
r = c.get("/api/stores", headers=own_a)
check("deleted store is gone from the list", "9999" not in {s["store"] for s in r.get_json()})
r = c.delete("/api/stores/9999", headers=KEY)
check("deleting a missing store 404s", r.status_code == 404)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
