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
    db = main.get_db()
    db.commit()

c = main.app.test_client()
KEY = {"X-API-Key": "test-api-key"}
passed = failed = 0

def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"  ok: {name}")
    else: failed += 1; print(f"FAIL: {name}")

# ── Seed: two orgs, stores, users, employees ──
r = c.post("/api/orgs", headers=KEY, json={"name": "Alpha Pizza"})
alpha = r.get_json()["id"] if r.status_code == 201 else [o["id"] for o in c.get("/api/orgs", headers=KEY).get_json() if o["name"] == "Alpha Pizza"][0]
r = c.post("/api/orgs", headers=KEY, json={"name": "Beta Pizza"})
beta = r.get_json()["id"]
orgs_list = c.get("/api/orgs", headers=KEY).get_json()
# default org from migration may exist too; that's fine.

for store, org in [("1001", alpha), ("1002", alpha), ("2001", beta)]:
    r = c.patch(f"/api/stores/{store}", headers=KEY, json={"org_id": org, "name": f"Store {store}"})
    assert r.status_code in (200, 201), r.get_data()

c.post("/api/users", headers=KEY, json={"username": "padmin", "password": "x", "role": "platform_admin"})
c.post("/api/users", headers=KEY, json={"username": "alpha-own", "password": "x", "role": "owner", "org_id": alpha})
c.post("/api/users", headers=KEY, json={"username": "beta-own", "password": "x", "role": "owner", "org_id": beta})

c.post("/api/employees", headers=KEY, json={"employee_id": "A1", "name": "Al", "store": "1001"})
c.post("/api/employees", headers=KEY, json={"employee_id": "B1", "name": "Bea", "store": "2001"})

def login(u):
    r = c.post("/api/dashboard/login", json={"username": u, "password": "x"})
    assert r.status_code == 200, r.get_data()
    return {"X-Dashboard-Token": r.get_json()["token"]}

pa = login("padmin")
pa_alpha = dict(pa, **{"X-Org-View": str(alpha)})
pa_beta = dict(pa, **{"X-Org-View": str(beta)})
own_a = login("alpha-own")

# ── 1. No org view: platform admin sees everything ──
stores_all = {s["store"] for s in c.get("/api/stores", headers=pa).get_json()}
check("platform sees all stores unfiltered", {"1001", "1002", "2001"} <= stores_all)
users_all = {u["username"] for u in c.get("/api/users", headers=pa).get_json()}
check("platform sees all users unfiltered", {"padmin", "alpha-own", "beta-own"} <= users_all)

# ── 2. Org view filters stores/users/employees ──
stores_a = {s["store"] for s in c.get("/api/stores", headers=pa_alpha).get_json()}
check("org view: alpha stores only", stores_a == {"1001", "1002"})
stores_b = {s["store"] for s in c.get("/api/stores", headers=pa_beta).get_json()}
check("org view: beta stores only", stores_b == {"2001"})
users_a = {u["username"] for u in c.get("/api/users", headers=pa_alpha).get_json()}
check("org view: alpha users only (no padmin, no beta)", users_a == {"alpha-own"})
emps_a = {e["employee_id"] for e in c.get("/api/employees", headers=pa_alpha).get_json()}
check("org view: alpha employees only", emps_a == {"A1"})
emps_b = {e["employee_id"] for e in c.get("/api/employees", headers=pa_beta).get_json()}
check("org view: beta employees only", emps_b == {"B1"})

# ── 3. Header ignored for owner and API key callers ──
own_a_spoof = dict(own_a, **{"X-Org-View": str(beta)})
stores_own = {s["store"] for s in c.get("/api/stores", headers=own_a_spoof).get_json()}
check("owner cannot escape org via X-Org-View", stores_own == {"1001", "1002"})
key_spoof = dict(KEY, **{"X-Org-View": str(beta)})
stores_key = {s["store"] for s in c.get("/api/stores", headers=key_spoof).get_json()}
check("API key unaffected by X-Org-View", {"1001", "1002", "2001"} <= stores_key)

# ── 4. Pulse credentials default to the org view ──
r = c.post("/api/org/pulse-credentials", headers=pa_alpha, json={"username": "pwr-a", "password": "pw"})
check("pulse POST uses org view (no explicit org_id)", r.status_code == 201 and r.get_json()["org_id"] == alpha)
r = c.get("/api/org/pulse-credentials", headers=pa_alpha)
check("pulse GET scoped to org view", r.get_json().get("pwr_username") == "pwr-a")
r = c.get("/api/org/pulse-credentials", headers=pa)
check("pulse GET without org view still requires org_id", r.status_code == 400)

# ── 5. Bad header values are ignored, not fatal ──
pa_junk = dict(pa, **{"X-Org-View": "banana"})
r = c.get("/api/stores", headers=pa_junk)
check("junk X-Org-View ignored", r.status_code == 200 and {"1001", "2001"} <= {s["store"] for s in r.get_json()})

# ── 6. Freshness endpoint follows the org view ──
r = c.get("/api/freshness", headers=pa_beta)
fresh_stores = {s["store"] for s in r.get_json()["stores"]}
check("freshness scoped to org view", fresh_stores == {"2001"})

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
