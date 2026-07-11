---
name: Rate limiting under gunicorn workers
description: Why in-memory counters fail for throttling/auth state when running multiple gunicorn workers
---

# In-memory state is per-worker under gunicorn

A naive in-memory dict (e.g. `defaultdict(list)` keyed by IP) for login throttling
does NOT work when gunicorn runs `--workers N`. Each worker has its own copy of the
dict, and the proxy round-robins requests across workers, so a threshold of 10
effectively becomes ~10*N before it trips — and a test that sends 12 bad attempts
splits across workers and never reaches the limit on any single one.

**Why:** workers are separate processes; module-level globals are not shared.

**How to apply:** for any state that must be consistent across requests
(rate-limit counters, sessions, locks), use a shared store. In this repo the
Flask attendance API uses a Postgres `login_attempts` table (prune by time window,
count per IP, insert on failure, delete on success). Alternatives: a single worker,
or Redis. Verify multi-worker behavior with a burst test, not a single request.
