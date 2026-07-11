# Attendance API — Guide for Leo (DM Agent)

Base URL (production): `https://flask-deployer-colecochran1.replit.app`

Leo has DM-level access, permanently scoped to stores **2501, 2545, 2556, 2557** only. Every list endpoint automatically filters to just these stores — you never need to pass a store filter to "scope" yourself, but you can use `?store=2556` etc. to narrow results.

## 1. Authenticate

```
POST /api/dashboard/login
Content-Type: application/json

{"username": "leo", "password": "<the password you were given>"}
```

Response:
```json
{"token": "...", "role": "dm", "username": "leo", "expires_in": 43200}
```

- `expires_in` is in seconds (12 hours). Cache the token and re-login when a request returns `401`.
- Send the token on every other call as a header: `X-Dashboard-Token: <token>`.
- Do not use the `X-API-Key` header — that's for the separate full-access programmatic key, not for this account.
- Login is rate-limited (too many failed attempts from the same IP triggers a temporary `429`).

## 2. Employees

- `GET /api/employees` — list employees in your stores. Optional query params: `store`, `position`.
- `POST /api/employees` — create/upsert an employee. Body: `{"employee_id": "...", "name": "...", "position": "...", "store": "..."}`.
- `PATCH /api/employees/<employee_id>` — update `name`, `position`, or `store`.
- `DELETE /api/employees/<employee_id>` — remove an employee.

## 3. Attendance logs

- `GET /api/logs` — filters: `employee_id`, `date_from`, `date_to`, `status`, `store`.
- `POST /api/logs` — record an attendance event. Body: `{"employee_id": "...", "status": "...", "date": "YYYY-MM-DD", "clock_in": "HH:MM", "scheduled_start": "HH:MM", "notes": "...", "manual_points": 0}`. `minutes_late` is auto-computed from `clock_in`/`scheduled_start` if omitted.
  - Common `status` values: `on_time`, `late`, `called_in`, `no_call_no_show` (a.k.a. `ncns` — triggers automatic termination status), `exempted`, `manual_addition` (use with `manual_points` to add/adjust points directly).
- `PATCH /api/logs/<id>` — correct a log (only for employees in your stores). Updatable fields: `date`, `clock_in`, `clock_out`, `hours`, `status`, `scheduled_start`, `minutes_late`, `notes`, `manual_points`.
- `DELETE /api/logs/<id>` — remove a log (only for employees in your stores).

## 4. Stats (points & disciplinary status)

- `GET /api/stats` — returns each employee's current point total, disciplinary stage, and the point log behind it. Filters: `employee_id`, `store`, `window_days` (default 90 — the rolling lookback window).
- Disciplinary stages: Good Standing (0–7 pts) → Hours May Be Reduced (7–9) → Written Warning (9–10) → Final Written Warning (10–13) → Termination (13+). An NCNS log always forces "Automatic Termination" regardless of points.
- Weekend infractions (Fri/Sat/Sun) count double.

## 5. Point redemptions

Employees can "redeem" points off their total for coming in on a day off, etc.

- `POST /api/redemptions` — request one for an employee in your stores. Body: `{"employee_id": "...", "redemption_type": "came_in_day_off" | "came_in_weekend_day_off" | "came_in_early", "date": "YYYY-MM-DD", "notes": "..."}`. Point values: day off = 2, weekend day off = 3, came in early = 1. Creates it as `pending`.
- `GET /api/redemptions` — list redemptions for your stores. Filter: `status`.
- `PATCH /api/redemptions/<id>` — approve or deny a pending redemption for an employee in your stores. Body: `{"action": "approve" | "deny"}`. Returns `409` if it's not still `pending`, `403` if the employee is outside your stores.

## 6. Shift swaps

- `POST /api/swap` — log a swap. Body: `{"requester_id": "...", "recipient_id": "...", "shift_date": "YYYY-MM-DD", "original_shift": "...", "swapped_shift": "...", "notes": "..."}`. `status` defaults to `pending` (valid values: `pending`, `approved`, `rejected`, `completed`).
- `GET /api/swaps` — list swaps involving employees in your stores. Filters: `employee_id`, `status`.
- `PATCH /api/swap/<id>` — update `status`, `notes`, `original_shift`, `swapped_shift`, `shift_date`. Leo can approve/reject swaps for his own stores.

## 7. Stores

- `GET /api/stores` — lists your 4 assigned stores (`store`, `name`). DM accounts don't see the `dm_user_id`/`dm_username` fields — that's owner-only info.
- Everything else under `/api/stores/*` (assigning a DM, resetting points) and `/api/users/*`, `/api/point-resets` is **owner-only** — Leo will get a `403` if he calls these.

## Error handling

- `401` — missing/invalid/expired token → re-login.
- `403` — action not permitted for this role, or the target employee/log/store is outside Leo's 4 stores.
- `404` — record not found.
- `429` — too many failed logins from this IP; wait a few minutes.
- `400`/`409` — validation errors or conflicts (e.g. duplicate username, invalid status value) — the JSON body's `error` field explains why.

## Notes on scope

Leo's 4-store access is hardcoded into the server (independent of the normal per-store DM assignment), so it won't be accidentally revoked by reassigning stores to other DMs, and it doesn't take store access away from anyone else (e.g. ccochran keeps full access to the same 4 stores).
