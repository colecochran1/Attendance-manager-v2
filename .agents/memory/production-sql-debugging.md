---
name: Production read-only SQL debugging quirks
description: Gotchas when using the production-environment SQL query tool to sanity-check logic against live data
---

- Comparing a `date`-typed column to a `text` column (or vice versa) in a query run against the production read-only replica fails, but the failure is **silent**: the tool's output is just `START TRANSACTION\nROLLBACK` with no visible error/row data. If a query against production returns only that with no rows, suspect a type mismatch (e.g. comparing `text` dates to a `::date` cast) before assuming the query logic itself is wrong.
- **Why:** wasted a debugging cycle assuming a correct JOIN query had matched zero rows, when actually the whole query errored and got rolled back with no surfaced error message.
- **How to apply:** when a production SQL query via the SQL tool returns no data unexpectedly, first re-run a trivial `SELECT` to confirm the tool works, then check `information_schema.columns` for actual column types on both sides of any comparison/join — don't assume types match code assumptions. For text-stored dates, use `to_char(ts_col, 'YYYY-MM-DD')` rather than `::date` casts when joining against text date columns.
