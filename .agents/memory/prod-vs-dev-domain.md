---
name: Prod URL vs REPLIT_DOMAINS
description: How to reach the real production deployment vs the dev workspace domain
---

`$REPLIT_DOMAINS` (env var) always resolves to the dev workspace's `.replit.dev` domain, even when you intend to test "production". It is NOT the deployed app's URL.

**Why:** In a pnpm-workspace/artifact setup, dev and production run against separate databases and separate served processes. Curling `$REPLIT_DOMAINS` to "test production" silently operates on dev — any accounts, records, or config changes created this way land in the dev DB, not prod, producing confusing bugs (e.g. a feature that "doesn't work in production" when it was never actually exercised there).

**How to apply:** Whenever a task requires hitting the real production app (verifying prod data, creating prod-only accounts, debugging a prod-only symptom), call `getDeploymentInfo()` and use `primaryUrl` — never assume or reuse `$REPLIT_DOMAINS`/`REPLIT_DEV_DOMAIN` for this. Confirm `isDeployed`/`hasSuccessfulBuild` first.
