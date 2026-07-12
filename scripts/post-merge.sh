#!/bin/bash
set -e
pnpm install --frozen-lockfile
pnpm --filter db push

# Migrate the workspace database to the pulled schema. Flask's init_db() runs
# on import, so this is a boot-without-serve. Without it the workspace DB lags
# the code, and Replit's deploy diff (dev DB vs prod DB) proposes DROPPING
# every table prod has that dev doesn't. Failure is non-fatal: fall back to
# running `python artifacts/flask-api/main.py` once by hand.
(cd artifacts/flask-api && timeout 90 python -c "import main" \
  && echo "workspace DB migrated (init_db)") \
  || echo "WARNING: workspace DB migration failed — run 'python artifacts/flask-api/main.py' once before deploying"
