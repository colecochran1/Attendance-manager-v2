---
name: Deploy a non-JS backend as a publishable Replit artifact
description: How to publish a Python/gunicorn (or other non-JS) backend when createArtifact only scaffolds JS apps and only "web" kind is publishable.
---

## The constraints (discovered, not in docs)

- `createArtifact` only supports JS-oriented kinds: automation, data-visualization, expo, mockup-sandbox, react-vite, slides, video-js. There is **no "api" kind** option.
- Artifact **`kind` is immutable**: `verifyAndReplaceArtifactToml` rejects changing `kind` (`cannot change artifact kind`).
- **Only deployable kinds appear in Publish.** `kind="api"` and `kind="design"` are NOT publishable; the Publish UI says "nothing to publish". `kind="web"` IS publishable.
- `verifyAndReplaceArtifactToml` also refuses to change `integratedSkills` — keep the scaffold's `[[integratedSkills]]` block in the replacement toml or it errors.

## The working recipe

To publish a Python/gunicorn backend:
1. `createArtifact({artifactType:"react-vite", ...})` — this registers `kind="web"` (the publishable label).
2. Strip the React scaffold (src, public, index.html, package.json, vite.config.ts, tsconfig.json, components.json, node_modules). A Python-only artifact dir with no package.json is fine — pnpm just ignores it.
3. Add `main.py` + `requirements.txt`; install python packages.
4. Rewrite `artifact.toml` (via temp `artifact.edit.toml` + verifyAndReplaceArtifactToml) so production is a **process, not static**: set `[services.production.run].args`, drop `serve="static"`, `publicDir`, `build`, and the static rewrites. Add `[services.production.health.startup].path`.

## Routing / PORT model (router="path" + application proxy)

- The shared proxy routes by `paths` to the service's fixed `localPort` in **both dev and production**. So bind the app to that localPort: set `[services.env].PORT` and `[services.production.run.env].PORT` to the assigned localPort, and bind `0.0.0.0:${PORT}`.

## CWD gotcha

- **Artifact-managed workflows run with CWD = the artifact dir**, NOT the repo root (a manually-defined `.replit` workflow runs from root). So `cd artifacts/<slug> && ...` fails in a managed workflow.
- Make run commands CWD-resilient: `cd artifacts/<slug> 2>/dev/null; exec gunicorn ... main:app` — works whether started from the artifact dir or repo root.

## gunicorn + startup DDL

- Use `--preload` when the app runs `init_db()` (CREATE TABLE) at import time: it loads once in the master before forking workers, avoiding a multi-worker race on table creation.

## Cleanup

- Deleting an artifact dir deregisters the artifact, but its **artifact-managed workflow lingers** and cannot be removed via `removeWorkflow` (`PROHIBITED_ACTION ... managed by an artifact`). A `not_started` orphan is harmless.
- After removing workspace packages, run `pnpm install` to drop stale importers from `pnpm-lock.yaml` (avoids frozen-lockfile issues at publish).
