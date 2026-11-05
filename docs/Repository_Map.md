# Repository Map

This checkout is one product (SkillBench / product code SKB, ticket B07) built on the
shared bounded baseline. It is deliberately a single backend service, not a monorepo.

| Concern | Path | Notes |
| --- | --- | --- |
| HTTP API | `src/api/` | FastAPI routers: `foundation.py` (projects, uploads, artifacts, jobs), `skb.py` (packages, suites, plans, experiments, analyses), `auth.py` (login, callback, session, logout, loopback IdP), `deps.py` (authentication and capability dependencies). |
| Runtime core | `src/core/` | `config.py` (fail-closed startup), `db.py` (pool + transaction-local RLS scope), `security.py` (capabilities, token verifier), `oidc.py` (authorization-code + PKCE, JWKS), `auth.py` (session/API-key resolution), `errors.py` (safe Problems), `canonical.py` (canonical JSON, digests). |
| Domain services | `src/services/` | `foundation.py`, `skb.py`, `idempotency.py` (scoped replay), `storage.py` (private artifact volume), `zipscan.py` (inert ZIP inspection), `analysis.py` (paired descriptive analysis), `fixture_registry.py` (recorded synthetic trials), `common.py` (shared shaping/audit). |
| Worker | `src/worker/` | `main.py` (fenced lease claim/complete, `--check`), `handlers.py` (`skb.inspect`, `skb.experiment`). Runs as its own process with the dispatcher role. |
| Lifecycle process | `src/lifecycle/` | `main.py`: expiry, purge, deletion completion, operational-state pruning and opt-in outbox marking. Runs as its own process with the lifecycle role; the only identity allowed to destroy content. |
| Schema mirror | `src/models/` | SQLAlchemy Core metadata drift-tested against `database/migrations`. |
| Migrations | `database/migrations/` | `001_baseline.sql` (schema, RLS, triggers, functions), `002_roles.sql` (roles, grants, policies), `003_lifecycle.sql` (lifecycle grants, enumeration helper, reference predicate). Applied in filename order inside a transaction. |
| Contracts | `contracts/` | Working authority for API/UI shapes (`openapi.yaml`, `schemas/`, `endpoint-policy.json`, `ui-workflows.yaml`). |
| Frontend | `apps/web/` | React 18 + Vite + strict TypeScript single-page app. Same-origin `/api` calls, HttpOnly session cookie, in-memory CSRF token. |
| Fixtures | `fixtures/paired_trials.json` | Synthetic recorded trials used only for deterministic orchestration/analysis checks. Never evidence of skill benefit. |
| Scripts | `scripts/` | `verify_manifest.py`, `release_gate.py`, `dev_db.py`, `seed_dev.py`, `build_contracts.py`, `product_journeys.py`, `build_images.py` (image policy check), `build_sbom.py` (CycloneDX from installed environment + npm lock), `serve_static.py` (the UI image's static server), others. |
| Evidence | `evidence/` | Validation logs, release status, `evidence/sbom/` CycloneDX SBOMs, and `evidence/tickets/` per-slice notes. |
| Archived references | `reference/` | Read-only provenance from the shared baseline. Never edited to make root verification pass, never imported by runtime code. |

## Naming mapping from earlier plans

Earlier planning documents referred to `apps/api/*` and `apps/dispatcher/*`. Those
concerns live in this checkout at:

| Planned path | Actual path | Reason |
| --- | --- | --- |
| `apps/api/*` | `src/api/`, `src/core/`, `src/services/` | The existing FastAPI application is kept in place; a second backend was explicitly out of scope. |
| `apps/dispatcher/*` | `src/worker/` | The fixture worker is a separate process (`python -m src.worker.main`) with its own database role. |
| `apps/web/*` | `apps/web/` | New frontend directory, as planned. |

## Process topology

1. Reverse proxy terminates TLS and serves `apps/web/dist` plus `/api`, `/local-idp`
   (development only), `/health`, `/docs`.
2. API process: `uvicorn src.main:app`, database role `app_login` (member of
   `baseline_app`). Never the owner, never the worker role.
3. Worker process: `python -m src.worker.main`, database role `worker_login` (member of
   `baseline_dispatcher`). Claims jobs with `core.claim_job` under a fenced lease.
4. Lifecycle process: `python -m src.lifecycle.main`, database role `lifecycle_login`
   (member of `baseline_lifecycle`). Expires, purges and prunes; cannot read trials,
   analyses or audit rows.
5. PostgreSQL 16: single database, `core` and `skb` schemas, row-level security on
   content tables, append-only evidence tables.
