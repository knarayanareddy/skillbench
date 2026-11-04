# B07 — SkillBench product slice (implementation note)

Status: implementation complete for the fixture-first slice; **production_ready = false**.
Date: 2026-11-04. Branch: `arena/e7d80e52-skillbench`. Base commit: `01a7075`.

## What was built

Real code, not stubs, in the existing checkout:

- `src/core/`: fail-closed configuration, canonical digests, safe Problems, capability
  model, OIDC authorization-code + PKCE with a loopback synthetic IdP for dev/test,
  session/API-key resolution, transaction-local RLS scoping.
- `src/services/`: scoped idempotency, private artifact storage, inert ZIP inspection,
  fixture registry, paired descriptive analysis, SkillBench domain service, audit trail.
- `src/api/`: projects/uploads/artifacts/jobs, packages/suites/plans/experiments/analyses,
  auth + loopback IdP, authorization dependencies.
- `src/worker/`: fenced lease claim/complete, `skb.inspect` and `skb.experiment` handlers,
  cooperative cancellation, `--check` startup validation.
- `apps/web/`: React + Vite + strict TypeScript UI (projects, package registration and
  inspection evidence, review decisions, suites, preregistered plans, experiment trials,
  descriptive analysis) with permanent simulation labelling.
- `database/migrations/`: schema, RLS policies, append-only triggers, artifact-identity
  freeze, plan freeze, single-analysis-per-input rule, `claim_job` with cancellation
  intent, least-privilege grants for the three runtime roles.
- Tests: real PostgreSQL 16 harness, real OIDC flow, API/DB/worker/unit suites.

## Commands run and results

| Command | Result |
| --- | --- |
| `.venv/bin/python -m pytest -q` | see `evidence/tickets/B07-test-run.log` |
| `cd apps/web && npx tsc --noEmit` | exit 0, no output |
| `cd apps/web && npm run build` | exit 0, `dist/` built (200.8 kB JS, 5.1 kB CSS) |
| `scripts/verify_manifest.py` | exit 0 (307 protected files) |
| `scripts/release_gate.py` | exit 1 (`production_ready=false`, 15 blocking gates) |
| `scripts/seed_dev.py` (twice) | exit 0 both times, idempotent (5 users, 1 project, 5 roles, 1 key) |

## Evidence of the end-to-end journey

`tests/api/test_skb_flow.py::test_full_fixture_journey_produces_descriptive_analysis`
drives the whole path against PostgreSQL 16 through HTTP only:
ZIP upload → artifact finalize (digest-bound) → package registration (quarantined) →
inspection job → worker → inspected → maintainer approval (revision + digest bound) →
suite → plan (draft) → preregistration → experiment → worker replays 72 recorded
synthetic trials → analysis `valid`, `delta 0.5`, `descriptive_no_certification`,
identical `input_sha256` on replay. Audit actions for every step are asserted present.

Adversarial coverage in the same suite: path traversal, absolute paths, duplicate paths,
symlinks, executables, non-ZIP bytes (scanner failure stays quarantined and is never a
clean scan), digest mismatch at finalize and at review, stale/absent `If-Match`
(`412`/`428`), concurrent approvals producing exactly one decision, post-approval digest
swap attempts, plan immutability and double preregistration, experiment digest mismatch,
missing recorded fixture → `infra_error` (never `pass`) with bounded partial analysis,
below-threshold task count → `insufficient`, cross-project 403/404, role matrix,
idempotent replay vs conflicting body (`409`), pending artifact rejection.

## Deliberate reviewed changes to existing expectations

- `tests/test_api.py`: `POST /projects` now returns `201` (was a `501` B00 stub) and
  identity comes from the real OIDC flow / scoped machine key instead of
  `Bearer test-token-*`. Negative guarantees (401/403/400/404) were preserved and
  extended to object routes. This file was rewritten as a reviewed change, not relaxed.
- `core.audit_events` policy now permits organization-level rows (project context NULL)
  so `POST /projects` can be audited.
- `core.sessions` gained `UPDATE` for the app role (idle-expiry touch).
- Local IdP authorization URL is relative in dev/test so the browser stays same-origin.

## Limitations

- Python 3.12 / Node 24 were unavailable; see `docs/SKB_Operations.md` §7.
- One read-only endpoint outside `contracts/openapi.yaml` (`/skb/packages/{id}/inspection`)
  is flagged for contract review.
- No public cancel endpoint; cancellation is tested at the queue level.
- Independent security, domain, statistical and clean-room reviews remain pending; the
  release gate therefore still exits 1 by design.

## Manifest update (explicit, scoped)

`scripts/verify_manifest.py` reported exactly two changed protected files after this
slice: `database/migrations/001_baseline.sql` and `database/migrations/002_roles.sql`.
Only those two entries in `contracts/baseline-manifest.json` were recomputed:

```
001_baseline.sql  49d6c15c9fe6… -> f2a13e827be2…
002_roles.sql     90385fc0a91d… -> 7d219680664d…
```

No blanket regeneration was performed. Role/runtime source files are new and therefore
outside the protected set; the manifest intentionally covers only the reviewed baseline.

## Live local stack walkthrough (not a substitute for tests)

`evidence/tickets/B07-live-stack-journey.log` records the same journey driven through the
**UI origin** (Vite dev server on :5173 proxying `/api` and `/local-idp` to uvicorn on
:8000), with the worker running as a separate process using `worker_login`:

```
upload 201 / put 200 / finalize 200 / package 201 / inspect 202
worker exit 0 → package inspected (2 entries)
review 200 / suite 201 / plan 201 / preregister 200 / experiment 202
worker exit 0 → experiment completed, 72 trials
analysis 201 {"status":"valid","delta":0.5,"ci_low":0.25,"ci_high":0.75,
              "interpretation":"descriptive_no_certification"}
```

Changes made while validating the live stack:

- the local synthetic IdP now shows a **subject chooser** instead of defaulting to one
  identity (no silent impersonation, still no passwords);
- `GET /skb/packages/{id}/inspection` returns the revision `ETag` so the review form can
  send `If-Match`;
- worker startup validates only its own surface (`require_identity=False`); it performs no
  authentication, and it exits `0` with `{"status":"ok","processed":N}` instead of using
  the job count as an exit status.
