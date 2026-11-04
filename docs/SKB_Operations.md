# SkillBench Operations (B07)

Private, fixture-first skill evaluation. **Nothing uploaded is executed; no model is
called.** Outcomes come from `fixtures/paired_trials.json` (synthetic recorded trials).
Analysis is descriptive and makes no efficacy, equivalence or safety claim.

`production_ready` remains **false**: independent security, domain, statistical and
clean-room reviews have not been completed.

## 1. Target runtimes

| Component | Target | Verified here |
| --- | --- | --- |
| Python | 3.12 | **3.11.2** in this sandbox (no 3.12 interpreter available; see limitations) |
| Node | 24 | **22.22.3** in this sandbox (`apps/web/package.json` declares `node >= 24`) |
| PostgreSQL | 16 | 16.2 (bundled `pgserver` binaries) |

Tests were run on Python 3.11 only. Do not describe this as 3.12 verification.

## 2. Local development (disposable)

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
python scripts/dev_db.py          # ephemeral PostgreSQL 16 + migrations + roles + seed
```

`dev_db.py` prints the environment for the two processes. In separate terminals:

```bash
# API (app_login role)
SKB_ENV=development \
DATABASE_URL="postgresql://app_login@/skb_dev?host=<cluster>" \
ARTIFACT_ROOT="<cluster>/artifacts" SKB_LOCAL_IDP=1 \
OIDC_ISSUER=http://127.0.0.1:8000/local-idp \
OIDC_CLIENT_ID=skb-local-dev OIDC_CLIENT_SECRET=<local-only> \
.venv/bin/python -m uvicorn src.main:app --host 0.0.0.0 --port 8000

# Worker (worker_login role, never the API's role)
SKB_ENV=development DATABASE_URL="postgresql://worker_login@/skb_dev?host=<cluster>" \
ARTIFACT_ROOT="<cluster>/artifacts" \
.venv/bin/python -m src.worker.main

# UI (browser → same origin → Vite proxy → API)
cd apps/web && npm install && npm run dev
```

The loopback IdP is development/test only. It authenticates a fixed set of synthetic
subjects (`skb-dev-admin`, `-maintainer`, `-analyst`, `-viewer`, `-operator`) with no
passwords and no registration; startup refuses `SKB_LOCAL_IDP=1` in production.

## 3. Production-shaped deployment

1. PostgreSQL 16 database owned by a migration role; apply `database/migrations/*.sql`
   in filename order (`001_baseline.sql`, then `002_roles.sql`) inside one transaction.
2. Create login roles: `app_login IN ROLE baseline_app`,
   `worker_login IN ROLE baseline_dispatcher`, `lifecycle_login IN ROLE baseline_lifecycle`.
   No runtime role is a superuser or has `BYPASSRLS`.
3. Supply secrets by file: `DATABASE_DSN_FILE`, `OIDC_CLIENT_SECRET_FILE`. There are no
   working default credentials; startup fails closed on placeholder values.
4. Run the API (`uvicorn src.main:app`) and the worker (`python -m src.worker.main`)
   as separate processes with separate DSNs. The worker refuses to start without a
   valid configuration (`--check` exits 2 on problems).
5. Serve `apps/web/dist` as static assets from the same origin as `/api`, `/health`,
   `/docs`. Do not expose `/local-idp` in production (the router is not mounted unless
   `LOCAL_IDP` is enabled outside production).
6. Expose `/health/live` (liveness) and `/health/ready` (readiness: database reachable)
   to the platform probe only. Neither reveals configuration.

## 4. Migrations, seed and tests

```bash
.venv/bin/python scripts/verify_manifest.py     # manifest integrity
.venv/bin/python scripts/release_gate.py        # expected exit 1 until reviews exist
.venv/bin/python -m pytest -q                   # full suite against real PostgreSQL
cd apps/web && npm run typecheck && npm run build
```

The test suite starts an ephemeral PostgreSQL 16 cluster by default. If a server is
unavailable it **fails**; the explicit opt-out `SKB_TEST_PG_OPTIONAL=1` must be recorded
in evidence and is never used in CI. `SKB_TEST_DATABASE_URL` reuses a disposable server.

`scripts/seed_dev.py` is idempotent, refuses `SKB_ENV != development`, and refuses a
non-loopback database unless `SKB_SEED_CONFIRM_DISPOSABLE=1`.

## 5. Data, retention and backup/restore

- Private artifact volume (`ARTIFACT_ROOT`, absolute path required in production).
  Artifacts are never web-served by the filesystem; downloads stream through the API
  with `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff` and
  `Cache-Control: private, no-store`.
- Postgres holds all durable state. Evidence tables (`skb.package_reviews`,
  `skb.trials`, `skb.analyses`, `skb.package_findings`, `core.audit_events`) are
  append-only: triggers raise `immutable_record` on UPDATE/DELETE, and the runtime
  roles have no UPDATE/DELETE grants on them.
- Artifact identity is frozen by a trigger once an artifact is `ready`; a
  preregistered plan cannot be updated; a package decision is final.

Backup:

```bash
pg_dump --format=custom --file=skb.dump "$DATABASE_URL_ADMIN"
tar -C "$ARTIFACT_ROOT" -czf artifacts.tgz .
```

Restore (disposable verification, never in place over live data):

```bash
createdb skb_restore
pg_restore --dbname=skb_restore --clean --if-exists skb.dump
tar -C "$ARTIFACT_ROOT" -xzf artifacts.tgz
# verify: artifact digests match, package/plan/experiment counts match, /health/ready passes
```

Backups must be taken at a point where no worker attempt holds a lease; a restored
`leased`/`running` job is reclaimed by `core.claim_job` after its lease expires and its
prior attempt is recorded as `abandoned`. Record the restore drill in
`evidence/tickets/` before claiming backup/restore qualification.

## 6. Concurrency, locking and idempotency

- **Job claims**: `core.claim_job` uses `FOR UPDATE SKIP LOCKED`, bumps `attempt` and
  `fence`, and marks a lease-expired attempt `abandoned`. A completion must match the
  `fence` and an unexpired lease; a stale completion is logged and never reported as
  success. Unknown handler exceptions set `failed_unknown_effect`.
- **Idempotency**: project mutations are unique per `(project, actor, operation, key)`;
  project creation per `(organization, actor, operation, key)`. Same key + same
  normalized body replays the stored response (`X-Idempotency-Replayed: true`); same key
  + different body is `409`; records expire after 24 h and are then reusable. Identity
  and authorization are resolved before any replay.
- **Reviews and plans** are revision-fenced (`If-Match`): a stale revision is `412`, a
  final decision is `409`. Concurrent approvals with the same revision produce exactly
  one decision.
- **Cancellation** is a queue operation: setting the job to `cancel_requested` makes
  the worker stop between trials; unexecuted trials are absent and the experiment ends
  `stopped`. There is no public cancel endpoint in the contract yet (recorded limitation).

## 7. Known limitations and open items

- Python 3.12 and Node 24 were not available in this environment; tests ran on 3.11 and
  the frontend was built with Node 22. Re-run both on the target runtimes before release.
- `GET /skb/packages/{id}/inspection` is a read-only detail endpoint beyond
  `contracts/openapi.yaml` (the contract's `Package` shape omits findings). It adds no
  write capability. It is listed for a deliberate contract review.
- No public cancel endpoint; no lifecycle/retention job runner; no outbox consumer.
- `scripts/product_journeys.py` still sends SKB request shapes that differ from
  `contracts/schemas` (recorded contradiction, not silently "fixed").
- `database/migrations/001_baseline.sql` cites `docs/Baseline_Revision_r2.md` and
  `evidence/tickets/B02-database.md`, which do not exist in this checkout.
- Independent security, domain, statistical and clean-room reviews: **pending**.
