# B09 — Lifecycle process: expiry, purge, pruning

Date: 2026-11-05. Branch `arena/e0b5142f-skillbench`.
`production_ready = false`; this ticket covers the retention runner, not release approval.

## What was added

- `src/lifecycle/main.py` — one process, five per-project steps, `--once`, `--dry-run`,
  `--interval`, `--check`. Reports counts and error *types* only.
- `database/migrations/003_lifecycle.sql` — grants, `core.lifecycle_projects()`,
  `core.artifact_is_referenced(uuid, uuid)`, expiry/backlog indexes.
- `tests/db/test_lifecycle.py` — 9 tests; fixtures `lifecycle_settings`, `lifecycle` in
  `tests/conftest.py`.
- `infra/compose.yaml` — a `lifecycle` service on its own DSN secret.
- `Makefile` — `lifecycle`, `lifecycle-dry-run`, `lifecycle-check`.

## Grants: least privilege, derived from failures

The first run of the role failed closed on every project (`project_failed:ProgrammingError`).
`/tmp` debugging against a seeded cluster showed enumeration and plain scoped reads worked,
so the fault was statement-specific. Three real privilege gaps were found and fixed, each
with the narrowest grant that makes the statement legal:

| Statement | Failure | Grant added |
| --- | --- | --- |
| `UPDATE core.uploads SET state='expired'` | `permission denied for table uploads` | `UPDATE(state)` |
| Reference check over `skb.suites` / `skb.trials` | `permission denied for table suites` | **no grant** — moved behind `core.artifact_is_referenced()` |
| `DELETE … FROM core.idempotency_*` / `core.sessions` | `permission denied for table …` | `SELECT(project_id, expires_at)` / `SELECT(organization_id, expires_at)` / `SELECT(organization_id, absolute_expires_at, revoked_at)` |

The second row is the interesting one. The purger must know whether an artifact is still
referenced, but it must not be able to read trial traces or suite rights manifests. Rather
than granting `SELECT` on `skb.trials` (which would have made the role able to read every
recorded trace), the predicate became a single `SECURITY DEFINER` function returning a
boolean for one project-scoped artifact. The evidence tables stay revoked:

```
REVOKE ALL ON core.audit_events, skb.package_reviews, skb.trials, skb.analyses
  FROM baseline_lifecycle;
```

`test_evidence_surfaces_stay_unreachable` asserts this is still true, and the backup drill
re-asserts it in the restored database.

## Behaviour pinned by tests

| Test | Guarantee |
| --- | --- |
| `test_lifecycle_requires_its_own_role` | an API-role imposter run fails closed and reports the failure instead of raising |
| `test_expired_upload_is_expired_and_its_bytes_removed` | upload → `expired`, staged bytes gone, artifact `deleted`, tombstone `complete` |
| `test_referenced_artifact_is_kept` | package/trace/manifest references block purging |
| `test_requested_deletion_completes_and_is_idempotent` | a second run does not duplicate work or resurrect state |
| `test_operational_state_is_pruned` | sessions, auth transactions, idempotency records pruned by time |
| `test_outbox_delivery_is_opt_in` | nothing is marked delivered unless `LIFECYCLE_OUTBOX_DELIVER=1` |
| `test_dry_run_changes_nothing` | counts move, rows and bytes do not |
| `test_evidence_surfaces_stay_unreachable` | audit/reviews/trials/analyses rejected for the role |
| `test_cross_project_scoping` | a run for project A never touches project B |

## Enumeration failures are reported, not raised

`run_once` catches enumeration failure (wrong role, missing `EXECUTE`) and records
`projects_failed:<Type>`, so the CLI exits 1 rather than printing a clean empty run. That
is what makes the imposter test meaningful.

## Contract manifest

`contracts/baseline-manifest.json` pins the frozen baseline (`001_baseline.sql`,
`002_roles.sql`). `003_lifecycle.sql` is a new, separately reviewed migration and is
deliberately **not** added to that frozen list; `verify_manifest.py` reports 307 protected
files valid. No digest for 003 was invented.

## Not done here

- Outbox delivery is a state change only; there is no external consumer.
- Retention windows are read from artifact/upload `expires_at`, which the API sets; this
  process does not re-derive policy from `infra/runtime-policy.yaml` limits.
