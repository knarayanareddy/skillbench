# Progress log — SkillBench (B07)

Updated: 2026-11-05. Branch `arena/e0b5142f-skillbench`, base `dbf91c8`.
`production_ready = false`. Release gate exits 1 by design (independent reviews pending).

## Where things stand

Working end to end on a real PostgreSQL 16 cluster: inert ZIP intake → digest-bound
finalize → quarantined package → worker inspection → maintainer approval (revision +
digest bound) → immutable suite → preregistered plan → fixture experiment → 72 recorded
synthetic trials → descriptive paired analysis (`descriptive_no_certification`).
Frontend `apps/web/` runs against the real API through a same-origin proxy.

## Verify quickly

```bash
.venv/bin/python -m pytest -q                      # 268 passed (Python 3.11 here)
cd apps/web && npm run typecheck && npm run build  # built on Node 24.22.2
.venv/bin/python scripts/verify_manifest.py        # valid, 307 protected files
.venv/bin/python scripts/build_images.py --check   # image/SBOM policy ok
.venv/bin/python scripts/release_gate.py           # exit 1, expected
```

The retention/expiry process is `python -m src.lifecycle.main --once` (dry run:
`--dry-run`; config check: `--check`; or `make lifecycle`). It runs as its own role
and is the only identity allowed to destroy content.

Live local stack: `python scripts/dev_db.py`, then the API and worker as documented in
`docs/SKB_Operations.md` §2, then `cd apps/web && npm run dev`.

## Next tasks (in order)

1. **Python 3.12** re-run — still blocked in this environment (three acquisition paths
   tried and refused; see `evidence/tickets/B08-runtime-matrix.md`). CI's 3.12/3.13
   matrix is the verification path. **Node 24 done**: the UI builds on 24.22.2 with a
   byte-identical bundle.
2. Get the `/skb/packages/{id}/inspection` read-only endpoint into the contract through
   `scripts/build_contracts.py --scope skb` (or an equivalent reviewed amendment).
3. Contract review for a public cancel endpoint; until then cancellation is queue-level.
4. ~~Lifecycle job runner~~ **done** (`src/lifecycle/`, `003_lifecycle.sql`); outbox
   *delivery* stays opt-in and has no external consumer.
5. ~~Deployable images + SBOM~~ **defined and policy-checked, not built**: no container
   runtime here (`evidence/tickets/B11-images.md`). Probes are wired in compose and
   tested. Base-image digests must be resolved and the first build run on the operator
   host; SBOMs for the current lockfiles are in `evidence/sbom/`.
6. ~~Backup/restore drill~~ **done**: `make drill` round-trips a real journey through
   `pg_dump`/`pg_restore` into a disposable database and verifies counts, digests,
   sequence state, RLS, immutability and `/health/ready`
   (`evidence/tickets/B10-backup-restore.md`).
7. Independent security, domain, statistical and clean-room reviews (cannot self-approve).

## Recorded contradictions (do not silently "fix")

- `scripts/product_journeys.py` sends SKB request shapes that differ from
  `contracts/schemas`.
- `database/migrations/001_baseline.sql` cites `docs/Baseline_Revision_r2.md` and
  `evidence/tickets/B02-database.md`, neither of which exists in this checkout.
- `reference/` remains provenance only; runtime code never imports it.
- Container images exist as reviewed Dockerfiles and a policy check but have never been
  built or run here; do not quote an image digest.
- `contracts/baseline-manifest.json` pins the frozen baseline only. New migrations
  (`003_lifecycle.sql`) are reviewed but not added to it; `infra/compose.yaml` is
  protected, so its digest was re-pinned in this change set with the review recorded in
  `B11-images.md`.

## Conventions to keep

- Never execute uploaded skill code; never call a paid model. `fixtures/paired_trials.json`
  is orchestration evidence only, never evidence of skill benefit.
- No default credentials, no seeds outside `SKB_ENV=development`, no secrets in logs or
  commits, safe Problems with request IDs.
- Never change an oracle or a test expectation to obtain green; test counts are not targets.
