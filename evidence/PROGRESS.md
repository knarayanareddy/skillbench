# Progress log — SkillBench (B07)

Updated: 2026-11-04. Branch `arena/e7d80e52-skillbench`, base `01a7075`.
`production_ready = false`. Release gate exits 1 by design (independent reviews pending).

## Where things stand

Working end to end on a real PostgreSQL 16 cluster: inert ZIP intake → digest-bound
finalize → quarantined package → worker inspection → maintainer approval (revision +
digest bound) → immutable suite → preregistered plan → fixture experiment → 72 recorded
synthetic trials → descriptive paired analysis (`descriptive_no_certification`).
Frontend `apps/web/` runs against the real API through a same-origin proxy.

## Verify quickly

```bash
.venv/bin/python -m pytest -q                      # 239 passed (Python 3.11 here)
cd apps/web && npm run typecheck && npm run build
.venv/bin/python scripts/release_gate.py           # exit 1, expected
```

Live local stack: `python scripts/dev_db.py`, then the API and worker as documented in
`docs/SKB_Operations.md` §2, then `cd apps/web && npm run dev`.

## Next tasks (in order)

1. Re-run the suite on **Python 3.12** and build the UI on **Node 24**; record in
   `evidence/tickets/`. Do not claim 3.12/24 coverage until that exists.
2. Get the `/skb/packages/{id}/inspection` read-only endpoint into the contract through
   `scripts/build_contracts.py --scope skb` (or an equivalent reviewed amendment).
3. Contract review for a public cancel endpoint; until then cancellation is queue-level.
4. Lifecycle job runner (artifact retention/deletion) and outbox consumer — `core.deletions`
   and `core.outbox` exist but have no runner.
5. Deployable images: API image, worker image, static UI image + SBOM; wire the platform
   probes to `/health/live` and `/health/ready`.
6. Backup/restore drill against a disposable database; record evidence.
7. Independent security, domain, statistical and clean-room reviews (cannot self-approve).

## Recorded contradictions (do not silently "fix")

- `scripts/product_journeys.py` sends SKB request shapes that differ from
  `contracts/schemas`.
- `database/migrations/001_baseline.sql` cites `docs/Baseline_Revision_r2.md` and
  `evidence/tickets/B02-database.md`, neither of which exists in this checkout.
- `reference/` remains provenance only; runtime code never imports it.

## Conventions to keep

- Never execute uploaded skill code; never call a paid model. `fixtures/paired_trials.json`
  is orchestration evidence only, never evidence of skill benefit.
- No default credentials, no seeds outside `SKB_ENV=development`, no secrets in logs or
  commits, safe Problems with request IDs.
- Never change an oracle or a test expectation to obtain green; test counts are not targets.
