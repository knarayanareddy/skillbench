# B10 — Backup/restore drill (disposable database)

Date: 2026-11-05. `production_ready = false`.
Executable drill: `make drill` → `tests/db/test_backup_restore.py` (passes in the
268-test suite; see `B08-test-run.log`).

## Why this is a drill and not a table copy

The guarantees that matter live in the dump, not in the row values: ownership of the
`SECURITY DEFINER` helpers, the grants that keep the lifecycle role out of evidence
tables, the `FORCE` RLS policies, the append-only triggers and sequence state. A test
that copies rows would prove none of them.

## Procedure (exactly what the test does)

1. Drive a real product slice on a freshly migrated cluster as `app_login`:
   upload → finalize → package → inspect → approve → suite → preregister → experiment →
   worker runs 72 recorded trials → analysis (`paired-task-bootstrap/1`, `valid`).
2. `pg_dump --format=custom --file=skb.dump <owner DSN>`.
3. `tar -czf artifacts.tgz -C "$ARTIFACT_ROOT" .`.
4. `CREATE DATABASE skb_restore`, then
   `pg_restore --dbname=<restore DSN> --exit-on-error --single-transaction skb.dump`.
5. Extract the artifact archive into a separate root.
6. Verify, then point a real ASGI app at the restored database and archive.

## Assertions

| Check | Result |
| --- | --- |
| Dump TOC lists every state table as `TABLE DATA`, no `; ERROR`/`; WARNING` | required |
| Row counts identical for 25 tables (identity, content, jobs, outbox, deletions, audit, packages, suites, plans, experiments, trials, analyses) | required |
| `pg_sequences` state identical (`core`, `skb`) | required |
| Artifact files byte-identical (relative path → sha256 map equality) | required |
| Stored `core.artifacts.sha256` present among restored file digests | required |
| RLS: `app_login` with project scope sees all trials, without scope sees 0 | required |
| `has_table_privilege('baseline_lifecycle','skb.trials','SELECT')` = false after restore | required |
| `GET /health/ready` 200 and `/health/live` 200 against the restored copy | required |
| `UPDATE skb.analyses …` still rejected (immutability trigger survives) | required |

All asserted values are observed from the restored copy, not from source-side bookkeeping.

## Environmental notes

- `pg_amcheck` is **not** usable here: the bundled PostgreSQL 16.2 build omits the
  `amcheck` extension, so `pg_amcheck` degrades to `no relations to check`. Physical
  integrity is therefore covered by `pg_restore --exit-on-error --single-transaction`
  plus the TOC completeness and digest checks above. A real host with contrib can add
  `pg_amcheck` to the same drill.
- Both databases live in the same ephemeral cluster for the drill, which is intentional:
  it exercises a *disposable* target and never touches live data.
- `tar.extractall` is used on an archive created inside the test in the same run.

## Operator follow-up

The documented runbook in `docs/SKB_Operations.md` §5 stays the authority for real
backups (encrypted destination, key custody, retention). Before claiming qualification,
re-run `make drill` on the target host, then additionally verify a backup taken while no
worker attempt holds a lease, and a restore of that backup into a *different* cluster.
