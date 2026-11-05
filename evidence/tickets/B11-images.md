# B11 — Deployable images, probes and SBOM

Date: 2026-11-05. `production_ready = false`.

## What exists now

| Artifact | Purpose |
| --- | --- |
| `infra/Dockerfile.api` | one unprivileged image for API, worker and lifecycle (different commands, different DSNs) |
| `infra/Dockerfile.web` | multi-stage: Node 24 build of `apps/web`, then only `dist/` + `scripts/serve_static.py` |
| `requirements-runtime.txt` | runtime-only dependency set; strict subset of `requirements.txt`, no pytest/pglast/contract tooling |
| `scripts/build_images.py` | static policy check (`--check`) and digest-gated build commands (`--print-build`, `--execute`) |
| `scripts/build_sbom.py` | CycloneDX 1.5 SBOM from the installed environment + `package-lock.json` |
| `scripts/serve_static.py` | the web image's server: SPA fallback, immutable hashed assets, traversal refusal, `/health/live` |
| `evidence/sbom/skillbench-api.cdx.json` | 129 components: 9 python runtime, 120 npm (runtime + dev, marked by scope) |
| `evidence/sbom/skillbench-web.cdx.json` | 120 npm components for the UI build |
| `infra/compose.yaml` | readiness probe on the API, liveness on the web, `--check` on worker and lifecycle, `lifecycle` service added |
| `evidence/tickets/B11-image-policy.json` | `{"status":"ok","problems":[]}` |

## What could not be done here

There is **no container runtime** in this environment (`docker`, `podman`, `buildah`,
`nerdctl`, `skopeo` all absent, and no daemon to talk to). Therefore:

- the images were **not built and not run**; no image digest exists to quote;
- base-image digests were **not fabricated**. Both Dockerfiles take their base from a
  build arg, and `scripts/build_images.py` refuses to print a build command unless the
  reference contains `@sha256:`. The first real build must resolve those digests on the
  operator host and record them alongside the SBOM.

Claiming a built, scanned image would be a fabricated guarantee, so the ticket stops at
the policy boundary.

## Policy invariants enforced (and tested)

`scripts/build_images.py --check` (exit 1 on violation) plus `tests/test_images.py`:

1. Final stage runs as `USER 10001:10001` and declares a `HEALTHCHECK`.
2. No `ADD`; only allowlisted content enters the runtime layer.
3. No `pip install` of pytest/pglast; no `ENV …SECRET=`; digests only via `--build-arg`.
4. `requirements-runtime.txt ⊂ requirements.txt` and excludes the oracle set.
5. Compose: app services are `read_only`, `no-new-privileges:true`, `user 10001:10001`,
   no `:latest`; worker and lifecycle have their **own** DSN secrets and never
   `app_db_dsn`; the dispatcher no longer points at the obsolete `apps.dispatcher`.
6. SBOM advertises no oracle package and covers every runtime requirement.
7. The committed SBOM is checked against `apps/web/package-lock.json`, so a stale SBOM
   fails the suite instead of certifying components that are not shipped.

## Probes

- Liveness `/health/live` answers without touching the database — asserted with a DSN
  pointing at a non-existent cluster (`tests/api/test_probes.py`).
- Readiness `/health/ready` returns 503 in that state and 200 when the database answers,
  and its body never contains the DSN, host or database name.
- The web image answers `/health/live` from the static server; the API image's
  `HEALTHCHECK` is liveness, and the compose healthcheck overrides it to readiness.

These were verified in-process and over a real socket (static server), not inside a
container.

## SBOM determinism

`test_sbom_is_deterministic_and_complete` generates the BOM twice and compares bytes.
The CycloneDX serial number is a UUIDv5 over a hash of the content, and no timestamp is
embedded, so the SBOM is reproducible from a given environment and lockfile.

## Follow-ups for the operator host

1. Resolve and review base digests; build both images; run the policy check there.
2. Generate the SBOM *inside* each built image (`python scripts/build_sbom.py --runtime …`)
   so versions are the resolved image contents, and publish it with the image digest.
3. Scan the built images; the SBOM is the input to that scan, not a substitute for it.
4. Add `pg_amcheck` to the drill now that a contrib-enabled PostgreSQL is available.
