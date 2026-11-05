# B08 — Target runtime matrix (Python 3.12, Node 24)

Date: 2026-11-05. Branch `arena/e0b5142f-skillbench`, base `dbf91c8`.
`production_ready = false` throughout; this ticket records runtime coverage, not approval.

## Result

| Runtime | Target | Achieved here | Evidence |
| --- | --- | --- | --- |
| Node | 24 | **24.22.2** | UI typecheck + production build both green |
| Python | 3.12 | **not achievable** | every acquisition path refused; suite ran on 3.11.2 |
| PostgreSQL | 16 | 16.2 | full suite against a real cluster |

## Node 24

The Node 24 toolchain was obtained without root by unpacking the official npm
distribution of the runtime (`npm pack node-linux-x64@24.22.2`, then `tar xzf`):

```
package/bin/node -v   -> v24.22.2
```

With `node_modules` removed first, inside `apps/web/`:

```
npm ci --no-audit --no-fund     # added 73 packages in 2s
npm run build                   # tsc --noEmit && vite build
dist/index.html                   0.47 kB │ gzip:  0.30 kB
dist/assets/index-CIXD5xi-.css    5.12 kB │ gzip:  1.61 kB
dist/assets/index-CPs6jCH7.js   200.57 kB │ gzip: 62.69 kB
✓ built in 1.06s
```

The bundle is **byte-identical** to the Node 22.22.3 build recorded in B07
(`sha256 dist/assets/index-CPs6jCH7.js` =
`afe72f9a333a71ef82c04315a8dcd2cc9285ea77d01242a8f2668f0d7582a2ac`), so the earlier
UI evidence carries over to the target major rather than being replaced by it.

`package.json` declares `"engines": {"node": ">=24"}`; the build was run on 24.22.2,
not on a 22.x interpreter.

## Python 3.12: blocked, with the specific reasons

Attempted, in order, all within this sandbox:

1. `astral-sh/python-build-standalone` release asset
   `cpython-3.12.16+20261026-x86_64-unknown-linux-gnu-install_only.tar.gz`
   (`https://github.com/astral-sh/python-build-standalone/releases/download/20261026/…`):
   the API resolves the asset, but the download from
   `release-assets.githubusercontent.com` fails with `curl: (35) SSL_ERROR_SYSCALL`
   (that host is not reachable from here).
2. PyPI fallbacks — `python-standalone`, `python-build-standalone`,
   `standalone-python`, `cpython-bin` — all return 404; there is no standalone CPython
   wheel on PyPI.
3. Building CPython from source: `gcc` 12.2 and `make` exist but the development
   headers for `openssl`, `zlib`, `libffi` and `sqlite3` are absent from
   `/usr/include`, so a build would produce an interpreter without `ssl`, `sqlite3`,
   `ctypes` or `zlib` — not a usable verification target even if it linked.

Consequence: the suite is **not** verified on 3.12. `ci/github-workflow.yml` already
runs the matrix on 3.12 and 3.13, so the first CI run is the verification path for
that claim. Nothing in this ticket should be read as 3.12 coverage.

## Suite on 3.11.2

`evidence/tickets/B08-test-run.log`: **268 passed** in 39.56 s, no skips
(`SKB_TEST_PG_OPTIONAL` unused), PostgreSQL 16.2 started per session.

`pytest -q` covers the lifecycle runner, the backup/restore drill, image/SBOM policy,
the static server and the probe semantics added in this change set.
