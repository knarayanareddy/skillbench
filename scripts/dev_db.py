#!/usr/bin/env python3
"""Start a disposable local development database and seed the synthetic world.

Development convenience only. It creates an ephemeral PostgreSQL 16 cluster with
the bundled ``pgserver`` binaries, applies ``database/migrations``, creates the
runtime login roles (``app_login``, ``worker_login``, ``lifecycle_login``) and
seeds the synthetic identities from ``scripts/seed_dev.py``. Nothing here is used
in production: production uses an operator-managed PostgreSQL with the same
migrations and no seed data.

Local socket connections are trusted by the bundled server, so no passwords are
created. It prints the DSNs the API/worker need, then stays in the foreground.

    python scripts/dev_db.py
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = sorted((ROOT / "database" / "migrations").glob("*.sql"))
DATABASE = "skb_dev"

LOGIN_ROLES = [
    "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='app_login') "
    "THEN CREATE ROLE app_login LOGIN IN ROLE baseline_app; END IF; END $$;",
    "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='worker_login') "
    "THEN CREATE ROLE worker_login LOGIN IN ROLE baseline_dispatcher; END IF; END $$;",
    "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='lifecycle_login') "
    "THEN CREATE ROLE lifecycle_login LOGIN IN ROLE baseline_lifecycle; END IF; END $$;",
]


def psql_binary() -> Path:
    import pgserver  # type: ignore

    return Path(pgserver.__file__).parent / "pginstall" / "bin" / "psql"


def run_psql(dsn: str, args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(psql_binary()), dsn, "-v", "ON_ERROR_STOP=1", *args],
        capture_output=True,
        text=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=None, help="cluster directory (default: temp dir)")
    args = parser.parse_args()

    import pgserver

    cluster = Path(args.root) if args.root else Path(tempfile.mkdtemp(prefix="skbdev-"))
    cluster.mkdir(parents=True, exist_ok=True)
    print(f"starting PostgreSQL 16 in {cluster} …", flush=True)
    server = pgserver.get_server(cluster)

    admin = f"postgresql://postgres@/{DATABASE}?host={cluster}"
    created = run_psql(f"postgresql://postgres@/?host={cluster}", ["-c", f"CREATE DATABASE {DATABASE}"])
    if created.returncode != 0 and "already exists" not in created.stderr:
        print(created.stderr, file=sys.stderr)
        return 1

    for migration in MIGRATIONS:
        result = run_psql(admin, ["-q", "-f", str(migration)])
        if result.returncode != 0:
            print(f"migration failed: {migration}\n{result.stderr[-2000:]}", file=sys.stderr)
            return 1

    for statement in LOGIN_ROLES:
        result = run_psql(admin, ["-q", "-c", statement])
        if result.returncode != 0:
            print(f"role creation failed\n{result.stderr[-1000:]}", file=sys.stderr)
            return 1

    seeded = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "seed_dev.py")],
        env={**os.environ, "SKB_ENV": "development", "SKB_OWNER_DATABASE_URL": admin},
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    print(seeded.stdout.strip())
    if seeded.returncode != 0:
        print(seeded.stderr[-2000:], file=sys.stderr)
        return 1

    print("\nEnvironment for this session (local disposable only):")
    print("  export SKB_ENV=development")
    print(f'  export DATABASE_URL="postgresql://app_login@/{DATABASE}?host={cluster}"   # API process')
    print(f'  export DATABASE_URL="postgresql://worker_login@/{DATABASE}?host={cluster}" # worker process')
    print(f'  export ARTIFACT_ROOT="{cluster}/artifacts"')
    print("  export SKB_LOCAL_IDP=1")
    print("  export OIDC_ISSUER=http://127.0.0.1:8000/local-idp")
    print("  (leave OIDC_REDIRECT_URI unset: the callback stays same-origin)\n", flush=True)

    try:
        print("press Ctrl-C to stop and remove the cluster", flush=True)
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            server.cleanup()
        except Exception:  # noqa: BLE001 - best-effort shutdown
            shutil.rmtree(cluster, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
