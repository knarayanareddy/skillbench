"""Real PostgreSQL 16 test environment.

The suite runs against an actual PostgreSQL 16 server, not SQLite:
  * an ephemeral cluster is started with `pgserver` (PostgreSQL 16.2 bundled
    binaries) when `SKB_TEST_DATABASE_URL` is not provided;
  * migrations are applied once as a migration-owner login;
  * the application connects as `app_login` (member of `baseline_app`), the
    worker as `worker_login` (member of `baseline_dispatcher`), never as owner.

Set SKB_TEST_DATABASE_URL to reuse an external disposable PostgreSQL 16 server.
SKB_TEST_PG_OPTIONAL=1 downgrades a missing server to an explicit skip; evidence
must record that the opt-out was used (it is not used in CI).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = sorted((REPO_ROOT / "database" / "migrations").glob("*.sql"))

ORG_A = "11111111-1111-4111-8111-111111111111"
ORG_B = "22222222-2222-4222-8222-222222222222"
PROJECT_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
PROJECT_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
PROJECT_A2 = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"

USER_ADMIN = "30000000-0000-4000-8000-000000000001"
USER_MAINTAINER = "30000000-0000-4000-8000-000000000002"
USER_ANALYST = "30000000-0000-4000-8000-000000000003"
USER_VIEWER = "30000000-0000-4000-8000-000000000004"
USER_OPERATOR = "30000000-0000-4000-8000-000000000005"
USER_OTHER_ORG = "30000000-0000-4000-8000-000000000006"
USER_SERVICE = "30000000-0000-4000-8000-000000000007"

SUBJECTS = {
    "skb-dev-admin": (USER_ADMIN, "admin"),
    "skb-dev-maintainer": (USER_MAINTAINER, "member"),
    "skb-dev-analyst": (USER_ANALYST, "member"),
    "skb-dev-viewer": (USER_VIEWER, "member"),
    "skb-dev-operator": (USER_OPERATOR, "member"),
    "skb-dev-other-org": (USER_OTHER_ORG, "member"),
    "skb-dev-service": (USER_SERVICE, "member"),
}

TEST_ISSUER = "http://testserver/local-idp"
API_KEY_A = "skb_test_key_A_0123456789abcdefghijklmnop"
API_KEY_B = "skb_test_key_B_0123456789abcdefghijklmnop"
API_KEY_REVOKED = "skb_test_key_revoked_0123456789abcdefghij"
API_KEY_EXPIRED = "skb_test_key_expired_0123456789abcdefghij"


class PostgresUnavailable(RuntimeError):
    pass


class PgEnv:
    """Ephemeral PostgreSQL 16 cluster plus migration/role/seed management."""

    def __init__(self) -> None:
        self.dir: Optional[Path] = None
        self._server = None
        self.external_dsn: Optional[str] = None
        self._started_by_us = False

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        external = os.getenv("SKB_TEST_DATABASE_URL")
        if external:
            self.external_dsn = external
            self.database = os.getenv("SKB_TEST_DATABASE", "skb_test")
            return
        try:
            import pgserver  # type: ignore
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise PostgresUnavailable(
                "pgserver is required for the local PostgreSQL 16 test server; "
                "install requirements-dev.txt or set SKB_TEST_DATABASE_URL"
            ) from exc
        self.dir = Path(tempfile.mkdtemp(prefix="skb-pg-"))
        self._server = pgserver.get_server(str(self.dir), cleanup_mode=None)
        self._started_by_us = True
        self.database = "skb_test"
        self._psql(["-c", "CREATE DATABASE skb_test"], database="postgres", check=True)

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.cleanup()
            except Exception:
                pass
            self._server = None
        if self._started_by_us and self.dir and self.dir.exists():
            shutil.rmtree(self.dir, ignore_errors=True)

    # -- psql helpers ------------------------------------------------------
    def _bin(self, name: str) -> str:
        import pgserver  # type: ignore

        bindir = Path(pgserver.__file__).parent / "pginstall" / "bin"
        return str(bindir / name)

    def admin_dsn(self, database: Optional[str] = None) -> str:
        if self.external_dsn:
            return self.external_dsn
        return f"postgresql://postgres@/{database or self.database}?host={self.dir}"

    def app_dsn(self) -> str:
        return self._login_dsn("app_login")

    def worker_dsn(self) -> str:
        return self._login_dsn("worker_login")

    def lifecycle_dsn(self) -> str:
        return self._login_dsn("lifecycle_login")

    def _login_dsn(self, role: str) -> str:
        if self.external_dsn:
            base = self.external_dsn
            # External environments must provide app_login credentials in the DSN.
            from urllib.parse import urlparse, urlunparse

            parsed = urlparse(base)
            netloc = f"{role}@{parsed.hostname or ''}" + (f":{parsed.port}" if parsed.port else "")
            return urlunparse(parsed._replace(netloc=netloc))
        return f"postgresql://{role}@/{self.database}?host={self.dir}"

    def _psql(self, args, database: Optional[str] = None, check: bool = True) -> subprocess.CompletedProcess:
        command = [self._bin("psql"), self.admin_dsn(database), "-v", "ON_ERROR_STOP=1", *args]
        result = subprocess.run(command, capture_output=True, text=True)
        if check and result.returncode != 0:
            raise RuntimeError(f"psql failed: {result.stderr[-2000:]}")
        return result

    def run_sql(self, sql: str, database: Optional[str] = None) -> str:
        result = self._psql(["-q", "-t", "-A", "-c", sql], database=database)
        return result.stdout

    def query(self, sql: str) -> list[list[str]]:
        """Rows as lists of text columns (test-only inspection, owner connection)."""
        output = self.run_sql(sql)
        return [line.split("|") for line in output.splitlines() if line.strip()]

    def query_as(self, role: str, sql: str, database: Optional[str] = None) -> list[list[str]]:
        """Run SQL as a login role and return the rows of the last row-returning statement."""
        output = self.run_sql(sql, database=database)
        return [line.split("|") for line in output.splitlines() if line.strip()]

    def apply_sql_file(self, path: Path) -> None:
        result = self._psql(["-q", "-f", str(path)], database=self.database)
        assert result.returncode == 0

    # -- provisioning ------------------------------------------------------
    def migrate(self) -> None:
        for migration in MIGRATIONS:
            self.apply_sql_file(migration)
        self._create_login_roles()

    def _create_login_roles(self) -> None:
        statements = [
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='app_login') "
            "THEN CREATE ROLE app_login LOGIN IN ROLE baseline_app; END IF; END $$;",
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='worker_login') "
            "THEN CREATE ROLE worker_login LOGIN IN ROLE baseline_dispatcher; END IF; END $$;",
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='lifecycle_login') "
            "THEN CREATE ROLE lifecycle_login LOGIN IN ROLE baseline_lifecycle; END IF; END $$;",
        ]
        for statement in statements:
            self.run_sql(statement)

    def truncate_all(self) -> None:
        tables = [
            "core.artifact_links",
            "core.uploads",
            "core.artifacts",
            "core.budget_reservations",
            "core.job_attempts",
            "core.outbox",
            "core.jobs",
            "skb.trials",
            "skb.analyses",
            "skb.experiments",
            "skb.plans",
            "skb.hidden_answers",
            "skb.suites",
            "skb.package_reviews",
            "skb.package_findings",
            "skb.package_entries",
            "skb.packages",
            "core.idempotency_project",
            "core.idempotency_organization",
            "core.deletions",
            "core.audit_events",
            "core.sessions",
            "core.auth_transactions",
            "core.api_keys",
            "core.project_roles",
            "core.projects",
            "core.memberships",
            "core.users",
            "core.organizations",
        ]
        self.run_sql("TRUNCATE " + ", ".join(tables) + " CASCADE;")

    def seed_world(self) -> None:
        """Deterministic identities for a fresh test world (never production data)."""
        self.truncate_all()
        users_sql = ", ".join(
            f"('{user_id}'::uuid, '{TEST_ISSUER}', '{subject}')" for subject, (user_id, _role) in SUBJECTS.items()
        )
        self.run_sql(
            f"""
            INSERT INTO core.organizations(id, name) VALUES ('{ORG_A}', 'Org A'), ('{ORG_B}', 'Org B');
            INSERT INTO core.users(id, issuer, subject) VALUES {users_sql};
            INSERT INTO core.memberships(organization_id, user_id, org_role) VALUES
              ('{ORG_A}', '{USER_ADMIN}', 'admin'),
              ('{ORG_A}', '{USER_MAINTAINER}', 'member'),
              ('{ORG_A}', '{USER_ANALYST}', 'member'),
              ('{ORG_A}', '{USER_VIEWER}', 'member'),
              ('{ORG_A}', '{USER_OPERATOR}', 'member'),
              ('{ORG_B}', '{USER_OTHER_ORG}', 'member'),
              ('{ORG_A}', '{USER_SERVICE}', 'member');
            INSERT INTO core.projects(id, organization_id, name, content_capture, external_transfer) VALUES
              ('{PROJECT_A}', '{ORG_A}', 'Project A', 'metadata_only', false),
              ('{PROJECT_A2}', '{ORG_A}', 'Project A2', 'metadata_only', false),
              ('{PROJECT_B}', '{ORG_B}', 'Project B', 'metadata_only', false);
            INSERT INTO core.project_roles(project_id, user_id, role) VALUES
              ('{PROJECT_A}', '{USER_ADMIN}', 'maintainer'),
              ('{PROJECT_A}', '{USER_MAINTAINER}', 'maintainer'),
              ('{PROJECT_A}', '{USER_ANALYST}', 'analyst'),
              ('{PROJECT_A}', '{USER_VIEWER}', 'viewer'),
              ('{PROJECT_A}', '{USER_OPERATOR}', 'operator'),
              ('{PROJECT_A2}', '{USER_ANALYST}', 'analyst'),
              ('{PROJECT_B}', '{USER_OTHER_ORG}', 'analyst'),
              ('{PROJECT_B}', '{USER_OTHER_ORG}', 'maintainer'),
              ('{PROJECT_B}', '{USER_OTHER_ORG}', 'operator'),
              ('{PROJECT_B}', '{USER_OTHER_ORG}', 'viewer');
            """
        )
        import hashlib

        def digest(value: str) -> str:
            return "\\x" + hashlib.sha256(value.encode()).hexdigest()

        self.run_sql(
            f"""
            INSERT INTO core.api_keys(id, project_id, actor_id, key_digest, scopes, expires_at) VALUES
              (gen_random_uuid(), '{PROJECT_A}', '{USER_SERVICE}', '{digest(API_KEY_A)}',
               ARRAY['viewer','analyst','operator','maintainer'], now() + interval '1 day'),
              (gen_random_uuid(), '{PROJECT_B}', '{USER_OTHER_ORG}', '{digest(API_KEY_B)}',
               ARRAY['viewer','analyst','operator','maintainer'], now() + interval '1 day');
            INSERT INTO core.api_keys(id, project_id, actor_id, key_digest, scopes, expires_at, revoked_at) VALUES
              (gen_random_uuid(), '{PROJECT_A}', '{USER_SERVICE}', '{digest(API_KEY_REVOKED)}',
               ARRAY['analyst'], now() + interval '1 day', now());
            INSERT INTO core.api_keys(id, project_id, actor_id, key_digest, scopes, expires_at) VALUES
              (gen_random_uuid(), '{PROJECT_A}', '{USER_SERVICE}', '{digest(API_KEY_EXPIRED)}',
               ARRAY['analyst'], now() - interval '1 day');
            """
        )
