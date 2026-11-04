"""Async database access with transaction-local RLS context.

Every project-scoped statement runs inside a transaction that sets
``baseline.project_id``/``baseline.organization_id`` with ``SET LOCAL``. Because
the setting is transaction-local, a pooled connection cannot leak context into
the next request (verified by tests/db/test_rls.py).
"""
from __future__ import annotations

import contextlib
import re
import uuid
from typing import Any, AsyncIterator, Optional
from urllib.parse import parse_qs, urlparse

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from src.core.config import Settings, settings as default_settings


def _to_async_dsn(dsn: str) -> tuple[str, dict[str, Any]]:
    """Normalize a PostgreSQL DSN for asyncpg, supporting unix-socket hosts."""
    dsn = dsn.strip()
    if dsn.startswith("postgresql+asyncpg://"):
        url = dsn
    elif dsn.startswith("postgresql://"):
        url = "postgresql+asyncpg://" + dsn[len("postgresql://") :]
    elif dsn.startswith("postgres://"):
        url = "postgresql+asyncpg://" + dsn[len("postgres://") :]
    else:
        raise ValueError("unsupported_database_dsn_scheme")

    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    connect_args: dict[str, Any] = {}
    socket_host = query.pop("host", [None])[0]
    if socket_host and socket_host.startswith("/"):
        connect_args["host"] = socket_host
    rebuilt_query = "&".join(f"{k}={v[0]}" for k, v in sorted(query.items()) if v)
    netloc = parsed.netloc
    if connect_args:
        # Drop the placeholder host so asyncpg uses the socket directory.
        userinfo, _, _host = netloc.rpartition("@")
        netloc = f"{userinfo}@" if userinfo else ""
    return (
        f"{parsed.scheme}://{netloc}{parsed.path}" + (f"?{rebuilt_query}" if rebuilt_query else ""),
        connect_args,
    )


class Database:
    """Owns the async engine and the transaction-scoped session factories."""

    def __init__(self, config: Optional[Settings] = None) -> None:
        self.settings = config or default_settings
        self._engine: Optional[AsyncEngine] = None
        self._sessionmaker: Optional[async_sessionmaker[AsyncSession]] = None

    @property
    def engine(self) -> AsyncEngine:
        if self._engine is None:
            url, connect_args = _to_async_dsn(self.settings.dsn())
            self._engine = create_async_engine(
                url,
                echo=self.settings.DB_ECHO,
                pool_pre_ping=True,
                pool_size=self.settings.DB_POOL_SIZE,
                max_overflow=2,
                connect_args=connect_args,
            )
        return self._engine

    @property
    def sessionmaker(self) -> async_sessionmaker[AsyncSession]:
        if self._sessionmaker is None:
            self._sessionmaker = async_sessionmaker(
                bind=self.engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
            )
        return self._sessionmaker

    async def dispose(self) -> None:
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
            self._sessionmaker = None

    @contextlib.asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """Plain session (no RLS context). Used for narrow pre-context lookups."""
        async with self.sessionmaker() as session:
            async with session.begin():
                yield session

    @contextlib.asynccontextmanager
    async def scoped(
        self,
        *,
        project_id: Optional[str] = None,
        organization_id: Optional[str] = None,
    ) -> AsyncIterator[AsyncSession]:
        """Transaction with reviewable, transaction-local RLS context."""
        async with self.sessionmaker() as session:
            async with session.begin():
                await apply_scope(session, project_id=project_id, organization_id=organization_id)
                yield session

    async def healthy(self) -> bool:
        try:
            async with self.session() as session:
                await session.execute(_text("SELECT 1"))
            return True
        except Exception:  # noqa: BLE001 - readiness must be safe and non-throwing
            return False


_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def ensure_uuid(value: str, *, field: str = "id") -> str:
    if not isinstance(value, str) or not _UUID_RE.match(value):
        raise ValueError(f"invalid_uuid:{field}")
    return str(uuid.UUID(value))


async def apply_scope(
    session: AsyncSession,
    *,
    project_id: Optional[str] = None,
    organization_id: Optional[str] = None,
) -> None:
    """Set transaction-local RLS context. Always reset both settings explicitly."""
    await session.execute(
        _text("SELECT set_config('baseline.project_id', :v, true)"),
        {"v": ensure_uuid(project_id, field="project_id") if project_id else ""},
    )
    await session.execute(
        _text("SELECT set_config('baseline.organization_id', :v, true)"),
        {"v": ensure_uuid(organization_id, field="organization_id") if organization_id else ""},
    )


def _text(sql: str):
    from sqlalchemy import text

    return text(sql)


def database() -> Database:
    """Process-wide database handle."""
    global _DATABASE
    try:
        return _DATABASE
    except NameError:
        _DATABASE = Database()
        return _DATABASE


def set_database(instance: Database) -> None:
    global _DATABASE
    _DATABASE = instance
