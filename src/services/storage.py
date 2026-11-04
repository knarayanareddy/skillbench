"""Private local artifact storage.

Bytes live outside the web root on a private volume and are only ever streamed
through an authorized API handler. Uploads land in a quarantine directory and are
promoted by an atomic rename only after the server-computed digest and size match
the declared values.
"""
from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from src.core.db import ensure_uuid


class StorageError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass
class StagedFile:
    sha256: str
    byte_size: int


class ArtifactStore:
    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self.quarantine = self.root / "quarantine"
        self.objects = self.root / "objects"

    def ensure_dirs(self) -> None:
        for path in (self.root, self.quarantine, self.objects):
            path.mkdir(parents=True, exist_ok=True)
            os.chmod(path, 0o700)

    def staging_path(self, upload_id: str) -> Path:
        return self.quarantine / f"{ensure_uuid(upload_id, field='upload_id')}.part"

    def object_path(self, project_id: str, artifact_id: str) -> Path:
        project = ensure_uuid(project_id, field="project_id")
        artifact = ensure_uuid(artifact_id, field="artifact_id")
        return self.objects / project / artifact

    def write_chunks(self, upload_id: str, chunks: Iterable[bytes], *, maximum_bytes: int) -> StagedFile:
        """Stream chunks to quarantine with a hard byte cap and a running digest."""
        self.ensure_dirs()
        target = self.staging_path(upload_id)
        digest = hashlib.sha256()
        size = 0
        tmp_path: Optional[Path] = None
        try:
            handle = tempfile.NamedTemporaryFile(dir=self.quarantine, delete=False)
            tmp_path = Path(handle.name)
            with handle:
                for chunk in chunks:
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > maximum_bytes:
                        raise StorageError("too_large")
                    digest.update(chunk)
                    handle.write(chunk)
            if size == 0:
                raise StorageError("empty_body")
            os.replace(tmp_path, target)
            tmp_path = None
            return StagedFile(sha256=digest.hexdigest(), byte_size=size)
        finally:
            if tmp_path is not None:
                tmp_path.unlink(missing_ok=True)

    async def write_async_chunks(
        self, upload_id: str, chunks, *, maximum_bytes: int
    ) -> StagedFile:
        """Stream an async chunk iterator to quarantine without buffering it all."""
        self.ensure_dirs()
        target = self.staging_path(upload_id)
        digest = hashlib.sha256()
        size = 0
        handle = tempfile.NamedTemporaryFile(dir=self.quarantine, delete=False)
        tmp_path = Path(handle.name)
        try:
            with handle:
                async for chunk in chunks:
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > maximum_bytes:
                        raise StorageError("too_large")
                    digest.update(chunk)
                    handle.write(chunk)
            if size == 0:
                raise StorageError("empty_body")
            os.replace(tmp_path, target)
            return StagedFile(sha256=digest.hexdigest(), byte_size=size)
        finally:
            tmp_path.unlink(missing_ok=True)

    def promote(self, upload_id: str, project_id: str, artifact_id: str) -> Path:
        source = self.staging_path(upload_id)
        if not source.is_file():
            raise StorageError("staged_bytes_missing")
        destination = self.object_path(project_id, artifact_id)
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(destination.parent, 0o700)
        os.replace(source, destination)
        os.chmod(destination, 0o600)
        return destination

    def discard(self, upload_id: str) -> None:
        self.staging_path(upload_id).unlink(missing_ok=True)

    def read_bytes(self, project_id: str, artifact_id: str, *, maximum_bytes: int = 104857600) -> bytes:
        path = self.object_path(project_id, artifact_id)
        try:
            if path.stat().st_size > maximum_bytes:
                raise StorageError("too_large")
            return path.read_bytes()
        except FileNotFoundError as exc:
            raise StorageError("object_missing") from exc

    def exists(self, project_id: str, artifact_id: str) -> bool:
        return self.object_path(project_id, artifact_id).is_file()

    def delete(self, project_id: str, artifact_id: str) -> None:
        self.object_path(project_id, artifact_id).unlink(missing_ok=True)

    def iter_chunks(self, project_id: str, artifact_id: str, chunk_size: int = 65536):
        path = self.object_path(project_id, artifact_id)
        if not path.is_file():
            raise StorageError("object_missing")
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                yield chunk
