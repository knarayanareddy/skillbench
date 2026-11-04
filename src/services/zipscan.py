"""Inert ZIP inspection for SkillBench package intake.

The archive is never extracted to disk and no submitted entry is executed,
imported or interpreted. Only entry metadata plus a bounded streaming decompress
check (to detect size lies and zip bombs) is performed.

Rejection policy (reviewed, docs/SKB_Intake_Policy.md):
  * path traversal, absolute paths, drive letters, backslashes, NUL, empty,
    ``.``/``..`` components, or duplicate paths (case-insensitive included);
  * symlinks, hardlinks, devices, FIFOs and any non-regular entry type;
  * encrypted entries;
  * unsupported compression methods (only stored and deflate are accepted);
  * more than ``max_files`` entries, more than ``max_expanded`` declared or
    actual expanded bytes, more than ``max_compressed`` archive bytes;
  * an entry whose declared size does not match the decompressed size, or a
    file whose first bytes are an executable/scripting shebang marker.
Any scanner/inspection failure is a failed inspection, never a clean scan.
"""
from __future__ import annotations

import io
import re
import stat
import zipfile
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

from src.core.canonical import sha256_hex

ZIP_LOCAL_HEADER = b"PK\x03\x04"
ALLOWED_METHODS = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
MAX_SINGLE_ENTRY = 104857600
_EXECUTABLE_MAGIC = (b"\x7fELF", b"MZ", b"\xca\xfe\xba\xbe", b"#!/", b"#! ")
_DRIVE_RE = re.compile(r"^[A-Za-z]:")
MAX_RATIO = 100


class InspectionError(Exception):
    """Inspection could not complete. This is never reported as a clean scan."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass
class Finding:
    code: str
    severity: str
    detail: str

    def as_dict(self) -> dict:
        return {"code": self.code, "severity": self.severity, "detail": self.detail}


@dataclass
class Entry:
    path: str
    entry_type: str
    byte_size: int
    compressed_size: int
    ordinal: int

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "entry_type": self.entry_type,
            "byte_size": self.byte_size,
            "compressed_size": self.compressed_size,
            "ordinal": self.ordinal,
        }


@dataclass
class InspectionResult:
    accepted: bool
    entries: List[Entry] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    summary_sha256: str = ""

    def finding_codes(self) -> List[str]:
        return [f.code for f in self.findings]


def inspect_zip(
    blob: bytes,
    *,
    max_expanded: int = 104857600,
    max_files: int = 2000,
    max_compressed: int = 20971520,
    known_script_names: Optional[Iterable[str]] = None,
) -> InspectionResult:
    """Inspect an in-memory archive and return a deterministic verdict."""
    findings: List[Finding] = []
    entries: List[Entry] = []

    if len(blob) > max_compressed:
        raise InspectionError("compressed_limit")
    if len(blob) < 22 or not blob.startswith(ZIP_LOCAL_HEADER) and b"PK\x05\x06" not in blob[-1024:]:
        raise InspectionError("not_a_zip")

    try:
        archive = zipfile.ZipFile(io.BytesIO(blob))
        infos = archive.infolist()
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        raise InspectionError("corrupt_zip") from exc

    if len(infos) > max_files:
        raise InspectionError("entry_limit")

    declared_total = 0
    seen: set[str] = set()
    seen_folded: set[str] = set()

    for ordinal, info in enumerate(infos):
        path = info.filename
        unsafe = _unsafe_path(path)
        if unsafe:
            findings.append(Finding("unsafe_path", "critical", f"entry {ordinal} rejected: {unsafe}"))
            continue

        mode = (info.external_attr >> 16) & 0o170000
        if info.is_dir():
            entry_type = "directory"
        elif mode in (0, stat.S_IFREG):
            entry_type = "file"
        else:
            findings.append(
                Finding("unsafe_entry_type", "critical", f"entry {ordinal} has a non-regular file type")
            )
            continue

        if info.flag_bits & 0x1:
            findings.append(Finding("encrypted_entry", "critical", f"entry {ordinal} is encrypted"))
            continue
        if entry_type == "file" and info.compress_type not in ALLOWED_METHODS:
            findings.append(
                Finding("unsupported_compression", "high", f"entry {ordinal} uses an unsupported method")
            )
            continue

        key = path.rstrip("/")
        if key in seen or key.casefold() in seen_folded:
            findings.append(Finding("duplicate_path", "high", f"entry {ordinal} duplicates another path"))
            continue
        seen.add(key)
        seen_folded.add(key.casefold())

        if info.file_size > MAX_SINGLE_ENTRY:
            findings.append(Finding("entry_too_large", "high", f"entry {ordinal} exceeds the per-file limit"))
            continue

        declared_total += info.file_size
        if declared_total > max_expanded:
            findings.append(Finding("expanded_limit", "critical", "declared expanded size exceeds the limit"))
            break

        if entry_type == "file" and info.file_size > 1048576:
            ratio = info.file_size / max(info.compress_size, 1)
            if ratio > MAX_RATIO:
                findings.append(
                    Finding("compression_ratio", "high", f"entry {ordinal} has a suspicious compression ratio")
                )
                continue

        entries.append(
            Entry(
                path=key,
                entry_type=entry_type,
                byte_size=int(info.file_size),
                compressed_size=int(info.compress_size),
                ordinal=ordinal,
            )
        )

    # Bounded streaming verification: catch lying sizes and explosive archives
    # without ever writing extracted content to disk.
    if not any(f.severity in {"critical", "high"} for f in findings):
        try:
            entries, findings = _verify_stream(archive, entries, max_expanded, findings, known_script_names)
        except InspectionError:
            raise
        finally:
            archive.close()
    else:
        archive.close()

    if not infos:
        findings.append(Finding("empty_archive", "high", "archive contains no entries"))
    # Only blocking findings reject; informational findings are surfaced to the
    # reviewing maintainer without making a benign archive unusable.
    accepted = not any(f.severity in {"critical", "high"} for f in findings)
    summary = {
        "policy": "skb-zip-inspection/1",
        "entries": len(entries),
        "expanded_bytes": sum(e.byte_size for e in entries),
        "max_expanded_bytes": max_expanded,
        "max_files": max_files,
        "accepted": accepted,
        "finding_codes": sorted({f.code for f in findings}),
        "labels": ["synthetic-only", "inert-inspection"],
    }
    return InspectionResult(
        accepted=accepted,
        entries=entries,
        findings=findings,
        summary=summary,
        summary_sha256=sha256_hex(summary),
    )


def _verify_stream(
    archive: zipfile.ZipFile,
    entries: List[Entry],
    max_expanded: int,
    findings: List[Finding],
    known_script_names: Optional[Iterable[str]],
) -> tuple[List[Entry], List[Finding]]:
    total = 0
    script_names = {name.casefold() for name in (known_script_names or [])}
    originals = {info.filename.rstrip("/"): info for info in archive.infolist()}
    for entry in entries:
        info = originals.get(entry.path)
        if info is None:
            raise InspectionError("archive_changed")
        if entry.entry_type == "directory":
            continue
        actual = 0
        head = b""
        try:
            with archive.open(info, "r") as stream:
                while True:
                    chunk = stream.read(65536)
                    if not chunk:
                        break
                    if not head:
                        head = chunk[:8]
                    actual += len(chunk)
                    if actual > info.file_size or actual + total > max_expanded:
                        raise InspectionError("size_mismatch")
        except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
            raise InspectionError("corrupt_entry") from exc
        if actual != info.file_size:
            raise InspectionError("size_mismatch")
        total += actual
        if head.startswith(_EXECUTABLE_MAGIC):
            findings.append(
                Finding(
                    "executable_payload",
                    "high",
                    f"entry {entry.ordinal} contains an executable or shebang payload; inert intake only",
                )
            )
        if entry.path.casefold() in script_names:
            findings.append(
                Finding("script_entry_present", "info", f"entry {entry.ordinal} is a declared script file")
            )
    findings = _dedupe_findings(findings)
    return entries, findings


def _dedupe_findings(findings: List[Finding]) -> List[Finding]:
    seen: set[tuple[str, str]] = set()
    out: List[Finding] = []
    for finding in findings:
        key = (finding.code, finding.detail)
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def _unsafe_path(name: str) -> Optional[str]:
    if not name or "\x00" in name:
        return "empty_or_nul"
    if "\\" in name:
        return "backslash"
    if name.startswith("/"):
        return "absolute"
    if _DRIVE_RE.match(name):
        return "drive_letter"
    if name.startswith("./"):
        return "dot_prefix"
    parts = name.rstrip("/").split("/")
    if any(part in ("", ".", "..") for part in parts):
        return "traversal"
    return None
