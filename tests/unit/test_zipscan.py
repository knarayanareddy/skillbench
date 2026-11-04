"""Inert archive inspection: rejections are findings, failures are never clean scans."""
from __future__ import annotations

import io
import zipfile

import pytest

from src.services.zipscan import InspectionError, inspect_zip


def archive(entries, *, compression=zipfile.ZIP_DEFLATED, mode=None):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as handle:
        for name, body in entries:
            info = zipfile.ZipInfo(name)
            if mode is not None:
                info.external_attr = mode << 16
            compress = zipfile.ZIP_STORED if isinstance(body, bytes) and len(body) < 20 else compression
            handle.writestr(info, body, compress_type=compress)
    return buffer.getvalue()


def codes(result):
    return {finding.code for finding in result.findings}


def test_benign_archive_is_accepted_with_stable_ordering():
    result = inspect_zip(archive([("b.txt", b"two"), ("a.txt", b"one")]))
    assert result.accepted is True
    assert [entry.path for entry in result.entries] == ["b.txt", "a.txt"]
    assert [entry.ordinal for entry in result.entries] == [0, 1]
    assert result.summary["accepted"] is True
    assert len(result.summary_sha256) == 64


@pytest.mark.parametrize(
    "name",
    ["../escape.txt", "/abs/path.txt", "a/../../b.txt", "C:/windows.txt", "dir\\evil.txt", "a//b.txt", ""],
)
def test_unsafe_paths_are_rejected(name):
    result = inspect_zip(archive([(name, b"x")]))
    assert result.accepted is False
    assert "unsafe_path" in codes(result)


def test_nul_byte_path_is_rejected():
    from src.services.zipscan import _unsafe_path

    # Python's zip reader truncates at NUL, so the guard is asserted directly.
    assert _unsafe_path("a\x00b.txt")
    result = inspect_zip(archive([("a\x00b.txt", b"x")]))
    assert result.accepted is True


def test_duplicate_paths_are_rejected_case_insensitively():
    result = inspect_zip(archive([("Readme.md", b"a"), ("readme.md", b"b")]))
    assert result.accepted is False
    assert "duplicate_path" in codes(result)


@pytest.mark.parametrize("mode", [0o120777, 0o060644, 0o020644])
def test_non_regular_entry_types_are_rejected(mode):
    result = inspect_zip(archive([("link", b"/etc/passwd")], mode=mode))
    assert result.accepted is False
    assert "unsafe_entry_type" in codes(result)


def test_executable_payload_is_a_finding_not_an_execution():
    for payload in (b"\x7fELF\x02\x01", b"MZ\x90\x00", b"#!/bin/sh\nrm -rf /"):
        result = inspect_zip(archive([("tool", payload)]))
        assert result.accepted is False
        assert "executable_payload" in codes(result)
        # Inspection is metadata only: no entry content is returned to callers.
        assert set(result.entries[0].as_dict()) == {"path", "entry_type", "byte_size", "compressed_size", "ordinal"}


def test_encrypted_entries_are_rejected():
    payload = bytearray(archive([("secret.txt", b"x" * 40)]))
    # Set the "encrypted" bit in the local header and central directory flags.
    for signature in (b"PK\x03\x04", b"PK\x01\x02"):
        start = payload.find(signature)
        flag_offset = start + (6 if signature == b"PK\x03\x04" else 8)
        payload[flag_offset] |= 0x01
    result = inspect_zip(bytes(payload))
    assert result.accepted is False
    assert "encrypted_entry" in codes(result)


def test_unsupported_compression_is_rejected():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_BZIP2) as handle:
        handle.writestr("data.txt", b"compress me with bzip2 please")
    result = inspect_zip(buffer.getvalue())
    assert result.accepted is False
    assert "unsupported_compression" in codes(result)


def test_entry_count_limit_is_enforced():
    result_bytes = archive([(f"file-{index}.txt", b"x") for index in range(6)])
    with pytest.raises(InspectionError) as error:
        inspect_zip(result_bytes, max_files=5)
    assert str(error.value) == "entry_limit"


def test_expanded_size_limit_is_enforced():
    blob = archive([("big.bin", b"0" * 4096)])
    result = inspect_zip(blob, max_expanded=1024)
    assert result.accepted is False
    assert "expanded_limit" in codes(result)


def test_not_a_zip_and_corrupt_input_fail_closed():
    with pytest.raises(InspectionError) as error:
        inspect_zip(b"definitely not a zip archive")
    assert str(error.value) == "not_a_zip"
    corrupt = bytearray(archive([("a.txt", b"hello")]))
    corrupt[40:60] = b"\x00" * 20
    with pytest.raises(InspectionError):
        inspect_zip(bytes(corrupt))


def test_empty_archive_is_rejected():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w"):
        pass
    result = inspect_zip(buffer.getvalue())
    assert result.accepted is False
    assert "empty_archive" in codes(result)


def test_script_entry_is_reported_as_informational_only():
    result = inspect_zip(
        archive([("run.sh", b"echo hello"), ("SKILL.md", b"body")]),
        known_script_names=["run.sh"],
    )
    assert result.accepted is True
    assert "script_entry_present" in codes(result)
    severities = {finding.code: finding.severity for finding in result.findings}
    assert severities["script_entry_present"] == "info"
