"""Deterministic canonical JSON (`baseline-json/1`) and digests.

This is application code, intentionally independent of reference/oracles.py.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


class CanonicalisationError(ValueError):
    """Raised when a value cannot be represented in the bounded canonical form."""


def _reject_constant(value: str) -> None:
    raise CanonicalisationError("non_finite_number")


def canonical_bytes(value: Any) -> bytes:
    """UTF-8 JSON, sorted keys, compact separators, NaN/Infinity rejected."""
    try:
        text = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
            default=_raise_not_serialisable,
        )
    except (TypeError, ValueError) as exc:
        if isinstance(exc, CanonicalisationError):
            raise
        raise CanonicalisationError("not_canonicalisable") from exc
    return text.encode("utf-8")


def _raise_not_serialisable(value: Any) -> Any:
    raise CanonicalisationError("not_canonicalisable")


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_request_hash(*, method: str, path: str, query: dict[str, str], body: Any) -> str:
    """Digest of the normalized request used for scoped idempotency replay."""
    return sha256_hex(
        {
            "method": method.upper(),
            "path": path,
            "query": {k: query[k] for k in sorted(query) if k != "Idempotency-Key"},
            "body": body,
        }
    )
