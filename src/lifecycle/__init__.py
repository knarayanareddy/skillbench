"""Lifecycle process: expiry, purge and backlog maintenance.

Runs as `lifecycle_login` (member of `baseline_lifecycle`), the only runtime identity
allowed to delete content. It never touches evidence tables: audit rows, reviews,
trials and analyses are append-only and their privileges are revoked from this role.

Guarantees:
  * a purge marks intent (``deleting`` / tombstone) before removing bytes, so an
    interrupted purge is retried rather than reported complete;
  * content that is still referenced by a package, suite, trial or upload is never
    deleted, even when it is past its expiry;
  * a run is idempotent: repeating it performs no additional destructive work.
"""
from __future__ import annotations
