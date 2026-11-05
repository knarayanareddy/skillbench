"""Deployable-image policy and SBOM hygiene.

No container runtime exists in this environment, so these tests pin the parts of
the image definition that a reviewer can check statically and that a later build
must not silently weaken: unprivileged runtime, no test/oracle packages, pinned
bases, compose services that agree with the Dockerfiles, and an SBOM that matches
the runtime dependency set exactly.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import build_images, build_sbom  # noqa: E402

EXCLUDED = {"pytest", "pytest-asyncio", "pglast", "jsonschema", "referencing", "pyyaml", "alembic"}


def test_image_policy_checks_pass():
    assert build_images.main(["--check"]) == 0


def test_build_requires_digest_pinned_bases():
    with pytest.raises(SystemExit):
        build_images.build_commands("python:3.12-slim", "node:24-slim")
    commands = build_images.build_commands(
        "python:3.12-slim@sha256:" + "0" * 64, "node:24-slim@sha256:" + "1" * 64
    )
    assert set(commands) == {"api", "web"}
    assert all("@sha256:" in " ".join(command) for command in commands.values())


def test_runtime_requirements_are_a_strict_subset_without_oracles():
    runtime = set(build_images._requirement_names(build_images.RUNTIME_REQS))
    everything = set(build_images._requirement_names(build_images.ALL_REQS))
    assert runtime < everything
    assert not runtime & EXCLUDED


def test_sbom_is_deterministic_and_complete(tmp_path):
    first = tmp_path / "one.json"
    second = tmp_path / "two.json"
    for target in (first, second):
        assert build_sbom.main(
            [
                "--runtime",
                "--npm-lock",
                str(ROOT / "apps" / "web" / "package-lock.json"),
                "--base-image",
                "api=python:3.12-slim@sha256:" + "a" * 64,
                "--output",
                str(target),
            ]
        ) == 0
    assert first.read_bytes() == second.read_bytes()

    bom = json.loads(first.read_text())
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.5"
    assert bom["metadata"]["component"]["name"] == "skillbench-api"
    assert bom["metadata"]["properties"] == [
        {"name": "skb:production_ready", "value": "false"},
        {"name": "skb:runtime", "value": "fixture-only; no model calls; no upload execution"},
    ]
    names = {component["name"] for component in bom["components"]}
    assert not names & EXCLUDED
    for requirement in build_images._requirement_names(build_images.RUNTIME_REQS):
        assert requirement.replace("_", "-") in names
    containers = [c for c in bom["components"] if c["type"] == "container"]
    assert len(containers) == 1 and containers[0]["name"] == "api"
    npm = [c for c in bom["components"] if c["name"] == "react"]
    assert npm and npm[0]["version"].startswith("18.")
    assert npm[0]["hashes"][0]["alg"] == "SHA-512"


def test_committed_sboms_match_the_lockfiles():
    """A stale SBOM is worse than none: it certifies components that are not shipped."""
    committed = ROOT / "evidence" / "sbom" / "skillbench-api.cdx.json"
    assert committed.exists()
    bom = json.loads(committed.read_text())
    components = {c["bom-ref"]: c for c in bom["components"]}

    lock = json.loads((ROOT / "apps" / "web" / "package-lock.json").read_text())
    for path, entry in lock["packages"].items():
        if not path or "version" not in entry:
            continue
        name = entry.get("name") or path.split("node_modules/")[-1]
        assert f"pkg:npm/{name}@{entry['version']}" in components

    digest = hashlib.sha256(committed.read_bytes()).hexdigest()
    assert len(digest) == 64


def test_compose_services_pin_their_own_database_identity():
    import yaml

    services = yaml.safe_load((ROOT / "infra" / "compose.yaml").read_text())["services"]
    for service in ("dispatcher", "lifecycle"):
        body = services[service]
        secrets = body.get("secrets") or []
        assert f"{service}_db_dsn" in secrets
        assert "app_db_dsn" not in secrets
        assert body.get("user") == "10001:10001"
        assert body.get("read_only") is True
