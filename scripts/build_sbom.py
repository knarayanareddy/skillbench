#!/usr/bin/env python3
"""Generate the CycloneDX SBOM for an image from what is actually installed.

The SBOM is produced from the *built environment*, not from the loose requirement
ranges: inside the image, `requirements-runtime.txt` has already been resolved by
pip. Run this script there and it records exact versions plus the digests that npm
locked, so the SBOM can be compared with the image digest.

What is deliberately excluded: test runners, contract linters and oracles
(pytest, pytest-asyncio, pglast, jsonschema, referencing, pyyaml, alembic). A
production image that could run its own certifying oracles would ship the thing
it is supposed to be checked by.

Usage (API image):
    python scripts/build_sbom.py --runtime --npm-lock apps/web/package-lock.json \
        --base-image api=python:3.12-slim@sha256:... --output evidence/sbom/api.cdx.json

Usage (web image):
    python scripts/build_sbom.py --npm-lock apps/web/package-lock.json \
        --base-image web=node:24-slim@sha256:... --output evidence/sbom/web.cdx.json
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import uuid
from pathlib import Path
from typing import Dict, Iterable, List, Optional

ROOT = Path(__file__).resolve().parents[1]
SERVICE_VERSION = "0.2.0"
EXCLUDED_RUNTIME = {
    "pytest",
    "pytest-asyncio",
    "pglast",
    "jsonschema",
    "referencing",
    "pyyaml",
    "alembic",
}
BOM_VERSION = "1.5"
# Fixed namespace so the serial number is a deterministic function of the content.
SERIAL_NAMESPACE = uuid.UUID("6f9619ff-8b86-d011-b42d-00c04fc964ff")


def normalise(name: str) -> str:
    """PEP 503 normalisation, minus extras (`uvicorn[standard]` -> `uvicorn`)."""
    return re.sub(r"[-_.]+", "-", name.split("[")[0]).strip().lower()


def requirement_names(path: Path) -> List[str]:
    names = []
    for raw in path.read_text().splitlines():
        line = raw.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        name = re.split(r"[<>=!~;\[ ]", line, maxsplit=1)[0]
        names.append(normalise(name))
    return names


def installed_versions(names: Iterable[str], *, allow_missing: bool) -> List[dict]:
    from importlib import metadata

    components, missing = [], []
    for name in sorted(set(names)):
        if name in EXCLUDED_RUNTIME:
            continue
        try:
            distribution = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            missing.append(name)
            continue
        components.append(
            {
                "type": "library",
                "bom-ref": f"pkg:pypi/{name}@{distribution.version}",
                "name": name,
                "version": distribution.version,
                "purl": f"pkg:pypi/{name}@{distribution.version}",
                "properties": [
                    {"name": "skb:scope", "value": "python-runtime"},
                    {"name": "skb:source", "value": "installed-metadata"},
                ],
            }
        )
    if missing and not allow_missing:
        raise SystemExit(f"runtime requirements not installed: {', '.join(sorted(missing))}")
    return components


def npm_components(lockfile: Path) -> List[dict]:
    lock = json.loads(lockfile.read_text())
    components = []
    for path, entry in sorted(lock.get("packages", {}).items()):
        if not path or "version" not in entry:
            continue
        name = entry.get("name") or path.split("node_modules/")[-1]
        version = entry["version"]
        scope = "npm-dev" if entry.get("dev") else "npm-runtime"
        component = {
            "type": "library",
            "bom-ref": f"pkg:npm/{name}@{version}",
            "name": name,
            "version": version,
            "purl": f"pkg:npm/{name}@{version}",
            "properties": [
                {"name": "skb:scope", "value": scope},
                {"name": "skb:source", "value": "package-lock.json"},
            ],
        }
        integrity = entry.get("integrity", "")
        if integrity.startswith("sha512-"):
            digest = base64.b64decode(integrity.split("-", 1)[1]).hex()
            component["hashes"] = [{"alg": "SHA-512", "content": digest}]
        if entry.get("license"):
            component["licenses"] = [{"license": {"name": entry["license"]}}]
        components.append(component)
    return components


def base_image_components(refs: Iterable[str]) -> List[dict]:
    components = []
    for ref in refs:
        label, _, image = ref.partition("=")
        if not image:
            raise SystemExit(f"--base-image must be name=reference, got {ref!r}")
        if "@sha256:" not in image:
            raise SystemExit(f"base image must be digest-pinned, got {image!r}")
        components.append(
            {
                "type": "container",
                "bom-ref": f"skb:base:{label}",
                "name": label,
                "version": image.rsplit("@", 1)[-1],
                "properties": [
                    {"name": "skb:scope", "value": "base-image"},
                    {"name": "skb:source", "value": image},
                ],
            }
        )
    return components


def build_bom(components: List[dict], *, component_name: str) -> dict:
    body = {
        "bomFormat": "CycloneDX",
        "specVersion": BOM_VERSION,
        "version": 1,
        "metadata": {
            "tools": [{"vendor": "SkillBench", "name": "scripts/build_sbom.py", "version": "1"}],
            "component": {
                "type": "application",
                "bom-ref": f"skb:{component_name}",
                "name": component_name,
                "version": SERVICE_VERSION,
            },
            "properties": [
                {"name": "skb:production_ready", "value": "false"},
                {"name": "skb:runtime", "value": "fixture-only; no model calls; no upload execution"},
            ],
        },
        "components": components,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(canonical).hexdigest()
    ordered = {
        "bomFormat": body["bomFormat"],
        "specVersion": body["specVersion"],
        "serialNumber": f"urn:uuid:{uuid.uuid5(SERIAL_NAMESPACE, digest)}",
        "version": body["version"],
        "metadata": body["metadata"],
        "components": components,
    }
    return ordered


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", action="store_true", help="include installed runtime requirements")
    parser.add_argument("--requirements", type=Path, default=ROOT / "requirements-runtime.txt")
    parser.add_argument("--npm-lock", type=Path, action="append", default=[])
    parser.add_argument("--base-image", action="append", default=[], metavar="NAME=REF@sha256:...")
    parser.add_argument("--component-name", default="skillbench-api")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-missing", action="store_true")
    args = parser.parse_args(argv)

    components: List[dict] = []
    if args.runtime:
        names = requirement_names(args.requirements)
        components.extend(installed_versions(names, allow_missing=args.allow_missing))
    for lockfile in args.npm_lock:
        components.extend(npm_components(lockfile))
    components.extend(base_image_components(args.base_image))

    seen: Dict[str, dict] = {}
    for component in components:
        seen.setdefault(component["bom-ref"], component)
    unique = sorted(seen.values(), key=lambda item: (item["type"], item["name"], item["version"]))

    bom = build_bom(unique, component_name=args.component_name)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(bom, indent=2, sort_keys=False) + "\n"
    args.output.write_text(payload)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "components": len(unique),
                "scopes": sorted({p["value"] for c in unique for p in c["properties"] if p["name"] == "skb:scope"}),
                "sha256": hashlib.sha256(payload.encode()).hexdigest(),
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
