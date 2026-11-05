#!/usr/bin/env python3
"""Check the deployable-image policy and print (or run) the build commands.

There is no container runtime in this sandbox, so the images cannot be built here.
What *can* be checked is the part that tends to go wrong and that no test suite
covers: that the shipping image is unprivileged and read-only friendly, that it
carries no test or oracle packages, that every base image is digest-pinned before
a build command is printed, that the compose services reference the same images,
and that the SBOM matches the runtime dependency set.

    python scripts/build_images.py --check
    python scripts/build_images.py --print-build --python-base python:3.12-slim@sha256:... \\
        --node-base node:24-slim@sha256:...

`--check` exits 1 on any policy violation. `--print-build` refuses mutable tags and
will run `docker build` only with `--execute` (unavailable without a daemon).
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILES = {
    "api": ROOT / "infra" / "Dockerfile.api",
    "web": ROOT / "infra" / "Dockerfile.web",
}
COMPOSE = ROOT / "infra" / "compose.yaml"
RUNTIME_REQS = ROOT / "requirements-runtime.txt"
ALL_REQS = ROOT / "requirements.txt"
APP_SERVICES = {"api", "web", "dispatcher", "lifecycle"}
EXCLUDED_RUNTIME = {"pytest", "pytest-asyncio", "pglast", "jsonschema", "referencing", "pyyaml", "alembic"}


def _requirement_names(path: Path) -> List[str]:
    names = []
    for raw in path.read_text().splitlines():
        line = raw.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        names.append(re.split(r"[<>=!~;\[ ]", line, maxsplit=1)[0].lower())
    return names


def _final_stage(text: str) -> str:
    parts = re.split(r"(?m)^FROM\s", text)
    return "FROM " + parts[-1] if parts else text


def check_dockerfiles() -> List[str]:
    problems: List[str] = []
    for name, path in DOCKERFILES.items():
        if not path.exists():
            problems.append(f"{name}: missing {path.relative_to(ROOT)}")
            continue
        text = path.read_text()
        stage = _final_stage(text)
        if "USER 10001:10001" not in stage:
            problems.append(f"{name}: final stage must run as USER 10001:10001")
        if "HEALTHCHECK" not in stage:
            problems.append(f"{name}: final stage needs a HEALTHCHECK")
        if re.search(r"(?m)^\s*ADD\s", text):
            problems.append(f"{name}: use COPY, not ADD")
        if re.search(r"(?i)pip install[^\n]*pytest|pip install[^\n]*pglast", text):
            problems.append(f"{name}: image installs test/oracle packages")
        if re.search(r"(?m)^\s*ENV\s+.*(SECRET|PASSWORD|TOKEN)=", text):
            problems.append(f"{name}: secrets must be supplied by file, never baked in")
        if "@sha256:" in re.search(r"(?m)^ARG\s+[A-Z_]+=(.*)$", text).group(0):
            problems.append(f"{name}: digests belong in --build-arg, not the default")
        allowed = {"requirements-runtime.txt", "src", "contracts", "dist", "serve_static.py"}
        for copy in re.findall(r"(?m)^COPY\s+(?:--from=\S+\s+)?(\S+)", _final_stage(text)):
            leaf = copy.rstrip("/").split("/")[-1]
            if leaf not in allowed:
                problems.append(f"{name}: unexpected runtime layer content {copy}")
    return problems


def check_requirements() -> List[str]:
    problems: List[str] = []
    runtime = set(_requirement_names(RUNTIME_REQS))
    everything = set(_requirement_names(ALL_REQS))
    missing = runtime - everything
    if missing:
        problems.append(f"requirements-runtime.txt is not a subset of requirements.txt: {sorted(missing)}")
    leaked = runtime & EXCLUDED_RUNTIME
    if leaked:
        problems.append(f"runtime requirements include test/oracle packages: {sorted(leaked)}")
    return problems


def check_compose() -> List[str]:
    problems: List[str] = []
    text = COMPOSE.read_text()
    try:
        import yaml

        parsed = yaml.safe_load(text)
    except Exception as exc:  # noqa: BLE001 - a compose file must at least parse
        return [f"compose: not parseable YAML ({type(exc).__name__})"]
    services = parsed.get("services", {})
    for name, service in services.items():
        if not isinstance(service, dict) or "image" not in service:
            problems.append(f"compose: {name} has no image")
            continue
        # Hardening applies to the images this repository builds. The database and
        # edge proxy are third-party digest-pinned images with their own runtime needs
        # (pg writes to /var/lib/postgresql/data, caddy to /data); they are bounded
        # instead by digest pinning, cap limits and network placement.
        if name not in APP_SERVICES:
            continue
        if not service.get("read_only"):
            problems.append(f"compose: {name} must run with a read-only root filesystem")
        if "no-new-privileges:true" not in (service.get("security_opt") or []):
            problems.append(f"compose: {name} must set no-new-privileges")
        if str(service.get("user")) != "10001:10001":
            problems.append(f"compose: {name} must run as 10001:10001")
    for service in ("api", "web", "dispatcher", "lifecycle"):
        block = re.search(rf"(?ms)^  {service}:\n(.*?)(?=^  \w|\Z)", text)
        if not block:
            problems.append(f"compose: missing service {service}")
            continue
        body = block.group(1)
        if "image:" not in body:
            problems.append(f"compose: {service} has no image")
        if ":latest" in body:
            problems.append(f"compose: {service} uses a mutable :latest tag")
        if "read_only: true" not in body:
            problems.append(f"compose: {service} must run with a read-only root filesystem")
        if "no-new-privileges:true" not in body:
            problems.append(f"compose: {service} must set no-new-privileges")
        if service in {"dispatcher", "lifecycle"}:
            if "baseline_app" in body or "/run/secrets/app_db_dsn" in body:
                problems.append(f"compose: {service} must not borrow the API's database identity")
    if "python\n    - -m\n    - apps.dispatcher" in text:
        problems.append("compose: dispatcher points at the obsolete apps.dispatcher module")
    if "/health/ready" not in text:
        problems.append("compose: the API readiness probe must target /health/ready")
    for secret in ("db_owner_password", "app_db_dsn", "dispatcher_db_dsn", "lifecycle_db_dsn"):
        if f"{secret}:" not in text.split("secrets:")[-1]:
            problems.append(f"compose: secret {secret} is referenced but not declared")
    return problems


def check_sbom() -> List[str]:
    problems: List[str] = []
    bom_path = ROOT / "evidence" / "sbom" / "skillbench-api.cdx.json"
    if not bom_path.exists():
        return ["evidence/sbom/skillbench-api.cdx.json is missing; run scripts/build_sbom.py"]
    bom = json.loads(bom_path.read_text())
    names = {component["name"] for component in bom.get("components", [])}
    leaked = names & EXCLUDED_RUNTIME
    if leaked:
        problems.append(f"SBOM advertises test/oracle packages in the image: {sorted(leaked)}")
    expected = set(_requirement_names(RUNTIME_REQS)) - EXCLUDED_RUNTIME
    absent = {name for surname in expected for name in [surname.replace("_", "-")]} - names
    if absent:
        problems.append(f"SBOM misses runtime components: {sorted(absent)}")
    return problems


def build_commands(python_base: str, node_base: str) -> Dict[str, List[str]]:
    for label, ref in (("python", python_base), ("node", node_base)):
        if "@sha256:" not in ref:
            raise SystemExit(f"--{label}-base must be digest-pinned (got {ref!r})")
    return {
        "api": [
            "docker", "build", "-f", "infra/Dockerfile.api",
            "--build-arg", f"PYTHON_BASE={python_base}",
            "-t", "baseline-api:local", ".",
        ],
        "web": [
            "docker", "build", "-f", "infra/Dockerfile.web",
            "--build-arg", f"NODE_BASE={node_base}",
            "--build-arg", f"PYTHON_BASE={python_base}",
            "-t", "baseline-web:local", ".",
        ],
    }


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--print-build", action="store_true")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--python-base", default="python:3.12-slim")
    parser.add_argument("--node-base", default="node:24-slim")
    args = parser.parse_args(argv)

    problems = check_dockerfiles() + check_requirements() + check_compose() + check_sbom()
    report: Dict[str, object] = {
        "status": "ok" if not problems else "blocked",
        "problems": problems,
        "dockerfiles": sorted(str(path.relative_to(ROOT)) for path in DOCKERFILES.values()),
        "container_runtime": shutil.which("docker") or shutil.which("podman") or None,
        "production_ready": False,
    }
    if args.print_build or args.execute:
        commands = build_commands(args.python_base, args.node_base)
        report["build"] = {" ".join(command) for command in (v for v in commands.values())}
        if args.execute:
            if not report["container_runtime"]:
                raise SystemExit("no container runtime available; cannot execute the build")
            for command in commands.values():
                result = subprocess.run(command, cwd=ROOT)
                if result.returncode != 0:
                    raise SystemExit(f"build failed: {command[0]}")
            report["built"] = True
        else:
            report["built"] = False
    print(json.dumps(report, indent=2, default=list))
    if problems:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
