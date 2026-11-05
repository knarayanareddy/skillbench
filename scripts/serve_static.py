#!/usr/bin/env python3
"""Serve the built single-page app as immutable static assets.

The web image is a *content* image: it holds `apps/web/dist` and nothing else.
Keeping the server in-repo (instead of a general-purpose web server) means the
serving policy is reviewable and testable without a container runtime:

  * unknown, extension-less paths fall back to `index.html` (client-side routes);
  * anything with an extension must exist, otherwise 404 -- no catch-all masking
    a missing asset as HTML;
  * path traversal, dotfiles and symlinks out of the root are refused;
  * hashed assets under `assets/` are `immutable`, `index.html` is `no-store`;
  * every response carries `X-Content-Type-Options: nosniff`;
  * `GET /health/live` answers for the platform probe without touching disk.

Usage:
    python scripts/serve_static.py --root apps/web/dist --port 8080
"""
from __future__ import annotations

import argparse
import json
import mimetypes
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

IMMUTABLE_PREFIXES = ("assets/",)
DEFAULT_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}


class StaticApp:
    """Path resolution and caching policy, independent of the HTTP plumbing."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        if not self.root.is_dir():
            raise SystemExit(f"static root does not exist: {self.root}")

    def resolve(self, url_path: str) -> tuple[Path, bool] | None:
        """Map a URL path to (file, is_spa_fallback); None means 404."""
        relative = unquote(url_path).lstrip("/")
        if relative in {"", "index.html"}:
            return self._inside("index.html"), False
        if relative.startswith(".") or "/." in relative:
            return None
        candidate = self._inside(relative)
        if candidate is None:
            return None
        if candidate.is_file() and not candidate.is_symlink():
            return candidate, False
        if Path(relative).suffix:
            return None
        return self._inside("index.html"), True

    def _inside(self, relative: str) -> Path | None:
        candidate = (self.root / relative).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            return None
        return candidate

    @staticmethod
    def cache_control(relative: str) -> str:
        if relative.startswith(IMMUTABLE_PREFIXES):
            return "public, max-age=31536000, immutable"
        return "no-store"


class Handler(BaseHTTPRequestHandler):
    server_version = "skb-static"
    sys_version = ""
    app: StaticApp  # set on the subclass created by serve()

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlparse(self.path).path
        if path == "/health/live":
            self._json({"status": "pass", "service": "skillbench-web"})
            return
        if path == "/health/ready":
            self._json({"status": "pass", "service": "skillbench-web"})
            return
        resolved = self.app.resolve(path)
        if resolved is None:
            self._json({"error": "not_found"}, status=HTTPStatus.NOT_FOUND)
            return
        target, _fallback = resolved
        try:
            body = target.read_bytes()
        except OSError:
            self._json({"error": "not_found"}, status=HTTPStatus.NOT_FOUND)
            return
        relative = str(target.relative_to(self.app.root))
        media_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if media_type.startswith("text/") or media_type in {"application/javascript", "application/json"}:
            media_type = f"{media_type}; charset=utf-8"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", media_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", self.app.cache_control(relative))
        for key, value in DEFAULT_HEADERS.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self.do_GET()

    def _json(self, payload: dict, *, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in DEFAULT_HEADERS.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:  # keep container logs quiet
        if os.getenv("SKB_STATIC_ACCESS_LOG") == "1":
            super().log_message(fmt, *args)


def serve(root: Path, host: str, port: int) -> ThreadingHTTPServer:
    app = StaticApp(root)
    handler = type("BoundHandler", (Handler,), {"app": app})
    return ThreadingHTTPServer((host, port), handler)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("apps/web/dist"))
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    server = serve(args.root, args.host, args.port)
    print(json.dumps({"serving": str(server.server_address[1]), "root": str(args.root)}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
