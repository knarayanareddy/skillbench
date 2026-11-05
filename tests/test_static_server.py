"""The static UI server: SPA fallback, caching policy and traversal refusal.

These are the properties the web image depends on, exercised over a real socket
rather than by inspecting a framework config.
"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from scripts.serve_static import StaticApp, serve


@pytest.fixture()
def dist(tmp_path: Path) -> Path:
    root = tmp_path / "dist"
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text("<!doctype html><div id=root></div>")
    (root / "assets" / "index-abc123.js").write_text("console.log('hi')")
    (root / "assets" / "index-abc123.css").write_text("body{}")
    (root / ".hidden").write_text("secret")
    return root


@pytest.fixture()
def base_url(dist: Path):
    server = serve(dist, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def fetch(url: str):
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as error:  # 4xx/5xx are still responses
        return error.code, dict(error.headers), error.read()


def test_index_is_served_uncached_with_nosniff(base_url):
    status, headers, body = fetch(base_url + "/")
    assert status == 200
    assert headers["Content-Type"].startswith("text/html")
    assert headers["Cache-Control"] == "no-store"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert b"<div id=root>" in body


def test_hashed_assets_are_immutable(base_url):
    status, headers, body = fetch(base_url + "/assets/index-abc123.js")
    assert status == 200
    assert headers["Cache-Control"] == "public, max-age=31536000, immutable"
    assert headers["Content-Type"].startswith(("application/javascript", "text/javascript"))
    assert b"console.log" in body


def test_client_side_routes_fall_back_to_index(base_url):
    status, headers, body = fetch(base_url + "/experiments/123/trials")
    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert b"<div id=root>" in body


def test_missing_asset_is_not_masked_by_the_fallback(base_url):
    status, _headers, body = fetch(base_url + "/assets/index-deadbeef.js")
    assert status == 404
    assert json.loads(body)["error"] == "not_found"


@pytest.mark.parametrize(
    "path",
    ["/../etc/passwd", "/%2e%2e/%2e%2e/etc/passwd", "/.hidden", "/assets/../../etc/passwd"],
)
def test_traversal_and_dotfiles_are_refused(base_url, path):
    status, _headers, _body = fetch(base_url + path)
    assert status == 404


def test_health_probes_do_not_touch_disk(dist: Path):
    # The probe is answered by the request handler before any path is resolved,
    # so it cannot be shadowed by a build artefact.
    app = StaticApp(dist)
    assert app.resolve("/health/live")[1] is True
    server = serve(dist, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/health/live"
        status, headers, body = fetch(url)
        assert status == 200 and json.loads(body)["status"] == "pass"
        assert headers["Cache-Control"] == "no-store"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
