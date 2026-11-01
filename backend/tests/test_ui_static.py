"""Automated tests asserting zero-CDN UI compliance, vendor asset presence, and static endpoints."""

import re
from pathlib import Path

import pytest
from app.main import app
from fastapi.testclient import TestClient


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def test_vendor_assets_exist_and_non_empty():
    static_dir = Path(__file__).resolve().parents[1] / "app" / "static" / "vendor"
    assert static_dir.exists(), f"Vendor directory {static_dir} must exist"

    required_assets = ["cytoscape.min.js", "dagre.min.js", "cytoscape-dagre.js"]
    for asset in required_assets:
        file_path = static_dir / asset
        assert file_path.exists(), f"Vendor library {asset} must exist in {static_dir}"
        assert file_path.stat().st_size > 1000, f"Vendor library {asset} must be non-empty (>1KB)"


def test_index_html_has_zero_cdn_references():
    index_path = Path(__file__).resolve().parents[1] / "app" / "static" / "index.html"
    assert index_path.exists(), f"Index HTML {index_path} must exist"

    content = index_path.read_text(encoding="utf-8")

    # Strict check: No external http or https in <script src=...> or <link href=...>
    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', content, re.IGNORECASE)
    link_hrefs = re.findall(r'<link[^>]+href=["\']([^"\']+)["\']', content, re.IGNORECASE)

    for src in script_srcs:
        assert not src.startswith("http://") and not src.startswith("https://"), (
            f"Zero-CDN violation in <script src>: {src}"
        )

    for href in link_hrefs:
        assert not href.startswith("http://") and not href.startswith("https://"), (
            f"Zero-CDN violation in <link href>: {href}"
        )


def test_static_routes_served_via_fastapi(client: TestClient):
    # Root index
    root_resp = client.get("/")
    assert root_resp.status_code == 200
    assert "CaseFile" in root_resp.text
    assert "Zero-CDN" in root_resp.text or "/vendor/" in root_resp.text

    # Vendor JS files
    cy_resp = client.get("/vendor/cytoscape.min.js")
    assert cy_resp.status_code == 200
    assert len(cy_resp.content) > 50000

    dagre_resp = client.get("/vendor/dagre.min.js")
    assert dagre_resp.status_code == 200
    assert len(dagre_resp.content) > 50000

    cy_dagre_resp = client.get("/vendor/cytoscape-dagre.js")
    assert cy_dagre_resp.status_code == 200
    assert len(cy_dagre_resp.content) > 5000
