from __future__ import annotations

import os
import socket
import threading
import time

import pytest

from .conftest import ROOT

pytestmark = pytest.mark.e2e
DIST = ROOT / "frontend" / "dist"
playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def server():
    if not (DIST / "index.html").is_file():
        pytest.skip("frontend not built")
    import uvicorn

    from attackgraph.api.app import create_app
    from attackgraph.config import DeploymentConfig
    from attackgraph.workspace import Workspace

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    ws = Workspace(DeploymentConfig(frontend_dist=DIST, graph_backend="memory", neo4j_uri=None, export_dir=ROOT / "data" / "exports"))
    cfg = uvicorn.Config(create_app(ws), host="127.0.0.1", port=port, log_level="warning")
    srv = uvicorn.Server(cfg)
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    srv.should_exit = True
    t.join(timeout=5)


@pytest.fixture(scope="module")
def page(server):
    with playwright.sync_playwright() as p:
        try:
            browser = p.chromium.launch(executable_path=os.environ.get("AGL_CHROME") or None)
        except Exception as exc:  # pragma: no cover - environment dependent
            pytest.skip(f"no Chromium available: {exc}")
        pg = browser.new_page(viewport={"width": 1500, "height": 950})
        errors: list[str] = []
        pg.on("pageerror", lambda e: errors.append(str(e)))
        pg.errors = errors  # type: ignore[attr-defined]
        yield pg
        browser.close()


def test_overview_to_incident_flow(server, page):
    page.goto(server + "/#/overview")
    page.wait_for_selector("text=Highest-priority investigation")
    assert page.locator("text=LSASS memory dump via comsvcs.dll").first.is_visible()
    page.get_by_role("button", name="Open investigation").click()
    page.wait_for_selector("text=Attack-path hypothesis")
    assert "#/incidents?id=INC-0002" in page.url
    assert page.locator("text=Correlated alerts (8)").is_visible()


def test_path_explorer_finds_and_explains(server, page):
    page.goto(server + "/#/paths?source=user%3Asameer&target=database%3AFINANCE-DB&hops=5")
    page.wait_for_selector("text=Hypothesis #1: chronological evidence")
    assert page.locator("text=Rejected: temporally impossible").is_visible()
    page.get_by_role("button", name="—ACCESSED→").first.click()
    page.wait_for_selector("text=most suspicious first")
    assert page.locator("aside >> text=R-DB-01").first.is_visible()
    page.get_by_role("button", name="Close inspector").click()


def test_blast_radius_hop_slider_updates(server, page):
    page.goto(server + "/#/blast?entity=user%3Asameer&hops=1&mode=temporal")
    page.wait_for_selector("text=Critical exposure")
    one = page.locator("text=/Reachable entities \\(\\d+\\)/").inner_text()
    page.get_by_role("slider", name="Hop limit").fill("4")
    page.wait_for_function("t => !document.body.innerText.includes(t)", arg=one, timeout=10000)
    assert page.locator("text=FINANCE-DB").first.is_visible()


def test_report_download_and_settings(server, page):
    page.goto(server + "/#/incidents?id=INC-0002")
    page.wait_for_selector("text=Attack-path hypothesis")
    with page.expect_download() as dl:
        page.get_by_role("link", name="Markdown").click()
    assert dl.value.suggested_filename == "INC-0002_report.md"
    page.goto(server + "/#/settings")
    page.wait_for_selector("text=Loaded files")
    page.get_by_role("button", name="Check").click()
    page.wait_for_selector("text=Application health")
    assert not page.errors  # type: ignore[attr-defined]


def test_containment_and_multichannel_panels(server, page):
    page.goto(server + "/#/incidents?id=INC-0002")
    page.wait_for_selector("text=Contained with 1 action(s)")
    assert page.locator("text=Isolate host WS-014").first.is_visible()
    page.get_by_role("button", name="Simulate 1 action(s)").click()
    page.wait_for_selector("text=Prevents reach to")
    page.locator("input[type=datetime-local]").first.fill("2026-10-27T21:10")
    page.get_by_role("button", name="Plan containment").click()
    page.wait_for_selector("text=Contained with 2 action(s)")
    assert page.locator("text=Multichannel corroboration: incident entities").is_visible()
    page.goto(server + "/#/paths?source=user%3Asameer&target=database%3AFINANCE-DB&hops=5")
    page.wait_for_selector("text=channel agreement")
    page.goto(server + "/#/overview")
    page.wait_for_selector("text=Behavioural deviations (MD score)")
    assert not page.errors  # type: ignore[attr-defined]


def test_live_replay_updates_the_ui(server, page):
    page.goto(server + "/#/live")
    page.wait_for_selector("text=Live stream & attack replay")
    page.locator("select").first.select_option(index=1)
    page.locator("input[type=number]").first.fill("2000")
    page.get_by_role("button", name="Start replay").click()
    page.wait_for_selector("text=Replay finished", timeout=60000)
    page.wait_for_selector("text=Anomalous bulk read by service account", timeout=10000)
    page.wait_for_selector("li:has-text('FINANCE-DB') >> text=Suspected", timeout=10000)
    page.get_by_role("button", name="Live updates on").first.wait_for(timeout=10000)
    page.goto(server + "/#/settings")
    page.get_by_role("button", name="Reset to sample dataset").click()
    page.wait_for_selector("text=Synthetic sample dataset reloaded.")
    assert not page.errors  # type: ignore[attr-defined]
