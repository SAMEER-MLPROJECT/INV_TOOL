#!/usr/bin/env python3
"""Capture real screenshots of the running application with Playwright (Chromium).

    python -m attackgraph serve &                       # from backend/
    python scripts/capture_screenshots.py [--base http://127.0.0.1:8000] [--out docs/screenshots]

Each screenshot is of the live UI driven by the real API on the synthetic dataset.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from playwright.sync_api import sync_playwright

SHOTS = [
    ("01_overview", "#/overview", None),
    ("02_attack_graph", "#/graph", None),
    ("03_attack_paths", "#/paths?source=user%3Asameer&target=database%3AFINANCE-DB&hops=5", "text=Hypothesis #1"),
    ("04_blast_radius", "#/blast?entity=user%3Asameer&hops=4&mode=temporal", "text=Critical exposure"),
    ("05_blast_radius_benign_admin", "#/blast?entity=user%3Aa.verma&hops=4&mode=temporal", "text=Critical exposure"),
    ("06_incident", "#/incidents?id=INC-0002", "text=Attack-path hypothesis"),
    ("07_evidence_centre", "#/evidence", "text=Evidence hash manifest"),
    ("08_settings_data", "#/settings", "text=Loaded files"),
]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000/")
    ap.add_argument("--out", type=Path, default=Path(__file__).resolve().parents[1] / "docs" / "screenshots")
    ap.add_argument("--chrome", default=None, help="path to a Chrome/Chromium binary (optional)")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=args.chrome) if args.chrome else p.chromium.launch()
        page = browser.new_page(viewport={"width": 1600, "height": 1000}, device_scale_factor=1)
        for name, frag, wait_for in SHOTS:
            page.goto(args.base.rstrip("/") + "/" + frag)
            page.wait_for_load_state("networkidle")
            if wait_for:
                page.wait_for_selector(wait_for, timeout=15000)
            page.wait_for_timeout(900)  # graph fit-view animation
            page.screenshot(path=str(args.out / f"{name}.png"), full_page=False)
            print("saved", name)
        # evidence inspector on the lateral-movement relationship
        page.goto(args.base.rstrip("/") + "/#/paths?source=user%3Asameer&target=database%3AFINANCE-DB&hops=5")
        page.wait_for_selector("text=Hypothesis #1", timeout=15000)
        page.get_by_role("button", name="—ACCESSED→").first.click()
        page.wait_for_selector("text=most suspicious first", timeout=10000)
        page.wait_for_timeout(400)
        page.screenshot(path=str(args.out / "09_evidence_inspector.png"))
        print("saved 09_evidence_inspector")
        # signature features
        page.get_by_role("button", name="Close inspector").click()
        page.goto(args.base.rstrip("/") + "/#/incidents?id=INC-0002")
        page.wait_for_selector("text=Contained with", timeout=20000)
        scroll_to = ("h => document.querySelector('main').scrollTo(0, [...document.querySelectorAll('h2')].find(x => "
                     "x.textContent.includes(h)).getBoundingClientRect().top + document.querySelector('main').scrollTop - 70)")
        page.locator("input[type=datetime-local]").first.fill("2026-10-27T21:10")
        page.get_by_role("button", name="Plan containment").click()
        page.wait_for_selector("text=Contained with 2 action(s)", timeout=20000)
        page.get_by_role("button", name="Simulate 2 action(s)").click()
        page.wait_for_selector("text=Prevents reach to", timeout=20000)
        page.evaluate(scroll_to, "Containment")
        page.wait_for_timeout(500)
        page.screenshot(path=str(args.out / "10_containment_whatif.png"))
        page.evaluate(scroll_to, "Multichannel corroboration: incident")
        page.wait_for_timeout(500)
        page.screenshot(path=str(args.out / "11_multichannel.png"))
        page.goto(args.base.rstrip("/") + "/#/overview")
        page.wait_for_selector("text=Behavioural deviations (MD score)", timeout=20000)
        page.evaluate(scroll_to, "Behavioural")
        page.wait_for_timeout(500)
        page.screenshot(path=str(args.out / "12_md_deviation.png"))
        print("saved 10-12 signature features")
        browser.close()


if __name__ == "__main__":
    main()
