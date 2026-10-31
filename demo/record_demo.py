#!/usr/bin/env python3
"""Record the demo video by driving the REAL running application in Chromium (Playwright).

Everything shown is live software output from the API on the synthetic dataset. The only
addition is a caption bar injected by this script to narrate each step (it is visibly
labelled as a narration caption). No frame is mocked or edited.

    cd backend && python -m attackgraph serve &           # start the app
    python demo/record_demo.py --chrome /usr/bin/google-chrome
    # -> demo/attackgraph_lens_demo.webm (+ .mp4 if ffmpeg is installed)
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import time
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

HERE = Path(__file__).resolve().parent
W, H = 1600, 900

CAPTION_JS = """
window.__caption = (step, text) => {
  let el = document.getElementById('__demo_caption');
  if (!el) {
    el = document.createElement('div');
    el.id = '__demo_caption';
    el.style.cssText = 'position:fixed;left:50%;bottom:22px;transform:translateX(-50%);z-index:99999;max-width:1100px;' +
      'background:rgba(12,14,18,.94);border:1px solid #7cc4ff;color:#e2e6eb;padding:10px 18px;border-radius:8px;' +
      'font:500 16px Inter Variable,system-ui,sans-serif;box-shadow:0 8px 30px rgba(0,0,0,.6);pointer-events:none';
    document.body.appendChild(el);
  }
  el.innerHTML = '<span style="color:#7cc4ff;font-weight:700;margin-right:10px">' + step + '</span>' + text +
    '<span style="display:block;font-size:10px;color:#6c7685;margin-top:2px">narration caption added by the recording script</span>';
};
"""


def cap(page: Page, step: str, text: str, hold: float = 3.0) -> None:
    page.evaluate("([s, t]) => window.__caption(s, t)", [step, text])
    page.wait_for_timeout(int(hold * 1450))  # paced for narration


def nav(page: Page, base: str, frag: str, wait: str) -> None:
    page.goto(base + "/" + frag)
    page.wait_for_selector(wait, timeout=20000)
    page.wait_for_timeout(700)


def pick(page: Page, input_id: str, text: str) -> None:
    page.click(f"#{input_id}")
    page.keyboard.type(text, delay=60)
    page.wait_for_timeout(400)
    page.keyboard.press("Enter")
    page.wait_for_timeout(400)


def run(page: Page, base: str) -> None:
    nav(page, base, "#/settings", "text=Loaded files")
    cap(page, "1 · Open", "AttackGraph Lens: a graph engine that turns scattered security telemetry into explainable attack paths.", 4)
    page.get_by_role("button", name="Reset to sample dataset").click()
    page.wait_for_selector("text=Synthetic sample dataset reloaded.")
    cap(page, "2 · Load", "Load seven synthetic source files: identity, EDR, firewall, DNS, database audit, SIEM alerts and asset inventory.", 4)
    page.mouse.wheel(0, 900)
    cap(page, "3 · Validate", "Every file is hashed and validated: invalid rows are rejected with reasons, duplicates and ID conflicts are flagged.", 5)

    nav(page, base, "#/overview", "text=Highest-priority investigation")
    cap(page, "4 · Graph built", "1,191 events become 349 entities and 968 time-stamped relationships; 4 candidate incidents are ranked.", 5)

    nav(page, base, "#/graph", "text=/\\d+ nodes/")
    cap(page, "4 · Attack graph", "Graph filtered to suspicious relationships. Dashed edges are inferred via IP-to-host resolution; solid edges are observed.", 5)
    page.get_by_text("sameer", exact=True).first.click()
    page.wait_for_selector("text=Why it exists")
    cap(page, "5 · Select entity", "Select the suspected compromised identity sameer: every node shows why it exists and its source records.", 4)
    page.get_by_role("button", name="Close inspector").click()

    nav(page, base, "#/paths", "text=Choose a starting entity")
    pick(page, "path-source", "sameer")
    pick(page, "path-target", "FINANCE-DB")
    page.get_by_role("button", name="Find paths").click()
    page.wait_for_selector("text=Hypothesis #1: chronological evidence")
    cap(page, "6 · Attack paths", "Temporal search finds paths where each step happens after the one that enables it, ranked with a visible score.", 5)
    page.locator("li", has_text="powershell.exe#7344 → SRV-APP-02 → FINANCE-DB").first.click()
    page.wait_for_timeout(600)
    page.mouse.wheel(0, 650)
    cap(page, "6 · Hypothesis", "Identity → workstation → encoded PowerShell → WinRM to SRV-APP-02 → 48,211-row read of FINANCE-DB, 20:40–21:32 UTC.", 6)
    page.mouse.wheel(0, 1400)
    cap(page, "6 · Critical thinking", "Routes that exist in the graph but are impossible in time (via the backup server) are rejected with the reason.", 5)
    page.mouse.wheel(0, -2400)
    page.get_by_role("button", name="—CONNECTED_TO→").first.click()
    page.wait_for_selector("text=most suspicious first")
    cap(page, "8 · Evidence", "Click any step: the rule that created the edge, every supporting record, its file, row and suspicion source.", 5)
    page.locator("aside button", has_text="powershell.exe on WS-014 connected to 10.10.2.12").first.click()
    page.wait_for_selector("text=Original record (verbatim)")
    page.locator("aside").evaluate("el => el.querySelector('div.overflow-y-auto').scrollTo(0, 600)")
    cap(page, "8 · Source record", "Down to the original EDR record, verbatim, beside its normalized form.", 5)
    page.get_by_role("button", name="Close inspector").click()

    nav(page, base, "#/blast?entity=user%3Asameer&hops=1&mode=temporal", "text=Critical exposure")
    cap(page, "7 · Blast radius", "Blast radius from sameer, counted only along time-respecting routes after the first suspicious logon.", 4)
    slider = page.get_by_role("slider", name="Hop limit")
    for h in ("2", "3", "4"):
        slider.fill(h)
        page.wait_for_timeout(1300)
    cap(page, "7 · Blast radius", "At 4 hops FINANCE-DB is reached through an unbroken suspicious chain: SUSPECTED, never auto-CONFIRMED.", 6)
    nav(page, base, "#/blast?entity=user%3Aa.verma&hops=4&mode=temporal", "text=Critical exposure")
    cap(page, "7 · Look-alike", "An IT admin reaches the same database by ordinary activity: POTENTIAL EXPOSURE, not lateral movement.", 6)

    nav(page, base, "#/incidents?id=INC-0002", "text=Attack-path hypothesis")
    cap(page, "9 · Incident", "Eight alerts from six independent source systems correlated into one incident, with the priority breakdown.", 6)
    page.mouse.wheel(0, 1100)
    cap(page, "9 · Correlation", "Each grouping link cites its rule (shared entity, graph adjacency or explicit evidence reference).", 5)
    page.mouse.wheel(0, 900)
    cap(page, "9 · Timeline", "One chronological picture of the intrusion built from scattered records.", 4)
    page.mouse.wheel(0, -3000)
    with page.expect_download():
        page.get_by_role("link", name="HTML").click()
    cap(page, "10 · Export", "Export the investigation report (HTML, Markdown, JSON); its SHA-256 is added to the evidence manifest.", 4)
    nav(page, base, "#/evidence", "text=Evidence hash manifest")
    page.mouse.wheel(0, 700)
    cap(page, "10 · Manifest", "Source files and exported reports with SHA-256 digests, and an explicit statement of what a hash does not prove.", 6)
    cap(page, "AttackGraph Lens", "Temporal attack paths · blast radius · correlated incidents · evidence for every conclusion.", 4)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--chrome", default=None)
    ap.add_argument("--out", type=Path, default=HERE / "attackgraph_lens_demo")
    a = ap.parse_args()
    vid_dir = HERE / "_video_tmp"
    shutil.rmtree(vid_dir, ignore_errors=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=a.chrome) if a.chrome else p.chromium.launch()
        ctx = browser.new_context(viewport={"width": W, "height": H}, record_video_dir=str(vid_dir),
                                  record_video_size={"width": W, "height": H}, accept_downloads=True)
        ctx.add_init_script(CAPTION_JS)
        page = ctx.new_page()
        t = time.time()
        run(page, a.base.rstrip("/"))
        video = page.video.path()
        ctx.close()
        browser.close()
    webm = a.out.with_suffix(".webm")
    shutil.move(video, webm)
    shutil.rmtree(vid_dir, ignore_errors=True)
    print(f"recorded {time.time() - t:.0f}s -> {webm}")
    if shutil.which("ffmpeg"):
        mp4 = a.out.with_suffix(".mp4")
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(webm), "-c:v", "libx264", "-preset", "veryfast",
                        "-crf", "26", "-pix_fmt", "yuv420p", "-movflags", "+faststart", str(mp4)], check=True)
        print(f"converted -> {mp4}")


if __name__ == "__main__":
    main()
