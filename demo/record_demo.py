#!/usr/bin/env python3
"""Record the demo video by driving the REAL running application in Chromium (Playwright).

Everything shown is live software output from the API on the synthetic dataset. The script
adds only presentation aids: a narration caption (labelled as such), a visible cursor, and
presenter-style zooms (graph zoom with the mouse wheel; CSS magnification of a region, like a
screen recorder's zoom). No frame is mocked or edited.

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
// visible presenter cursor (headless recordings have none); follows real mouse events
window.addEventListener('DOMContentLoaded', () => {
  const c = document.createElement('div');
  c.id = '__demo_cursor';
  c.innerHTML = '<svg width="26" height="26" viewBox="0 0 24 24"><path d="M4 2l15 9-7 1.5L8.5 20z" fill="#fff" stroke="#0c0e12" stroke-width="1.4" stroke-linejoin="round"/></svg>';
  c.style.cssText = 'position:fixed;left:-50px;top:-50px;z-index:100000;pointer-events:none;filter:drop-shadow(0 2px 4px rgba(0,0,0,.6))';
  document.body.appendChild(c);
  const ring = document.createElement('div');
  ring.style.cssText = 'position:fixed;width:34px;height:34px;margin:-17px 0 0 -17px;border-radius:50%;border:2px solid #7cc4ff;' +
    'z-index:99999;pointer-events:none;opacity:0;transition:opacity .4s, transform .4s;transform:scale(.4)';
  document.body.appendChild(ring);
  document.addEventListener('mousemove', e => { c.style.left = (e.clientX - 3) + 'px'; c.style.top = (e.clientY - 2) + 'px'; }, true);
  document.addEventListener('mousedown', e => {
    ring.style.left = e.clientX + 'px'; ring.style.top = e.clientY + 'px';
    ring.style.transition = 'none'; ring.style.opacity = '1'; ring.style.transform = 'scale(.4)';
    requestAnimationFrame(() => { ring.style.transition = 'opacity .5s, transform .5s'; ring.style.opacity = '0'; ring.style.transform = 'scale(1.6)'; });
  }, true);
});
"""


def cap(page: Page, step: str, text: str, hold: float = 3.0) -> None:
    page.evaluate("([s, t]) => window.__caption(s, t)", [step, text])
    page.wait_for_timeout(int(hold * 1250))  # paced for narration


def nav(page: Page, base: str, frag: str, wait: str) -> None:
    page.goto(base + "/" + frag)
    page.wait_for_selector(wait, timeout=20000)
    page.wait_for_timeout(700)


def glide(page: Page, x: float, y: float, steps: int = 28) -> None:
    """Move the visible cursor smoothly, like a presenter's hand."""
    page.mouse.move(x, y, steps=steps)
    page.wait_for_timeout(150)


def human_click(page: Page, loc) -> None:
    loc.scroll_into_view_if_needed()
    b = loc.bounding_box()
    if b:
        glide(page, b["x"] + b["width"] / 2, b["y"] + b["height"] / 2)
        page.wait_for_timeout(250)
    loc.click()


def panel(page: Page, title: str):
    return page.locator("section", has=page.locator("h2", has_text=title)).first


def show(page: Page, loc, offset: int = 80) -> None:
    """Scroll the main pane so that ``loc`` sits near the top of the screen."""
    loc.evaluate(f"el => document.querySelector('main').scrollTo({{top: el.getBoundingClientRect().top + "
                 f"document.querySelector('main').scrollTop - {offset}, behavior: 'smooth'}})")
    page.wait_for_timeout(700)


def zoom_on(page: Page, loc, step: str, text: str, hold: float = 4.0, max_scale: float = 2.0) -> None:
    """Screen-recorder style close-up: magnify the region around ``loc``, narrate, then zoom back out."""
    b = loc.bounding_box()
    if not b:
        return
    cx, cy = b["x"] + b["width"] / 2, b["y"] + b["height"] / 2
    scale = max(1.25, min(max_scale, 0.92 * W / b["width"], 0.78 * H / b["height"]))
    glide(page, cx, cy, steps=20)
    page.evaluate("""([cx, cy, s]) => { const r = document.getElementById('root');
        r.style.transition = 'transform 900ms cubic-bezier(.2,.8,.2,1)'; r.style.transformOrigin = cx + 'px ' + cy + 'px';
        r.style.transform = 'scale(' + s + ')'; }""", [cx, cy, scale])
    page.wait_for_timeout(950)
    cap(page, step, text, hold)
    page.evaluate("() => { document.getElementById('root').style.transform = 'scale(1)'; }")
    page.wait_for_timeout(950)


def graph_zoom(page: Page, label: str, step: str, text: str, notches: int = 4, hold: float = 4.0, canvas_index: int = 0) -> None:
    """Zoom the interactive graph itself (mouse wheel at a node, as a person would), then fit it back."""
    canvas = page.locator(".react-flow").nth(canvas_index)
    node = canvas.locator(".react-flow__node", has_text=label).first
    if node.count() == 0:
        return
    node.scroll_into_view_if_needed()
    b = node.bounding_box()
    if not b:
        return
    glide(page, b["x"] + b["width"] / 2, b["y"] + b["height"] / 2)
    for _ in range(notches):
        page.mouse.wheel(0, -160)
        page.wait_for_timeout(260)
    page.wait_for_timeout(500)
    cap(page, step, text, hold)
    fit = canvas.locator(".react-flow__controls-fitview").first
    if fit.count():
        human_click(page, fit)
        page.wait_for_timeout(700)


def pick(page: Page, input_id: str, text: str) -> None:
    human_click(page, page.locator(f"#{input_id}"))
    page.keyboard.type(text, delay=60)
    page.wait_for_timeout(400)
    page.keyboard.press("Enter")
    page.wait_for_timeout(400)


def run(page: Page, base: str) -> None:
    glide(page, W / 2, H / 2, steps=2)
    # 1-3 · load and validate -------------------------------------------------------------
    nav(page, base, "#/settings", "text=Loaded files")
    cap(page, "1 · Open", "AttackGraph Lens: a graph engine that turns scattered security telemetry into explainable attack paths.", 3.5)
    human_click(page, page.get_by_role("button", name="Reset to sample dataset"))
    page.wait_for_selector("text=Synthetic sample dataset reloaded.")
    cap(page, "2 · Load", "Seven synthetic source files: identity, EDR, firewall, DNS, database audit, SIEM alerts and asset inventory.", 3)
    files = panel(page, "Loaded files")
    show(page, files)
    human_click(page, files.locator("summary").first)
    zoom_on(page, files, "3 · Validate", "Every file is hashed and validated: bad rows rejected with row and reason, duplicates and ID conflicts flagged.", 4.5, 1.6)

    # real time ------------------------------------------------------------------------------
    nav(page, base, "#/live", "text=Live stream & attack replay")
    page.locator("select").first.select_option(index=1)
    cap(page, "Real time", "Live mode: events stream in through the push API; every view updates as the attack unfolds (replay at 240×).", 3)
    human_click(page, page.get_by_role("button", name="Start replay"))
    page.wait_for_selector("text=Streaming", timeout=20000)
    page.wait_for_timeout(5000)
    zoom_on(page, panel(page, "Live alert feed"), "Real time", "Alerts arrive one by one as the intrusion progresses.", 3.5, 1.7)
    page.wait_for_selector("text=Replay finished", timeout=90000)
    zoom_on(page, panel(page, "Live blast radius"), "Real time",
            "The 21:32 bulk read has streamed in: FINANCE-DB is now SUSPECTED and the incident is Critical.", 4.5, 1.8)
    nav(page, base, "#/settings", "text=Loaded files")
    human_click(page, page.get_by_role("button", name="Reset to sample dataset"))
    page.wait_for_selector("text=Synthetic sample dataset reloaded.")

    # 4 · overview and MD ---------------------------------------------------------------------
    nav(page, base, "#/overview", "text=Highest-priority investigation")
    cap(page, "4 · Graph built", "1,191 events become 349 entities and 968 time-stamped relationships; 4 candidate incidents are ranked.", 3.5)
    zoom_on(page, panel(page, "Highest-priority investigation"), "4 · Top incident",
            "Critical 92.6 — identities, affected assets and the attack-path hypothesis at a glance.", 4, 1.7)
    md = panel(page, "Behavioural deviations")
    show(page, md)
    zoom_on(page, md, "4 · MD deviation",
            "Robust Mahalanobis deviation: C2 beacon, 412 MB egress, odd-hour logons. Backups deviate too — but stay below the threshold.", 5, 1.5)

    # 4-5 · graph ------------------------------------------------------------------------------
    nav(page, base, "#/graph", "text=/\\d+ nodes/")
    page.wait_for_timeout(800)
    cap(page, "4 · Attack graph", "Graph filtered to suspicious relationships. Dashed = inferred via IP-to-host resolution; solid = observed.", 3.5)
    graph_zoom(page, "sameer", "4 · Zoom", "Start of the chain: sameer's off-hours VPN logon to WS-014, then encoded PowerShell.", 4, 4)
    graph_zoom(page, "FINANCE-DB", "4 · Zoom", "End of the chain: SRV-APP-02 reads the crown-jewel FINANCE-DB; the backup server's routes stay separate.", 4, 4)
    human_click(page, page.locator(".react-flow__node", has_text="sameer").first)
    page.wait_for_selector("text=Why it exists")
    zoom_on(page, page.locator("aside"), "5 · Select entity", "Every node explains why it exists and lists its source records.", 3.5, 1.4)
    human_click(page, page.get_by_role("button", name="Close inspector"))

    # 6 · attack paths -----------------------------------------------------------------------------
    nav(page, base, "#/paths", "text=Choose a starting entity")
    pick(page, "path-source", "sameer")
    pick(page, "path-target", "FINANCE-DB")
    human_click(page, page.get_by_role("button", name="Find paths"))
    page.wait_for_selector("text=Hypothesis #1: chronological evidence")
    cap(page, "6 · Attack paths", "Temporal search: each step must happen after the one that enables it; paths are ranked with a visible score.", 3.5)
    human_click(page, page.locator("li", has_text="powershell.exe#7344 → SRV-APP-02 → FINANCE-DB").first)
    page.wait_for_timeout(700)
    graph_zoom(page, "SRV-APP-02", "6 · Path graph", "Highlighted: the selected hypothesis among all valid paths; orange = suspicious evidence.", 3, 3.5)
    hyp = panel(page, "chronological evidence")
    show(page, hyp)
    zoom_on(page, hyp, "6 · Hypothesis",
            "sameer → WS-014 → encoded PowerShell → WinRM to SRV-APP-02 → 48,211-row read of FINANCE-DB, 20:40–21:32 UTC.", 5, 1.6)
    mc = panel(page, "Multichannel corroboration")
    show(page, mc)
    zoom_on(page, mc, "12 · Multichannel", "Signature view: which independent channels saw each step — 5 of 6 channels corroborate.", 4.5, 1.6)
    rej = panel(page, "Rejected: temporally impossible")
    show(page, rej)
    zoom_on(page, rej, "6 · Critical thinking", "Routes that exist in the graph but are impossible in time (via the backup server) are rejected with the reason.", 5, 1.8)
    show(page, hyp)
    human_click(page, page.get_by_role("button", name="—CONNECTED_TO→").first)
    page.wait_for_selector("text=most suspicious first")
    zoom_on(page, page.locator("aside"), "8 · Evidence", "Click any step: creating rule, every supporting record, file, row and why it is suspicious.", 4.5, 1.4)
    human_click(page, page.locator("aside button", has_text="powershell.exe on WS-014 connected to 10.10.2.12").first)
    page.wait_for_selector("text=Original record (verbatim)")
    page.locator("aside").evaluate("el => el.querySelector('div.overflow-y-auto').scrollTo({top: 560, behavior: 'smooth'})")
    page.wait_for_timeout(800)
    zoom_on(page, page.locator("aside"), "8 · Source record", "Down to the original EDR record, verbatim, beside its normalized form.", 4, 1.4)
    human_click(page, page.get_by_role("button", name="Close inspector"))

    # 7 · blast radius -----------------------------------------------------------------------------
    nav(page, base, "#/blast?entity=user%3Asameer&hops=1&mode=temporal", "text=Critical exposure")
    cap(page, "7 · Blast radius", "Blast radius from sameer, along time-respecting routes after the first suspicious logon.", 3)
    slider = page.get_by_role("slider", name="Hop limit")
    sb = slider.bounding_box()
    for h in ("2", "3", "4"):
        if sb:
            glide(page, sb["x"] + sb["width"] * (int(h) - 1) / 7, sb["y"] + sb["height"] / 2, steps=12)
        slider.fill(h)
        page.wait_for_timeout(1200)
    graph_zoom(page, "FINANCE-DB", "7 · Zoom", "FINANCE-DB at hop 3 through an unbroken suspicious chain: SUSPECTED, never auto-CONFIRMED.", 4, 4)
    zoom_on(page, panel(page, "Critical exposure"), "7 · Exposure", "Critical assets reached and their evidence tier.", 3.5, 1.8)
    nav(page, base, "#/blast?entity=user%3Aa.verma&hops=4&mode=temporal", "text=Critical exposure")
    zoom_on(page, panel(page, "Critical exposure"), "7 · Look-alike",
            "An IT admin reaches the same database by ordinary activity: POTENTIAL EXPOSURE, not lateral movement.", 4.5, 1.8)

    # 9-11 · incident, containment ----------------------------------------------------------------
    nav(page, base, "#/incidents?id=INC-0002", "text=Contained with")
    cap(page, "9 · Incident", "Eight alerts from six independent source systems correlated into one incident.", 3)
    zoom_on(page, panel(page, "Priority breakdown"), "9 · Priority", "Every point of the score is explained: criticality, suspicion, corroboration, quality, path, recency.", 4, 1.7)
    cont = panel(page, "Containment planner")
    show(page, cont)
    zoom_on(page, cont, "11 · Containment", "Act at the first alert (20:41 UTC): the planner simulates every option — isolating WS-014 alone stops it.", 4.5, 1.5)
    human_click(page, page.get_by_role("button", name="Simulate 1 action(s)"))
    page.wait_for_selector("text=Prevents reach to")
    zoom_on(page, page.locator("text=Prevents reach to").locator("xpath=ancestor::div[contains(@class,'rounded-md')][1]"),
            "11 · What-if", "Counterfactual replay: FINANCE-DB, SRV-APP-02 and the service account are no longer reachable.", 4, 1.9)
    human_click(page, page.locator("input[type=datetime-local]").first)
    page.locator("input[type=datetime-local]").first.fill("2026-10-27T21:10")
    human_click(page, page.get_by_role("button", name="Plan containment"))
    page.wait_for_selector("text=Contained with 2 action(s)")
    zoom_on(page, page.locator("ol", has_text="Isolate host WS-014").first, "11 · Too late?",
            "Act 30 min later: the service-account credential is already stolen, so its logon to SRV-APP-02 must be blocked too.", 5, 2.0)
    mi = panel(page, "Multichannel corroboration: incident")
    show(page, mi)
    zoom_on(page, mi, "12 · Multichannel", "Records per channel for every incident entity; '?' marks a channel that should have seen it but stayed silent.", 4.5, 1.5)
    page.evaluate("document.querySelector('main').scrollTo({top: 0, behavior: 'smooth'})")
    page.wait_for_timeout(700)
    with page.expect_download():
        human_click(page, page.get_by_role("link", name="HTML"))
    cap(page, "10 · Export", "Export the investigation report (HTML, Markdown, JSON); its SHA-256 is added to the evidence manifest.", 3.5)
    nav(page, base, "#/evidence", "text=Evidence hash manifest")
    man = panel(page, "Evidence hash manifest")
    show(page, man)
    zoom_on(page, man, "10 · Manifest", "SHA-256 digests of sources and exports — and an explicit statement of what a hash does not prove.", 4.5, 1.5)
    cap(page, "AttackGraph Lens", "Real-time attack paths · blast radius · one incident picture · containment · evidence for every conclusion.", 4)


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
