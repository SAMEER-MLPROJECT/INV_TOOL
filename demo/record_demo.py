#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
import random
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


RNG = random.Random(20261027)
POS = [W / 2, H / 2]


def human_move(page: Page, x: float, y: float) -> None:
    x0, y0 = POS
    dx, dy = x - x0, y - y0
    dist = math.hypot(dx, dy)
    if dist < 3:
        return
    nx, ny = -dy / dist, dx / dist
    bend = RNG.uniform(-0.2, 0.2) * dist
    c1 = (x0 + dx * 0.3 + nx * bend, y0 + dy * 0.3 + ny * bend)
    c2 = (x0 + dx * 0.78 + nx * bend * 0.4, y0 + dy * 0.78 + ny * bend * 0.4)
    over = dist > 260
    k = RNG.uniform(7, 15) if over else 0.0
    tx, ty = x + dx / dist * k, y + dy / dist * k
    n = min(64, int(16 + dist / 20))
    for i in range(1, n + 1):
        t = i / n
        e = t * t * (3 - 2 * t)
        u = 1 - e
        bx = u ** 3 * x0 + 3 * u * u * e * c1[0] + 3 * u * e * e * c2[0] + e ** 3 * tx
        by = u ** 3 * y0 + 3 * u * u * e * c1[1] + 3 * u * e * e * c2[1] + e ** 3 * ty
        page.mouse.move(bx + RNG.uniform(-0.7, 0.7), by + RNG.uniform(-0.7, 0.7))
        page.wait_for_timeout(RNG.randint(5, 10))
    if over:
        page.wait_for_timeout(RNG.randint(50, 110))
        for i in range(1, 7):
            page.mouse.move(tx + (x - tx) * i / 6, ty + (y - ty) * i / 6)
            page.wait_for_timeout(RNG.randint(10, 20))
    POS[0], POS[1] = x, y
    page.wait_for_timeout(RNG.randint(70, 160))


def drift(page: Page, ms: int) -> None:
    left = ms
    while left > 0:
        pause = RNG.randint(500, 1100)
        page.wait_for_timeout(min(pause, left))
        left -= pause
        if left <= 0:
            break
        x, y = POS
        gx, gy = x + RNG.uniform(-14, 14), y + RNG.uniform(-9, 9)
        for i in range(1, 9):
            page.mouse.move(x + (gx - x) * i / 8, y + (gy - y) * i / 8)
            page.wait_for_timeout(22)
        left -= 180
        POS[0], POS[1] = gx, gy


def cap(page: Page, step: str, text: str, hold: float = 3.0) -> None:
    page.evaluate("([s, t]) => window.__caption(s, t)", [step, text])
    drift(page, int(hold * 900))


def target(loc, fx: float = 0.5, fy: float = 0.5):
    b = loc.bounding_box()
    if not b:
        return None
    jx = RNG.uniform(-0.12, 0.12) * b["width"]
    jy = RNG.uniform(-0.18, 0.18) * b["height"]
    return b["x"] + b["width"] * fx + jx, b["y"] + b["height"] * fy + jy


def point_at(page: Page, loc, fx: float = 0.5, fy: float = 0.5) -> None:
    loc.scroll_into_view_if_needed()
    t = target(loc, fx, fy)
    if t:
        human_move(page, *t)


def human_click(page: Page, loc) -> None:
    point_at(page, loc)
    page.wait_for_timeout(RNG.randint(120, 260))
    page.mouse.down()
    page.wait_for_timeout(RNG.randint(60, 120))
    page.mouse.up()
    page.wait_for_timeout(RNG.randint(150, 300))


def reshow_cursor(page: Page) -> None:
    page.mouse.move(POS[0] + 1, POS[1])
    page.mouse.move(POS[0], POS[1])


def open_app(page: Page, base: str, frag: str, wait: str) -> None:
    page.goto(base + "/" + frag)
    page.wait_for_selector(wait, timeout=20000)
    reshow_cursor(page)
    page.wait_for_timeout(700)


def side(page: Page, label: str, wait: str) -> None:
    human_click(page, page.locator("nav[aria-label=Main] a", has_text=label).first)
    page.wait_for_selector(wait, timeout=20000)
    page.wait_for_timeout(800)


def panel(page: Page, title: str):
    return page.locator("section", has=page.locator("h2", has_text=title)).first


def show(page: Page, loc, offset: int = 80) -> None:
    loc.evaluate(f"el => document.querySelector('main').scrollTo({{top: el.getBoundingClientRect().top + "
                 f"document.querySelector('main').scrollTop - {offset}, behavior: 'smooth'}})")
    page.wait_for_timeout(900)


def graph_zoom(page: Page, label: str, step: str, text: str, notches: int = 4, hold: float = 4.0, canvas_index: int = 0) -> None:
    canvas = page.locator(".react-flow").nth(canvas_index)
    node = canvas.locator(".react-flow__node", has_text=label).first
    if node.count() == 0:
        return
    point_at(page, node)
    page.wait_for_timeout(RNG.randint(200, 400))
    done = 0
    while done < notches:
        burst = min(notches - done, RNG.choice((1, 2, 2)))
        for _ in range(burst):
            page.mouse.wheel(0, -RNG.randint(110, 150))
            page.wait_for_timeout(RNG.randint(70, 140))
        done += burst
        page.wait_for_timeout(RNG.randint(220, 420))
    cap(page, step, text, hold)
    fit = canvas.locator(".react-flow__controls-fitview").first
    if fit.count():
        human_click(page, fit)
        page.wait_for_timeout(700)


def pick(page: Page, input_id: str, text: str) -> None:
    human_click(page, page.locator(f"#{input_id}"))
    for ch in text:
        page.keyboard.type(ch)
        page.wait_for_timeout(RNG.randint(55, 150))
    page.wait_for_timeout(RNG.randint(300, 500))
    page.keyboard.press("Enter")
    page.wait_for_timeout(400)


def run(page: Page, base: str) -> None:
    open_app(page, base, "#/settings", "text=Loaded files")
    cap(page, "1 · Open", "AttackGraph Lens turns scattered security telemetry into explainable attack paths.", 3.5)
    human_click(page, page.get_by_role("button", name="Reset to sample dataset"))
    page.wait_for_selector("text=Synthetic sample dataset reloaded.")
    cap(page, "2 · Load", "Seven synthetic source files: identity, EDR, firewall, DNS, database audit, SIEM alerts and asset inventory.", 3)
    files = panel(page, "Loaded files")
    show(page, files)
    human_click(page, files.locator("summary").first)
    point_at(page, files, 0.45, 0.35)
    cap(page, "3 · Validate", "Every file is hashed and validated. Bad rows are rejected with row and reason; duplicates and ID conflicts are flagged.", 4.5)

    side(page, "Live Monitor", "text=Live stream & attack replay")
    human_click(page, page.locator("select").first)
    page.locator("select").first.select_option(index=1)
    spd = page.locator("input[type=number]").first
    human_click(page, spd)
    page.keyboard.press("Control+A")
    for ch in "480":
        page.keyboard.type(ch)
        page.wait_for_timeout(RNG.randint(70, 150))
    cap(page, "Real time", "Live mode: events stream in through the push API and every view updates as the attack unfolds (replay at 480×).", 3)
    human_click(page, page.get_by_role("button", name="Start replay"))
    page.wait_for_selector("text=Streaming", timeout=20000)
    page.wait_for_timeout(2500)
    point_at(page, panel(page, "Live alert feed"), 0.5, 0.3)
    cap(page, "Real time", "Alerts arrive one by one as the intrusion progresses.", 3)
    page.wait_for_selector("text=Replay finished", timeout=90000)
    point_at(page, panel(page, "Live blast radius"), 0.35, 0.65)
    cap(page, "Real time", "The 21:32 bulk read has streamed in. FINANCE-DB is now SUSPECTED and the incident is Critical.", 4.5)
    side(page, "Settings & Data", "text=Loaded files")
    human_click(page, page.get_by_role("button", name="Reset to sample dataset"))
    page.wait_for_selector("text=Synthetic sample dataset reloaded.")

    side(page, "Overview", "text=Highest-priority investigation")
    point_at(page, panel(page, "Highest-priority investigation"), 0.3, 0.25)
    cap(page, "4 · Graph built", "1,191 events become 349 entities and 968 relationships. Top incident: Critical 92.6, with its attack-path hypothesis.", 4)
    md = panel(page, "Behavioural deviations")
    show(page, md)
    point_at(page, md, 0.25, 0.3)
    cap(page, "4 · MD deviation", "Robust Mahalanobis deviation flags the C2 beacon, 412 MB egress and odd-hour logons. Backups deviate too, but stay below the threshold.", 5)

    side(page, "Attack Graph", "text=/\\d+ nodes/")
    page.wait_for_timeout(800)
    cap(page, "4 · Attack graph", "Graph filtered to suspicious relationships. Dashed = inferred via IP-to-host resolution; solid = observed.", 3.5)
    graph_zoom(page, "sameer", "4 · Zoom", "Start of the chain: sameer's off-hours VPN logon to WS-014, then encoded PowerShell.", 4, 4)
    graph_zoom(page, "FINANCE-DB", "4 · Zoom", "End of the chain: SRV-APP-02 reads the crown-jewel FINANCE-DB. The backup server's routes stay separate.", 4, 4)
    human_click(page, page.locator(".react-flow__node", has_text="sameer").first)
    page.wait_for_selector("text=Why it exists")
    point_at(page, page.locator("aside").get_by_text("Why it exists").first, 0.5, 0.5)
    cap(page, "5 · Select entity", "Every node explains why it exists and lists its source records.", 3.5)
    human_click(page, page.get_by_role("button", name="Close inspector"))

    side(page, "Attack Paths", "text=Choose a starting entity")
    pick(page, "path-source", "sameer")
    pick(page, "path-target", "FINANCE-DB")
    human_click(page, page.get_by_role("button", name="Find paths"))
    page.wait_for_selector("text=Hypothesis #1: chronological evidence")
    cap(page, "6 · Attack paths", "Temporal search: each step must happen after the one that enables it. Paths are ranked with a visible score.", 3.5)
    human_click(page, page.locator("li", has_text="powershell.exe#7344 → SRV-APP-02 → FINANCE-DB").first)
    page.wait_for_timeout(700)
    graph_zoom(page, "SRV-APP-02", "6 · Path graph", "Highlighted: the selected hypothesis among all valid paths. Orange = suspicious evidence.", 3, 3.5)
    hyp = panel(page, "chronological evidence")
    show(page, hyp)
    point_at(page, hyp, 0.3, 0.45)
    cap(page, "6 · Hypothesis", "sameer → WS-014 → encoded PowerShell → WinRM to SRV-APP-02 → 48,211-row read of FINANCE-DB, 20:40 to 21:32 UTC.", 5)
    mc = panel(page, "Multichannel corroboration")
    show(page, mc)
    point_at(page, mc, 0.35, 0.5)
    cap(page, "12 · Multichannel", "Which independent channels saw each step: all 4 steps are seen by at least two channels.", 4.5)
    rej = panel(page, "Rejected: temporally impossible")
    show(page, rej)
    point_at(page, rej, 0.3, 0.4)
    cap(page, "6 · Critical thinking", "Routes that exist in the graph but are impossible in time (via the backup server) are rejected, with the reason.", 5)
    show(page, hyp)
    human_click(page, page.get_by_role("button", name="—CONNECTED_TO→").first)
    page.wait_for_selector("text=most suspicious first")
    cap(page, "8 · Evidence", "Click any step: the rule that created it, every supporting record, file, row and why it is suspicious.", 4.5)
    human_click(page, page.locator("aside button", has_text="powershell.exe on WS-014 connected to 10.10.2.12").first)
    page.wait_for_selector("text=Original record (verbatim)")
    page.locator("aside").evaluate("el => el.querySelector('div.overflow-y-auto').scrollTo({top: 560, behavior: 'smooth'})")
    page.wait_for_timeout(900)
    point_at(page, page.locator("aside").get_by_text("Original record (verbatim)").first, 0.5, 2.5)
    cap(page, "8 · Source record", "Down to the original EDR record, verbatim, next to its normalized form.", 4)
    human_click(page, page.get_by_role("button", name="Close inspector"))

    open_app(page, base, "#/blast?entity=user%3Asameer&hops=1&mode=temporal", "text=Critical exposure")
    cap(page, "7 · Blast radius", "Blast radius from sameer, along time-respecting routes after the first suspicious logon.", 3)
    slider = page.get_by_role("slider", name="Hop limit")
    sb = slider.bounding_box()
    if sb:
        human_move(page, sb["x"] + 4, sb["y"] + sb["height"] / 2)
    for h in ("2", "3", "4"):
        if sb:
            human_move(page, sb["x"] + sb["width"] * (int(h) - 1) / 7, sb["y"] + sb["height"] / 2)
        slider.fill(h)
        page.wait_for_timeout(RNG.randint(1000, 1400))
    graph_zoom(page, "FINANCE-DB", "7 · Zoom", "FINANCE-DB is reached at hop 3 through an unbroken suspicious chain: SUSPECTED, never auto-CONFIRMED.", 4, 4)
    point_at(page, panel(page, "Critical exposure"), 0.5, 0.25)
    cap(page, "7 · Exposure", "Critical assets reached and their evidence tier.", 3)
    open_app(page, base, "#/blast?entity=user%3Aa.verma&hops=4&mode=temporal", "text=Critical exposure")
    point_at(page, panel(page, "Critical exposure"), 0.5, 0.55)
    cap(page, "7 · Look-alike", "An IT admin reaches the same database through ordinary activity: POTENTIAL EXPOSURE, not lateral movement.", 4.5)

    side(page, "Incidents", "text=INC-0002")
    human_click(page, page.get_by_text("INC-0002").first)
    page.wait_for_selector("text=Contained with", timeout=20000)
    page.wait_for_timeout(600)
    cap(page, "9 · Incident", "Eight alerts from six independent source systems correlated into one incident.", 3)
    pb = panel(page, "Priority breakdown")
    show(page, pb)
    point_at(page, pb, 0.4, 0.4)
    cap(page, "9 · Priority", "Every point of the score is explained: criticality, suspicion, corroboration, quality, path, recency.", 4)
    cont = panel(page, "Containment planner")
    show(page, cont)
    point_at(page, page.get_by_text("Isolate host WS-014").first)
    cap(page, "11 · Containment", "Act at the first alert (20:41 UTC): the planner simulates every option. Isolating WS-014 alone stops it.", 4.5)
    human_click(page, page.get_by_role("button", name="Simulate 1 action(s)"))
    page.wait_for_selector("text=Prevents reach to")
    point_at(page, page.get_by_text("Prevents reach to").first)
    cap(page, "11 · What-if", "Counterfactual replay: FINANCE-DB, SRV-APP-02 and the service account are no longer reachable.", 4)
    dt = page.locator("input[type=datetime-local]").first
    human_click(page, dt)
    dt.fill("2026-10-27T21:10")
    page.wait_for_timeout(500)
    human_click(page, page.get_by_role("button", name="Plan containment"))
    page.wait_for_selector("text=Contained with 2 action(s)")
    point_at(page, page.locator("ol", has_text="Isolate host WS-014").first, 0.5, 0.8)
    cap(page, "11 · Too late?", "Act 30 minutes later: the service-account credential is already stolen, so its logon to SRV-APP-02 must be blocked too.", 5)
    mi = panel(page, "Multichannel corroboration: incident")
    show(page, mi)
    point_at(page, mi, 0.6, 0.45)
    cap(page, "12 · Multichannel", "Records per channel for every incident entity. '?' marks a channel that should have seen it but stayed silent.", 4.5)
    page.evaluate("document.querySelector('main').scrollTo({top: 0, behavior: 'smooth'})")
    page.wait_for_timeout(800)
    with page.expect_download():
        human_click(page, page.get_by_role("link", name="HTML"))
    cap(page, "10 · Export", "Export the investigation report (HTML, Markdown, JSON). Its SHA-256 is added to the evidence manifest.", 3.5)
    side(page, "Evidence", "text=Evidence hash manifest")
    man = panel(page, "Evidence hash manifest")
    show(page, man)
    point_at(page, man, 0.5, 0.4)
    cap(page, "10 · Manifest", "SHA-256 digests of sources and exports, plus a plain statement of what a hash does not prove.", 4.5)
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
