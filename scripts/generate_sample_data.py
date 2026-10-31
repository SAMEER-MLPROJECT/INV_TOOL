#!/usr/bin/env python3
"""Generate the AttackGraph Lens synthetic enterprise dataset.

Fictional organisation "Northwind Analytics" (all names, hosts and addresses invented).
Internal addresses use RFC 1918 space; "internet" addresses use the RFC 5737
documentation ranges and domains use the reserved ``.example`` TLD, so no real system is
referenced.

Deterministic: fixed seed and fixed clock, so the output is byte-identical on every run.

    python scripts/generate_sample_data.py            # writes data/sample/
    python scripts/generate_sample_data.py --out DIR

Scenarios (see data/sample/EXPECTED_OUTCOMES.md):
  S1 routine authentication, process, DNS, web, database and backup activity
  S2 suspicious account activity (failed logons then a 02:10 IST logon for sameer)
  S3 lateral movement WS-014 -> SRV-APP-02 with a dumped service-account credential
  S4 critical database exposure (bulk read of FINANCE-DB) and exfiltration
  S5 incomplete / conflicting evidence (unmanaged IP, EDR-only signal, bad records)
  plus benign look-alikes: admin jump-host use, nightly backup, authorised scanner.
"""
from __future__ import annotations

import argparse
import csv
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEED = 20261027
T0 = datetime(2026, 10, 26, 0, 0, tzinfo=timezone.utc)  # dataset start (Monday 05:30 IST)
DAYS = 3
END = datetime(2026, 10, 28, 13, 0, tzinfo=timezone.utc)
ATTACK = datetime(2026, 10, 27, 20, 31, tzinfo=timezone.utc)  # 02:01 IST on 28 Oct

rng = random.Random(SEED)

FIRST = ["aarav", "bhavna", "chirag", "deepa", "eshan", "farah", "gaurav", "hema", "ishaan", "jaya",
         "kabir", "lata", "manav", "neha", "omkar", "priya", "qadir", "riya", "sahil", "tara",
         "uday", "vani", "yash", "zoya"]
LAST = ["sharma", "iyer", "kapoor", "das", "menon", "khan", "bose", "pillai", "joshi", "rao",
        "sethi", "nair", "gill", "bhat", "kulkarni", "reddy", "ansari", "nair", "saxena", "dutta",
        "patil", "rao", "verma", "mirza"]

USERS: dict[str, dict] = {}
for i, (f, l) in enumerate(zip(FIRST, LAST), start=1):
    USERS[f"{f[0]}.{l}"] = {"ws": f"WS-{i:03d}", "dept": "finance" if i in (4, 9, 14, 17, 20) else ("hr" if i in (8, 12) else "staff")}


def assign(user: str, ws: str, dept: str) -> None:
    """Give ``ws`` to ``user`` (scenario roles), keeping one owner per workstation."""
    for other in [u for u, v in USERS.items() if v["ws"] == ws or u == user]:
        del USERS[other]
    USERS[user] = {"ws": ws, "dept": dept}


assign("a.verma", "WS-001", "it_admin")  # IT administrator (benign jump-host user)
assign("sameer", "WS-014", "finance")  # account compromised in S2
assign("r.nair", "WS-022", "staff")  # EDR-only signal in S5

SERVERS = {
    "DC-01": ("10.10.0.10", "domain_controller", 5),
    "VPN-01": ("10.10.0.5", "network_device", 3),
    "FS-01": ("10.10.0.20", "server", 3),
    "APP-01": ("10.10.2.11", "server", 4),
    "SRV-APP-02": ("10.10.2.12", "server", 4),
    "BKP-01": ("10.10.2.30", "server", 4),
    "WEB-01": ("10.10.2.40", "server", 2),
    "JUMP-01": ("10.10.3.5", "server", 4),
    "SCN-01": ("10.10.3.50", "server", 2),
}
DATABASES = {"FINANCE-DB": ("10.10.4.10", 5), "HR-DB": ("10.10.4.11", 4), "CRM-DB": ("10.10.4.12", 3)}
C2_IP, C2_DOMAIN = "203.0.113.45", "telemetry-cdn-sync.example"
UNKNOWN_IP = "10.10.9.77"
BENIGN_SITES = {"portal.northwind.example": "198.51.100.20", "mail.northwind.example": "198.51.100.21",
                "docs.vendor-suite.example": "198.51.100.34", "updates.os-vendor.example": "198.51.100.50",
                "news.example": "198.51.100.77"}


def ws_ip(ws: str) -> str:
    return f"10.10.1.{int(ws.split('-')[1])}"


class Sink:
    def __init__(self) -> None:
        self.auth, self.edr, self.fw, self.dns, self.db, self.alerts = [], [], [], [], [], []
        self.n = {"AUTH": 0, "EDR": 0, "FW": 0, "DNS": 0, "DB": 0, "ALR": 0}
        self.pid = 4000

    def next_id(self, prefix: str) -> str:
        self.n[prefix] += 1
        return f"{prefix}-{self.n[prefix]:06d}" if prefix != "ALR" else f"ALR-{self.n[prefix]:04d}"

    def next_pid(self) -> str:
        self.pid += rng.randint(3, 41)
        return str(self.pid)

    # --- emitters -----------------------------------------------------------
    def logon(self, t, user, dst, src=None, kind="interactive", result="success", user_fmt=None):
        eid = self.next_id("AUTH")
        self.auth.append({"event_id": eid, "time": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
                          "user": user_fmt or f"NORTHWIND\\{user}", "src_host": src or dst,
                          "dst_host": f"{dst.lower()}.corp.local" if rng.random() < 0.3 else dst,
                          "logon_type": kind, "result": result,
                          "auth_package": "Kerberos" if kind != "interactive" else "Negotiate"})
        return eid

    def proc(self, t, host, user, image, parent=None, ppid=None, pid=None, cmd=None, sev="info"):
        eid = self.next_id("EDR")
        pid = pid or self.next_pid()
        rec = {"id": eid, "ts": t.isoformat().replace("+00:00", "Z"), "host": host, "user": user,
               "event_type": "process_start", "image": f"C:\\Windows\\System32\\{image}" if image in SYS else f"C:\\Program Files\\{image}",
               "pid": pid, "cmdline": cmd or image, "severity": sev}
        if parent:
            rec["parent_image"] = parent
            rec["parent_pid"] = ppid
        self.edr.append(rec)
        return eid, pid

    def net(self, t, host, user, image, pid, dst_ip, port, sev="info"):
        eid = self.next_id("EDR")
        self.edr.append({"id": eid, "ts": t.isoformat().replace("+00:00", "Z"), "host": host, "user": user,
                         "event_type": "network_connect", "image": image, "pid": pid, "dst_ip": dst_ip,
                         "dst_port": port, "severity": sev})
        return eid

    def flow(self, t, src, dst, port, action="allow", proto="tcp", nbytes=None):
        eid = self.next_id("FW")
        self.fw.append({"log_id": eid, "timestamp": int(t.timestamp()), "src_ip": src, "src_port": rng.randint(49152, 65000),
                        "dst_ip": dst, "dst_port": port, "proto": proto, "action": action,
                        "bytes_out": nbytes if nbytes is not None else rng.randint(400, 90000)})
        return eid

    def query(self, t, client, domain, answer, offset_ist=False):
        eid = self.next_id("DNS")
        ts = t.astimezone(timezone(timedelta(hours=5, minutes=30))).isoformat() if offset_ist else t.isoformat().replace("+00:00", "Z")
        self.dns.append({"qid": eid, "time": ts, "client_ip": client, "query": domain, "qtype": "A",
                         "answers": [answer] if answer else [], "rcode": "NOERROR" if answer else "NXDOMAIN"})
        return eid

    def dbq(self, t, user, client, db, op, rows, obj):
        eid = self.next_id("DB")
        self.db.append({"audit_id": eid, "event_time": t.strftime("%Y-%m-%d %H:%M:%S"), "db_user": user,
                        "client_host": client, "database": db, "operation": op, "rows_returned": rows, "object": obj})
        return eid

    def alert(self, t, rule, sev, mitre, users=(), hosts=(), ips=(), dbs=(), refs=(), disposition="undetermined", status="open"):
        eid = self.next_id("ALR")
        self.alerts.append({"alert_id": eid, "created": t.isoformat().replace("+00:00", "Z"), "rule_name": rule,
                            "severity": sev, "mitre": mitre, "status": status, "disposition": disposition,
                            "entities": {"users": list(users), "hosts": list(hosts), "ips": list(ips), "databases": list(dbs)},
                            "evidence_refs": list(refs)})
        return eid


SYS = {"cmd.exe", "powershell.exe", "rundll32.exe", "svchost.exe", "explorer.exe", "wsmprovhost.exe", "sqlcmd.exe", "lsass.exe"}


def jitter(t: datetime, minutes: float) -> datetime:
    return t + timedelta(seconds=rng.randint(0, int(minutes * 60)))


def routine(s: Sink) -> None:
    """S1 — ordinary working days (business hours 09:00-18:30 IST = 03:30-13:00 UTC)."""
    for d in range(DAYS):
        day = T0 + timedelta(days=d)
        for user, info in sorted(USERS.items()):
            ws, ip = info["ws"], ws_ip(info["ws"])
            start = jitter(day + timedelta(hours=3, minutes=20), 80)
            if d == 2 and start > END:
                continue
            if rng.random() < 0.08:
                s.logon(start - timedelta(seconds=20), user, ws, kind="interactive", result="failure")  # typo
            s.logon(start, user, ws, kind="interactive")
            s.logon(start + timedelta(seconds=4), user, "DC-01", src=ws, kind="network")
            _, exp = s.proc(start + timedelta(seconds=9), ws, user, "explorer.exe")
            apps = ["Microsoft Office\\outlook.exe", "Google\\chrome.exe"] + (["Microsoft Office\\excel.exe"] if rng.random() < 0.6 else [])
            for k, app in enumerate(apps):
                _, apid = s.proc(start + timedelta(minutes=2 + k), ws, user, app, parent="explorer.exe", ppid=exp)
                if "chrome" in app:
                    for dom in rng.sample(sorted(BENIGN_SITES), 2):
                        tq = start + timedelta(minutes=3 + rng.randint(0, 200))
                        s.query(tq, ip, dom, BENIGN_SITES[dom], offset_ist=rng.random() < 0.1)
                        s.net(tq + timedelta(seconds=1), ws, user, app.split("\\")[-1], apid, BENIGN_SITES[dom], 443)
                        s.flow(tq + timedelta(seconds=1), ip, BENIGN_SITES[dom], 443)
            if rng.random() < 0.5:
                tf = start + timedelta(minutes=rng.randint(20, 300))
                s.logon(tf, user, "FS-01", src=ws, kind="network")
                s.flow(tf, ip, SERVERS["FS-01"][0], 445)
            if info["dept"] in ("finance", "hr"):
                for _ in range(rng.randint(2, 4)):
                    ta = start + timedelta(minutes=rng.randint(15, 500))
                    s.flow(ta, ip, SERVERS["APP-01"][0], 443)
                    db = "FINANCE-DB" if info["dept"] == "finance" else "HR-DB"
                    s.dbq(ta + timedelta(seconds=2), "svc_app", "APP-01", db, "SELECT", rng.randint(1, 60),
                          "dbo.invoices" if db == "FINANCE-DB" else "dbo.leave_requests")
        # scheduled reporting on SRV-APP-02 every 2 hours (benign use of the same server)
        for h in range(0, 24, 2):
            tr = day + timedelta(hours=h, minutes=5)
            if tr > END:
                break
            s.dbq(tr, "svc_app", "SRV-APP-02", "FINANCE-DB", "SELECT", rng.randint(200, 900), "dbo.daily_ledger")
            s.dbq(tr + timedelta(minutes=1), "svc_app", "SRV-APP-02", "CRM-DB", "SELECT", rng.randint(50, 300), "dbo.accounts")
        # IT admin: WS-001 -> JUMP-01 -> servers (benign look-alike of lateral movement)
        if d < 2:
            ta = day + timedelta(hours=6, minutes=10 + d * 7)
            s.logon(ta, "a.verma", "JUMP-01", src="WS-001", kind="remote_interactive")
            s.flow(ta, ws_ip("WS-001"), SERVERS["JUMP-01"][0], 3389)
            for k, srv in enumerate(["SRV-APP-02", "APP-01", "BKP-01"]):
                tk = ta + timedelta(minutes=12 + 9 * k)
                s.logon(tk, "a.verma", srv, src="JUMP-01", kind="network")
                s.flow(tk, SERVERS["JUMP-01"][0], SERVERS[srv][0], 5985)
        # nightly backup 01:00 IST (19:30 UTC)
        tb = day + timedelta(hours=19, minutes=30)
        if tb < END:
            s.logon(tb - timedelta(seconds=30), "svc_backup", "BKP-01", kind="service")
            s.flow(tb, SERVERS["BKP-01"][0], DATABASES["FINANCE-DB"][0], 1433, nbytes=880_000_000)
            s.dbq(tb, "svc_backup", "BKP-01", "FINANCE-DB", "BACKUP DATABASE", 0, "FINANCE-DB")
            s.dbq(tb + timedelta(minutes=22), "svc_backup", "BKP-01", "HR-DB", "BACKUP DATABASE", 0, "HR-DB")
        # Windows Update style DNS from servers
        for srv in ("APP-01", "FS-01"):
            s.query(day + timedelta(hours=1, minutes=rng.randint(0, 50)), SERVERS[srv][0], "updates.os-vendor.example",
                    BENIGN_SITES["updates.os-vendor.example"])
    # authorised vulnerability scan (benign look-alike of reconnaissance), day 1 22:00 UTC
    ts = T0 + timedelta(hours=22)
    refs = []
    for k, (host, (ip, _, _)) in enumerate(sorted(SERVERS.items())):
        for port in (445, 3389, 22):
            refs.append(s.flow(ts + timedelta(seconds=k * 6 + port % 5), SERVERS["SCN-01"][0], ip, port,
                               action="allow" if port != 22 else "deny", nbytes=120))
    s.alert(ts + timedelta(minutes=4), "Internal port scan", "medium", "T1046", hosts=["SCN-01"], refs=refs[:6],
            disposition="benign_true_positive", status="closed")


def attack(s: Sink) -> None:
    """S2-S4 — compromise of sameer, credential theft, lateral movement, bulk read, exfiltration."""
    ws, ip = "WS-014", ws_ip("WS-014")
    t = ATTACK
    fails = [s.logon(t + timedelta(seconds=25 * k), "sameer", ws, src="VPN-01", kind="remote_interactive", result="failure")
             for k in range(7)]
    ok = s.logon(t + timedelta(minutes=9), "sameer", ws, src="VPN-01", kind="remote_interactive")
    s.flow(t + timedelta(minutes=9), SERVERS["VPN-01"][0], ip, 3389)
    s.alert(t + timedelta(minutes=10), "Multiple failed logons followed by success (off-hours)", "high", "T1110.001",
            users=["sameer"], hosts=[ws, "VPN-01"], refs=fails[-3:] + [ok])

    t1 = t + timedelta(minutes=13)
    _, exp = s.proc(t1, ws, "sameer", "explorer.exe")
    _, cmd = s.proc(t1 + timedelta(seconds=40), ws, "sameer", "cmd.exe", parent="explorer.exe", ppid=exp)
    ps_ev, ps = s.proc(t1 + timedelta(minutes=1), ws, "sameer", "powershell.exe", parent="cmd.exe", ppid=cmd, pid="7344",
                       cmd="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
                       sev="high")
    s.alert(t1 + timedelta(minutes=2), "Encoded PowerShell from interactive shell", "high", "T1059.001",
            users=["sameer"], hosts=[ws], refs=[ps_ev])

    t2 = t1 + timedelta(minutes=3)
    dq = s.query(t2, ip, C2_DOMAIN, C2_IP)
    c2 = s.net(t2 + timedelta(seconds=2), ws, "sameer", "powershell.exe", ps, C2_IP, 443, sev="medium")
    beacons = [s.flow(t2 + timedelta(seconds=2) + timedelta(minutes=5 * k), ip, C2_IP, 443, nbytes=rng.randint(900, 1400)) for k in range(24)]
    s.alert(t2 + timedelta(minutes=16), "Periodic beaconing to newly observed domain", "medium", "T1071.001",
            hosts=[ws], ips=[C2_IP], refs=[dq, c2] + beacons[:3])

    t3 = t1 + timedelta(minutes=21)
    rd_ev, rd = s.proc(t3, ws, "sameer", "rundll32.exe", parent="powershell.exe", ppid=ps, pid="7712",
                       cmd="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 664 C:\\ProgramData\\wdi.dmp full", sev="high")
    ca = s.next_id("EDR")
    s.edr.append({"id": ca, "ts": (t3 + timedelta(seconds=3)).isoformat().replace("+00:00", "Z"), "host": ws, "user": "sameer",
                  "event_type": "credential_access", "image": "C:\\Windows\\System32\\rundll32.exe", "pid": rd,
                  "target_user": "NORTHWIND\\svc_backup", "target_process": "lsass.exe", "severity": "high"})
    s.alert(t3 + timedelta(minutes=1), "LSASS memory dump via comsvcs.dll", "critical", "T1003.001",
            users=["sameer", "svc_backup"], hosts=[ws], refs=[rd_ev, ca])

    t4 = t3 + timedelta(minutes=17)
    lm_net = s.net(t4, ws, "sameer", "powershell.exe", ps, SERVERS["SRV-APP-02"][0], 5985, sev="medium")
    s.flow(t4, ip, SERVERS["SRV-APP-02"][0], 5985)
    lm_auth = s.logon(t4 + timedelta(seconds=30), "svc_backup", "SRV-APP-02", src=ws, kind="network")
    s.alert(t4 + timedelta(minutes=2), "Service account WinRM logon from workstation", "high", "T1021.006",
            users=["svc_backup"], hosts=[ws, "SRV-APP-02"], refs=[lm_net, lm_auth])

    t5 = t4 + timedelta(minutes=2)
    _, svch = s.proc(t5 - timedelta(hours=30), "SRV-APP-02", "system", "svchost.exe", pid="912")
    _, wsm = s.proc(t5, "SRV-APP-02", "svc_backup", "wsmprovhost.exe", parent="svchost.exe", ppid=svch, pid="3320")
    _, ps2 = s.proc(t5 + timedelta(seconds=50), "SRV-APP-02", "svc_backup", "powershell.exe", parent="wsmprovhost.exe",
                    ppid=wsm, pid="4188", sev="medium", cmd="powershell.exe -ExecutionPolicy Bypass")
    sv = s.next_id("EDR")
    s.edr.append({"id": sv, "ts": (t5 + timedelta(minutes=4)).isoformat().replace("+00:00", "Z"), "host": "SRV-APP-02",
                  "user": "svc_backup", "event_type": "service_install", "image": "C:\\Windows\\System32\\powershell.exe",
                  "pid": ps2, "service_name": "WinTelemetrySync", "severity": "high"})
    s.alert(t5 + timedelta(minutes=5), "New service installed by remote PowerShell", "high", "T1543.003",
            users=["svc_backup"], hosts=["SRV-APP-02"], refs=[sv])
    sq_ev, sq = s.proc(t5 + timedelta(minutes=7), "SRV-APP-02", "svc_backup", "sqlcmd.exe", parent="powershell.exe", ppid=ps2,
                       pid="4520", sev="medium", cmd="sqlcmd.exe -S 10.10.4.10 -E -Q \"SELECT * FROM dbo.vendor_payments\"")
    s.net(t5 + timedelta(minutes=7, seconds=2), "SRV-APP-02", "svc_backup", "sqlcmd.exe", sq, DATABASES["FINANCE-DB"][0], 1433, sev="medium")
    reads = [s.dbq(t5 + timedelta(minutes=8), "svc_backup", "SRV-APP-02", "FINANCE-DB", "SELECT", 48211, "dbo.vendor_payments"),
             s.dbq(t5 + timedelta(minutes=12), "svc_backup", "SRV-APP-02", "FINANCE-DB", "SELECT", 12045, "dbo.employee_bank_details")]
    s.alert(t5 + timedelta(minutes=14), "Anomalous bulk read by service account", "critical", "T1213",
            users=["svc_backup"], hosts=["SRV-APP-02"], dbs=["FINANCE-DB"], refs=reads + [sq_ev])

    # attacker probes the backup server *after* the nightly backup already ran (temporally impossible route)
    t6 = t5 + timedelta(minutes=26)
    s.net(t6, ws, "sameer", "powershell.exe", ps, SERVERS["BKP-01"][0], 445, sev="low")
    s.flow(t6, ip, SERVERS["BKP-01"][0], 445)
    s.flow(t6 + timedelta(minutes=1), ip, DATABASES["HR-DB"][0], 1433, action="deny", nbytes=0)  # blocked: no edge

    t7 = t5 + timedelta(minutes=41)
    ex = s.net(t7, "SRV-APP-02", "svc_backup", "powershell.exe", ps2, C2_IP, 443, sev="medium")
    exf = s.flow(t7, SERVERS["SRV-APP-02"][0], C2_IP, 443, nbytes=412_000_000)
    s.alert(t7 + timedelta(minutes=6), "Large outbound transfer to rare external address", "high", "T1041",
            hosts=["SRV-APP-02"], ips=[C2_IP], refs=[ex, exf])


def incomplete(s: Sink) -> None:
    """S5 — incomplete and conflicting evidence."""
    d3 = T0 + timedelta(days=2)
    # EDR-only signal on WS-022: suspicious child of Excel, no corroborating telemetry (EDR sensor gap after)
    _, xl = s.proc(d3 + timedelta(hours=7, minutes=10), "WS-022", "r.nair", "Microsoft Office\\excel.exe", parent="explorer.exe", ppid="2211")
    s.proc(d3 + timedelta(hours=7, minutes=15), "WS-022", "r.nair", "rundll32.exe", parent="excel.exe", ppid=xl,
           cmd="rundll32.exe C:\\Users\\r.nair\\AppData\\Local\\Temp\\upd.dll,Start", sev="high")
    # unmanaged internal IP (not in inventory) logging on to FS-01 with a valid account
    tu = d3 + timedelta(hours=9, minutes=10)
    s.logon(tu, "k.sethi", "FS-01", src=UNKNOWN_IP, kind="network")
    s.flow(tu, UNKNOWN_IP, SERVERS["FS-01"][0], 445)
    s.alert(tu + timedelta(minutes=3), "Logon from host not in asset inventory", "medium", "T1078",
            users=["k.sethi"], hosts=["FS-01"], ips=[UNKNOWN_IP], refs=["AUTH-999999"])  # dangling evidence reference


def write(out: Path, s: Sink) -> None:
    out.mkdir(parents=True, exist_ok=True)

    def csv_out(name, rows, extra_rows=()):
        rows = list(rows) + list(extra_rows)
        with (out / name).open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
            w.writeheader()
            w.writerows(rows)

    s.auth.sort(key=lambda r: r["time"])
    bad_auth = [
        dict(s.auth[10]),  # exact duplicate
        {**s.auth[11], "event_id": "AUTH-BAD-1", "time": "not-a-time"},  # invalid timestamp
        {**s.auth[12], "event_id": "AUTH-BAD-2", "user": ""},  # missing user
        {**s.auth[13], "event_id": "AUTH-BAD-3", "result": "maybe"},  # invalid enumeration
    ]
    csv_out("auth_logs.csv", s.auth, bad_auth)

    s.fw.sort(key=lambda r: r["timestamp"])
    conflict = {**s.fw[20], "dst_port": 8443, "bytes_out": 1}  # same log_id, different content
    csv_out("firewall.csv", s.fw, [conflict, {**s.fw[21], "log_id": "FW-BAD-1", "src_ip": "10.10.1.999"}])

    s.db.sort(key=lambda r: r["event_time"])
    csv_out("db_audit.csv", s.db)

    s.edr.sort(key=lambda r: r["ts"])
    with (out / "edr_events.jsonl").open("w", encoding="utf-8") as fh:
        for r in s.edr:
            fh.write(json.dumps(r) + "\n")
        fh.write('{"id": "EDR-TRUNC", "ts": "2026-10-28T12:00:00Z", "host": "WS-0\n')  # truncated line (sensor crash)

    s.dns.sort(key=lambda r: r["qid"])
    (out / "dns.json").write_text(json.dumps(s.dns, indent=1) + "\n", encoding="utf-8")
    s.alerts.sort(key=lambda r: r["created"])
    (out / "siem_alerts.json").write_text(json.dumps({"alerts": s.alerts}, indent=1) + "\n", encoding="utf-8")

    inv = []
    for user, info in sorted(USERS.items()):
        inv.append({"asset_id": f"ID-{user}", "asset_type": "admin_account" if info["dept"] == "it_admin" else "user",
                    "name": user, "ip": "", "criticality": 4 if info["dept"] == "it_admin" else 2,
                    "owner": info["dept"], "tags": info["dept"]})
        inv.append({"asset_id": f"AST-{info['ws']}", "asset_type": "workstation", "name": info["ws"], "ip": ws_ip(info["ws"]),
                    "criticality": 2, "owner": user, "tags": "endpoint"})
    inv += [{"asset_id": "ID-svc_backup", "asset_type": "service_account", "name": "svc_backup", "ip": "", "criticality": 4,
             "owner": "it_ops", "tags": "backup;privileged"},
            {"asset_id": "ID-svc_app", "asset_type": "service_account", "name": "svc_app", "ip": "", "criticality": 3,
             "owner": "finance_it", "tags": "application"}]
    for name, (ip, kind, crit) in SERVERS.items():
        inv.append({"asset_id": f"AST-{name}", "asset_type": kind, "name": name, "ip": ip, "criticality": crit,
                    "owner": "it_ops", "tags": "server"})
    for name, (ip, crit) in DATABASES.items():
        inv.append({"asset_id": f"AST-{name}", "asset_type": "database", "name": name, "ip": ip, "criticality": crit,
                    "owner": "data_platform", "tags": "crown_jewel" if crit == 5 else "database"})
    csv_out("asset_inventory.csv", inv)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, default=Path(__file__).resolve().parents[1] / "data" / "sample")
    args = ap.parse_args()
    s = Sink()
    routine(s)
    attack(s)
    incomplete(s)
    write(args.out, s)
    counts = {"auth": len(s.auth), "edr": len(s.edr), "firewall": len(s.fw), "dns": len(s.dns), "db": len(s.db), "alerts": len(s.alerts)}
    print(f"wrote {args.out} (seed {SEED}): {counts}")


if __name__ == "__main__":
    main()
