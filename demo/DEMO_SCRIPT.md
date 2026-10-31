# Demo script (4–5 minutes)

Recorded version: `demo/attackgraph_lens_demo.mp4` (1600×900) — produced by `demo/record_demo.py`,
which drives the real application in Chromium. To record your own version with voice, follow
[RECORDING_CHECKLIST.md](RECORDING_CHECKLIST.md) and read the narration column.

Start: `./scripts/run_local.sh` → open http://127.0.0.1:8000.

| # | Time | On screen (action) | Narration |
|---|---|---|---|
| 1 | 0:00 | **Settings & Data** visible | "SOC analysts get alerts in pieces: a failed logon here, a PowerShell alert there, a database audit line somewhere else. AttackGraph Lens turns those pieces into one explainable graph." |
| 2 | 0:15 | Click **Reset to sample dataset** | "We load seven synthetic sources: identity, endpoint, firewall, DNS, database audit, SIEM alerts and the asset inventory." |
| 3 | 0:25 | Scroll to **Loaded files**, expand an issue list | "Ingestion is strict. Every file is hashed. Bad rows are rejected with a reason, duplicates and conflicting IDs are flagged — nothing is silently repaired." |
| 3b | 0:35 | **Live Monitor** → *Attack window at 240×* → **Start replay** | "Real time: events stream in through the push API. Watch alerts arrive, the incident escalate to Critical, and FINANCE-DB turn *Suspected* in the live blast radius the moment the bulk read streams in." |
| 3c | 1:05 | Settings & Data → **Reset to sample dataset** | "Back to the full three days for the investigation." |
| 4 | 1:10 | **Overview** | "1,191 events become 349 entities and 968 time-stamped relationships. Four candidate incidents are ranked; the top one is critical." |
| 4a | 0:48 | Overview → **Behavioural deviations (MD score)** | "A behavioural signal, robust Mahalanobis distance: the C2 beacon, the 412 MB transfer and the off-hours logons stand out. The nightly backup deviates too — and that is exactly why deviation alone is capped below the suspicion threshold." |
| 4b | 0:58 | **Attack Graph** (suspicious relationships only) | "Solid edges were observed directly; dashed edges were inferred through IP-to-host resolution. A connection is not proof of compromise — the graph says what happened, not what it means." |
| 5 | 1:00 | Click node **sameer** → inspector | "Select the suspected identity. Every node explains why it exists and lists its source records." |
| 6 | 1:10 | **Attack Paths**: source sameer, target FINANCE-DB, **Find paths** | "The engine searches for paths that are possible *in time*: each step must happen after the step that enables it." |
| 6b | 1:20 | Select hypothesis with powershell.exe#7344; scroll the chronological table | "Here is the chain: off-hours logon at 20:40, encoded PowerShell, WinRM to SRV-APP-02, then a 48,000-row read from the finance database — 52 minutes end to end, every step backed by a record." |
| 6c | 1:40 | Scroll to **Rejected: temporally impossible** and the connectivity-only path | "Critical thinking: the backup server *is* connected to the database, but its access happened before the attacker could get there, so the route is rejected. And a plain shortest-path query would have pointed at the normal finance web app." |
| 8 | 1:55 | Click **—CONNECTED_TO→** → inspector → open the EDR record | "Any step opens its evidence: the rule that created the edge, every occurrence, file and row, and the original record verbatim." |
| 7 | 2:15 | **Blast Radius** sameer, drag hop slider 1 → 4 | "Blast radius from the first suspicious logon, recomputed as I move the slider. At hop three the finance database is reached through an unbroken suspicious chain — *suspected*, never automatically *confirmed*." |
| 7b | 2:35 | **Blast Radius** a.verma | "Compare the IT admin: he reaches the same database through normal work. That is *potential exposure*, not lateral movement." |
| 9 | 2:50 | **Incidents → INC-0002**, scroll links and timeline | "Eight alerts from six independent sources become one incident. Every grouping link cites its rule, and the priority shows each component of its score." |
| 11 | 3:15 | Incident → **Containment planner**, then **Simulate** | "Now the response. If we act at the first alert, the planner simulates every option: isolating WS-014 alone stops the intrusion — FINANCE-DB is never reached." |
| 11b | 3:30 | Change time to 21:10, **Plan containment** | "Thirty minutes later the service-account password has already been dumped. Isolating the workstation is no longer enough; the plan adds blocking that account's logon to the server." |
| 12 | 3:45 | **Multichannel corroboration** matrices | "Our signature view: which independent channels saw each step. At the credential-theft step the identity channel was silent — a gap the analyst should check." |
| 10 | 4:00 | Click **HTML** export; open **Evidence** manifest | "Export the report. Its SHA-256 joins the evidence manifest — which also states plainly that a hash proves integrity, not authenticity." |
| — | 3:30 | Overview | "AttackGraph Lens: temporal attack paths, blast radius and one clear incident picture, with evidence for every conclusion." |

## Sample investigation (what the evaluator should see)

- Incident **INC-0002**, *Critical* (score ≈ 92.6): 8 alerts (T1110.001, T1059.001, T1071.001, T1003.001, T1021.006,
  T1543.003, T1213, T1041), identities `sameer`, `svc_backup`; assets WS-014, SRV-APP-02, FINANCE-DB, VPN-01,
  service `WinTelemetrySync`.
- Hypothesis: `sameer → WS-014 → rundll32.exe#7712 → svc_backup → SRV-APP-02 → FINANCE-DB` (credential theft
  variant) with the PowerShell/WinRM variant ranked second.
- Sample exported report: `demo/sample_incident_report_INC-0002.{html,md,json}`; manifest:
  `demo/sample_evidence_manifest.json`.
