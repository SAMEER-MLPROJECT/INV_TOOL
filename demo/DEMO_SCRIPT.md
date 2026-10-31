# Demo script (about 5 minutes)

Recorded version: `demo/attackgraph_lens_demo.mp4` (1600×900, 4 min 52 s), produced by `demo/record_demo.py`. The
script drives the real application in Chromium, moves a visible cursor like a hand, navigates with the sidebar and
zooms into the graphs with the mouse wheel. Captions are the only overlay and are labelled as such in every frame.

To record your own version with voice, follow [RECORDING_CHECKLIST.md](RECORDING_CHECKLIST.md) and read the narration
column below.

Start: `./scripts/run_local.sh`, then open http://127.0.0.1:8000.

| # | Screen and action | Narration |
|---|---|---|
| 1 | **Settings & Data** | "AttackGraph Lens turns scattered security telemetry into explainable attack paths." |
| 2 | **Reset to sample dataset** | "Seven synthetic source files: identity, EDR, firewall, DNS, database audit, SIEM alerts and asset inventory." |
| 3 | Expand an issue list under **Loaded files** | "Every file is hashed and validated. Bad rows are rejected with row and reason; duplicates and ID conflicts are flagged." |
| 4 | **Live Monitor**: preset *Attack window*, speed 480, **Start replay** | "Live mode: events stream in through the push API and every view updates as the attack unfolds." |
| 5 | Watch the **Live alert feed** | "Alerts arrive one by one as the intrusion progresses." |
| 6 | **Live blast radius** after the replay ends | "The 21:32 bulk read has streamed in. FINANCE-DB is now Suspected and the incident is Critical." |
| 7 | **Settings & Data → Reset**, then **Overview** | "1,191 events become 349 entities and 968 relationships. Top incident: Critical 92.6, with its attack-path hypothesis." |
| 8 | Overview → **Behavioural deviations** | "Robust Mahalanobis deviation flags the C2 beacon, 412 MB egress and odd-hour logons. Backups deviate too, but stay below the threshold." |
| 9 | **Attack Graph** | "Graph filtered to suspicious relationships. Dashed means inferred through IP-to-host resolution; solid means observed." |
| 10 | Wheel-zoom on **sameer** | "Start of the chain: sameer's off-hours VPN logon to WS-014, then encoded PowerShell." |
| 11 | Fit view, wheel-zoom on **FINANCE-DB** | "End of the chain: SRV-APP-02 reads the crown-jewel FINANCE-DB. The backup server's routes stay separate." |
| 12 | Click **sameer** | "Every node explains why it exists and lists its source records." |
| 13 | **Attack Paths**: start `sameer`, target `FINANCE-DB`, **Find paths** | "Temporal search: each step must happen after the one that enables it. Paths are ranked with a visible score." |
| 14 | Select the powershell.exe#7344 hypothesis; wheel-zoom on **SRV-APP-02** | "Highlighted: the selected hypothesis among all valid paths. Orange means suspicious evidence." |
| 15 | **Hypothesis: chronological evidence** | "sameer, WS-014, encoded PowerShell, WinRM to SRV-APP-02, a 48,211-row read of FINANCE-DB, 20:40 to 21:32 UTC." |
| 16 | **Multichannel corroboration** | "Which independent channels saw each step: all 4 steps are seen by at least two channels." |
| 17 | **Rejected: temporally impossible** | "Routes that exist in the graph but are impossible in time, via the backup server, are rejected with the reason." |
| 18 | Click **-CONNECTED_TO→**, then the EDR record | "Click any step: the rule that created it, every supporting record, file and row, and why it is suspicious. Down to the original EDR record, verbatim." |
| 19 | **Blast Radius** from `sameer`, hop slider 1 to 4, wheel-zoom on **FINANCE-DB** | "FINANCE-DB is reached at hop 3 through an unbroken suspicious chain: Suspected, never auto-confirmed." |
| 20 | Blast radius from `a.verma` | "An IT admin reaches the same database through ordinary activity: Potential exposure, not lateral movement." |
| 21 | **Incidents → INC-0002**, **Priority breakdown** | "Eight alerts from six independent source systems correlated into one incident. Every point of the score is explained." |
| 22 | **Containment planner** at 20:41, **Simulate** | "Act at the first alert: isolating WS-014 alone stops it. FINANCE-DB, SRV-APP-02 and the service account are no longer reachable." |
| 23 | Set 21:10, **Plan containment** | "Act 30 minutes later: the service-account credential is already stolen, so its logon to SRV-APP-02 must be blocked too." |
| 24 | **Multichannel corroboration: incident** | "Records per channel for every incident entity. A question mark marks a channel that should have seen it but stayed silent." |
| 25 | **HTML** export, then **Evidence** | "Export the report. Its SHA-256 joins the evidence manifest, which also states what a hash does not prove." |
| 26 | Closing caption | "Real-time attack paths, blast radius, one incident picture, containment, and evidence for every conclusion." |

All data is synthetic. The containment planner is advisory: it simulates actions and never changes a real system.
