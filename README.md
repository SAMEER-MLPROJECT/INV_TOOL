# AttackGraph Lens

**From fragmented security events to explainable attack paths and blast-radius intelligence.**

AttackGraph Lens is a graph-based threat-hunting and incident-investigation platform built for
**hackFront India 2026 · Theme T-2 Cybersecurity · Problem T2.1 GraphOps**:

> *Build a graph engine for security teams that maps attack paths, shows the blast radius of a compromised
> system in real time, and turns scattered alerts into one clear incident picture.*

It ingests identity, endpoint, firewall, DNS, database-audit and SIEM records, builds a **temporal knowledge graph**
in which every edge keeps the events that justify it, and answers the analyst's real question:
**who was reached, in what order, and how do we know?**

Target users: SOC analysts, threat hunters, incident responders, security administrators and critical-infrastructure
security teams.

| Analyst question | Feature | What makes it trustworthy |
|---|---|---|
| *How could an attacker get from here to the crown jewels?* | **Attack-path explorer** | Paths must be **time-consistent**: each step after the one that enables it. Routes that exist in the graph but are impossible in time are shown as *rejected*, with the reason. |
| *If this is compromised, what is exposed right now?* | **Blast radius + live stream** | Events stream in through a push API and every open screen refreshes itself. Each reached entity gets one of four evidence tiers; reachability is never presented as compromise. |
| *Which alerts belong together?* | **Incident correlation** | Alerts and high-severity records are grouped by three published rules; every link, score component and timeline entry cites its evidence. |
| *Which independent sources agree, and which are silent?* | **Multichannel corroboration** | Each step is checked across six channels (identity, endpoint, network, DNS, data, detection), separating *silent* channels from *blind* ones. |
| *What do we cut, and when?* | **Containment planner + what-if** | Actions are simulated on a counterfactual graph at the decision time; the plan changes as the attacker gains footholds. Advisory only. |

![Overview](docs/screenshots/01_overview.png)

**Demo video:** [`demo/attackgraph_lens_demo.mp4`](demo/attackgraph_lens_demo.mp4) (4 min 52 s, real application,
synthetic data) · **Presentation:** [`submission/AttackGraph_Lens_T2_Final.pdf`](submission/AttackGraph_Lens_T2_Final.pdf)
([PPTX](submission/AttackGraph_Lens_T2_Final.pptx))

---

## Contents

[What is new](#what-is-new) · [Team track record](#team-track-record) · [Features](#features) ·
[Architecture](#architecture) · [How it decides](#how-it-decides) · [Screenshots](#screenshots) ·
[Installation](#installation-and-execution) · [Configuration](#environment-configuration) ·
[Sample workflow](#sample-workflow) · [Neo4j](#neo4j-optional) · [Testing](#testing-and-validation) ·
[Project layout](#project-layout) · [Limitations](#known-limitations) ·
[AI use and acknowledgements](#ai-use-disclosure-and-acknowledgements)

## What is new

> AttackGraph Lens integrates temporal feasibility, occurrence-level evidence provenance, graded blast-radius
> reasoning, multichannel corroboration and time-aware counterfactual containment into one explainable security
> investigation workflow.

| | Contribution | In short |
|---|---|---|
| A | **Temporal feasibility of attack paths** | Keeps every occurrence and timestamp, enforces order and a maximum gap, rejects impossible routes and says why. |
| B | **Provenance-native evidence graph** | Every edge keeps its source records; observed and inferred edges stay distinct; any conclusion traces to file, row, rule and original event. |
| C | **Evidence-tiered blast radius** | `CONFIRMED_COMPROMISE` (analyst only) · `SUSPECTED_LATERAL_MOVEMENT` · `OBSERVED_CONNECTION` · `POTENTIAL_EXPOSURE`. An admin's reach is not compromise. |
| D | **Multichannel corroboration and behavioural context** | Six channels; primary, corroborating, silent and blind states; a bounded Mahalanobis deviation score as a supporting signal. |
| E | **Counterfactual, time-aware containment** | Simulates an action at a chosen time, re-runs paths and blast radius, and compares risk reduction with disruption cost. |

Not merely a graph of possible connections: an evidence-backed reconstruction of what could have happened, what likely
happened, and why. Temporal graphs, graph traversal, Mahalanobis distance, alert correlation and counterfactual
analysis are established techniques and are not claimed as inventions; the contribution is their integration.
Details: [docs/NOVELTY.md](docs/NOVELTY.md).

## Team track record

Design philosophy inspired by UniAethel, a previous cybersecurity tool shortlisted at SUTRAM 2026 by NFSU.

UniAethel and AttackGraph Lens are separate projects with different implementations and objectives. What carried over
is a way of working: evidence-oriented security thinking, analyst-centric interaction and clear technical
presentation. AttackGraph Lens was implemented independently for hackFront; no UniAethel code, data, results,
screenshots or presentation material are included. The shortlist recognises UniAethel only; it does not validate
AttackGraph Lens, and NFSU has not developed, endorsed or reviewed this project.

## Features

- **Multi-source ingestion** (CSV, JSON, JSON Lines) with schema detection, UTC normalisation of ISO, offset, naive and
  epoch timestamps, invalid-record rejection with reasons, exact-duplicate and ID-conflict detection, per-file
  SHA-256, a 20 MB upload limit, filename sanitising and parse-only handling: uploads are never executed.
- **Identity resolution with explicit identifiers only**: `CORP\Sameer` and `sameer@corp.local` become `user:sameer`;
  `ws-014.corp.local` becomes `host:WS-014`. An IP becomes a host *only* when the asset inventory assigns it, and such
  edges are marked **INFERRED**.
- **Temporal knowledge graph** (NetworkX): 8 entity types and 11 relationship types; each relationship aggregates
  ordered *occurrences* (time, event, source system, basis, creating rule, suspicion).
- **Temporal attack-path discovery**: bounded search with clock-skew tolerance, a maximum gap between steps, hop limit,
  relationship filters, a search budget, automatic crown-jewel targets, explainable ranking, rejected impossible routes
  and the connectivity-only shortest path for contrast.
- **Blast radius**: hop-bounded earliest-arrival reachability from the first suspicious activity (or a chosen time, or
  structurally), growth by hop, critical-asset exposure, impact ranking and the four evidence tiers.
- **Alert correlation** into incidents with time window, identities, assets, supporting events, evidence sources,
  correlation links, attack-path hypothesis, timeline and priority.
- **Explainable risk ranking**: `score = 100 · Σ wₖ·cₖ` over six documented components with adjustable weights and a
  full breakdown on every path and incident. It is a prioritisation score, not a probability of compromise.
- **Evidence and explainability**: click any node, edge, step or record to see why it exists, the rule that created it,
  every supporting record (file, row and the original record verbatim) and the incidents it belongs to.
- **Exports**: incident reports in HTML, Markdown and JSON; an evidence manifest with SHA-256 of sources and exports.
- **Real-time live mode**: `POST /api/stream/events` accepts batches from SIEM forwarders or log shippers. The graph,
  suspicion, deviation scores and incidents are recomputed in micro-batches (at most 0.4 s apart) and pushed to the
  browser over Server-Sent Events. A built-in **attack replay** streams the sample intrusion event by event.
- **Multichannel corroboration**: step × channel and entity × channel matrices, channel agreement and evidence-gap
  statements.
- **Mahalanobis behavioural deviation**: robust distance of each interaction from its own history, decomposed per
  factor and capped below the suspicion threshold, so unusual but benign activity (nightly backups) is shown but never
  becomes "suspected" on its own.
- **Containment planner and what-if simulation**: counterfactual graph at time `T`, adversary footholds at `T`, a
  greedy verified plan with redundancy pruning, before and after exposure, and an interactive simulator.
- **Optional Neo4j / AuraDB backend**: implemented and unit-tested against a recording driver (see [status](#neo4j-optional)).

## Architecture

![Architecture](docs/architecture.png)

Six layers around one temporal knowledge graph:

1. **Telemetry ingestion**: identity, endpoint/EDR, firewall, DNS, database audit, SIEM alerts, asset inventory.
2. **Validation and normalisation**: formats, schema, UTC time, duplicates and ID conflicts, IP-to-host resolution,
   event provenance, source-file SHA-256.
3. **Temporal knowledge graph**: entities, typed relationships, individual occurrences, observed vs inferred, evidence
   references.
4. **Analytical engines**: temporal paths, suspicion scoring, Mahalanobis deviation (supporting), blast radius and
   tiers, incident correlation, six-channel corroboration, explainable risk.
5. **Decision and simulation**: ranked paths, rejection reasons, blast-radius classes, the incident, counterfactual
   containment and residual-risk comparison.
6. **Output and interaction**: attack graph, incident view, evidence explorer, live monitor, reports and manifests,
   advisory containment.

The live path reuses the same validation and graph update: forwarder → `POST /api/stream/events` → validate →
micro-batch graph update → Server-Sent Events → dashboard refresh. Storage is an in-memory NetworkX graph by default,
with an optional Neo4j adapter.

Editable diagram source: [`submission/Architecture_Flowchart.mmd`](submission/Architecture_Flowchart.mmd) ·
details: [docs/TECHNICAL_ARCHITECTURE.md](docs/TECHNICAL_ARCHITECTURE.md) · algorithms and formulas:
[docs/METHODOLOGY.md](docs/METHODOLOGY.md).

| Layer | Technology |
|---|---|
| Engine and API | Python 3.11+, FastAPI, Pydantic v2, NetworkX, NumPy |
| Optional graph store | Neo4j 5 / AuraDB via the official `neo4j` driver |
| Interface | React 19, TypeScript (strict), Vite, Tailwind CSS 4, React Flow (`@xyflow/react`) with dagre layout, lucide icons |
| Tests | pytest, FastAPI TestClient, Playwright (Chromium), ruff |
| Delivery | run scripts, Dockerfile, docker-compose, GitHub Actions CI |

Pandas and Plotly are not used: parsing uses the standard-library `csv` and `json` modules (row-level error reporting,
no unsafe loaders) and the two small charts are plain SVG.

## How it decides

| Step | Rule |
|---|---|
| Suspicion of an occurrence | `s = max(s_native, s_alert, 0.8 · s_proximity, s_MD)`; suspicious when `s ≥ 0.5`. The maximum is used so that one strong independent signal is not diluted. |
| Mahalanobis deviation | features `[sin(2πh/24), cos(2πh/24), log₁₀(1+volume), novelty]`; baseline of the same relationship (n ≥ 20) or type (n ≥ 30); robust z with median and MAD; `S = 0.8·cov(z) + 0.2·I`; `D² = zᵀS⁻¹z`; `s_MD = 0.45 · min(1, (D² − 18.47)/18.47)`, where 18.47 is the 99.9th percentile of χ² with 4 degrees of freedom. Capped at 0.45, so it can support a decision but never make one. |
| Temporal feasibility | `t(i) − 120 s ≤ t(i+1) ≤ t(i) + 6 h` between consecutive steps. |
| Priority | `100 · Σ wₖ·cₖ` with criticality .25, suspicion .35, corroboration .15, evidence quality .05, path length .10, recency .10. Critical ≥ 75, High ≥ 55, Moderate ≥ 35. |
| Blast-radius tier | *suspected* needs an unbroken chain of suspicious steps from the selected entity; *confirmed* is set only by an analyst. |
| Correlation | shared non-hub entity (R-COR-01), graph adjacency within 90 min (R-COR-02), explicit evidence reference (R-COR-03); hubs such as the domain controller cannot glue incidents. |

## Screenshots

| Attack paths | Blast radius |
|---|---|
| ![](docs/screenshots/03_attack_paths.png) | ![](docs/screenshots/04_blast_radius.png) |
| **Incident** | **Evidence inspector** |
| ![](docs/screenshots/06_incident.png) | ![](docs/screenshots/09_evidence_inspector.png) |
| **Containment planner and what-if** | **Multichannel corroboration** |
| ![](docs/screenshots/10_containment_whatif.png) | ![](docs/screenshots/11_multichannel.png) |
| **Live Monitor (real-time replay)** | **Behavioural deviations (Mahalanobis)** |
| ![](docs/screenshots/13_live_monitor.png) | ![](docs/screenshots/12_md_deviation.png) |

## Installation and execution

Requirements: **Python 3.11+**. Node.js 20+ is needed only to rebuild the interface; the submission ZIP already
contains the built interface in `frontend/dist`.

One command (creates `.venv`, installs dependencies, builds the interface if needed and starts the server):

```bash
./scripts/run_local.sh                                          # Linux / macOS
powershell -ExecutionPolicy Bypass -File scripts\run_local.ps1  # Windows
```

Then open **http://127.0.0.1:8000**. The synthetic dataset loads automatically. API documentation: `/api/docs`.

Manual steps:

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cd frontend && npm ci && npm run build && cd ..          # only if frontend/dist is missing
cd backend && python -m attackgraph serve
```

Docker: `docker compose up --build` (not exercised in the build environment; see limitations).

Command line, without the interface:

```bash
cd backend
python -m attackgraph analyze                                    # incidents in the sample data
python -m attackgraph path user:sameer database:FINANCE-DB --hops 5
```

## Environment configuration

Copy `.env.example` to `.env`. Every variable is optional; the default is the zero-configuration local engine.
Never commit a `.env` file with real credentials.

| Variable | Default | Purpose |
|---|---|---|
| `AGL_GRAPH_BACKEND` | `memory` | `memory` or `neo4j` |
| `NEO4J_URI`, `NEO4J_USERNAME`, `NEO4J_PASSWORD`, `NEO4J_DATABASE` | empty / `neo4j` | Neo4j or AuraDB connection |
| `AGL_MAX_UPLOAD_MB` | `20` | per-file upload limit |
| `AGL_MAX_RECORDS_PER_FILE` | `200000` | per-file record limit |
| `AGL_SAMPLE_DIR`, `AGL_EXPORT_DIR`, `AGL_FRONTEND_DIST` | repository paths | path overrides |

## Sample workflow

The synthetic organisation "Northwind Analytics" covers 3 days and contains one intrusion, benign look-alikes and
planted data-quality problems. Counts: **1,258 rows read → 1,251 accepted** (5 rejected, 1 duplicate, 1 ID conflict)
**→ 1,191 events** plus 60 inventory assets **→ 349 entities, 968 relationships, 1,625 occurrences**. Answer key:
[data/sample/EXPECTED_OUTCOMES.md](data/sample/EXPECTED_OUTCOMES.md).

0. **Live Monitor**: start *Attack window* replay. Alerts arrive, INC-0002 escalates to Critical and FINANCE-DB turns
   *Suspected* when the 21:32 bulk read streams in. Afterwards use Settings & Data → Reset to sample dataset.
1. **Overview**: 4 candidate incidents; the top one is Critical 92.6 (8 alerts from 6 independent source systems).
2. **Attack Paths**: start `user:sameer`, target `database:FINANCE-DB`. The chain
   `sameer → WS-014 → powershell.exe#7344 → SRV-APP-02 → FINANCE-DB` runs 20:40 to 21:32 UTC with every hop suspicious
   (score 85.7). Routes through the backup server are **rejected**: its database access happened before the attacker
   could reach it.
3. **Blast Radius**: `user:sameer` with hops 1 to 4: FINANCE-DB becomes *Suspected lateral movement* at hop 3. From
   `user:a.verma` (IT admin) the same database is only *Potential exposure*.
4. **Evidence**: click any step for its rule, occurrences, source file and row, and the original record.
5. **Incidents**: INC-0002 with correlation links, timeline, hypothesis and priority breakdown; export HTML,
   Markdown or JSON.
6. **Containment**: at 20:41 the planner recommends *Isolate host WS-014* (98.7 % less path risk). At 21:10 the dumped
   `svc_backup` credential is already a foothold, so it adds *Block svc_backup → SRV-APP-02*.
7. **Multichannel**: the path and incident views show which channels saw each step.
8. **Behavioural deviations**: the C2 beacon, 412 MB egress and 48,211-row read stand out; the nightly backup also
   deviates but stays below the threshold.

## Neo4j (optional)

The adapter (`backend/attackgraph/store/neo4j_store.py`) creates a uniqueness constraint and indexes, stores entities
as `:Entity:<Type>` nodes and relationships with their occurrence arrays, all through parameterised `UNWIND $rows`
batches. In `neo4j` mode the path explorer asks Neo4j for structural candidates and validates them with the same
temporal scheduler as local mode, so ranking and explanations are identical.

```bash
# .env
AGL_GRAPH_BACKEND=neo4j
NEO4J_URI=neo4j+s://<your-instance>.databases.neo4j.io
NEO4J_USERNAME=<user>
NEO4J_PASSWORD=<password>
```

Restart, then open **Settings & Data → Graph backend → Connect & sync to Neo4j**.

**Status: implemented and tested against a recording fake driver only.** No Neo4j server or AuraDB instance was
available in the build environment, so the adapter has not been validated against a live database, and no Neo4j
partner-track qualification is claimed.

## Testing and validation

```bash
pip install -r requirements-dev.txt
cd backend
pytest -m "not e2e"                                       # 99 unit, integration, API, live and known-answer tests
python -m playwright install chromium && pytest -m e2e    # 6 browser tests (needs frontend/dist)
cd ../frontend && npm run typecheck
```

Last run: **105 passed, 0 failed**, 95 % statement coverage of `attackgraph/`. The known-answer tests check the
principal path, the rejected backup route, the attacker vs admin tiers, the planted bad rows and the evidence hashes.
Timings (medians on the synthetic dataset, one machine): ingest and build 88 ms, path query 2.3 ms, 4-hop temporal
blast radius 0.4 ms. No accuracy, precision, recall or F1 is claimed: the only labels are synthetic. Details:
[docs/VALIDATION_REPORT.md](docs/VALIDATION_REPORT.md).

## Project layout

```
backend/attackgraph/   engine: ingest/, graph/ (builder, paths, blast), correlate, channels, deviation,
                       containment, live, risk, evidence, report, store/ (Neo4j), api/
backend/tests/         unit, API, known-answer, live, Neo4j-adapter and browser tests
frontend/src/          React interface: pages/ (8 screens), components/, lib/
data/sample/           synthetic dataset and expected outcomes
scripts/               run scripts, data generator, benchmark, screenshot capture
docs/                  architecture, methodology, validation, novelty, limitations, disclosure, development log, repo map
demo/                  demo video, recording script, demo script, sample incident report
submission/            presentation (PPTX and PDF), architecture diagram, deck change log
```

File-by-file map, with each T2.1 requirement and judging dimension traced to code, tests and docs:
[docs/REPO_MAP.md](docs/REPO_MAP.md).

## Known limitations

Synthetic data only, so no real-world detection-accuracy claim. Neo4j, Docker and CI were not run against live
services. Single-process, in-memory state. Live mode recomputes the graph per micro-batch, which is fine at prototype
scale but needs incremental updates for very large streams. No authentication on the API, so bind it to localhost.
Full list: [docs/LIMITATIONS.md](docs/LIMITATIONS.md). Security policy: [SECURITY.md](SECURITY.md).

## AI-use disclosure and acknowledgements

This codebase, the dataset generator, tests and documentation were produced with substantial assistance from an AI
coding assistant (Anthropic Claude) working under the team's direction during the hackFront league. It is a new
implementation and does not reuse code, data, results or material from the team's earlier projects. Details and the
complete third-party list with licences: [docs/AI_AND_THIRD_PARTY_DISCLOSURE.md](docs/AI_AND_THIRD_PARTY_DISCLOSURE.md).

Built on FastAPI, Pydantic, Uvicorn, NetworkX, NumPy, the Neo4j Python driver, React, React Flow, dagre, Tailwind CSS,
Vite, lucide, Inter and JetBrains Mono. Thank you to their maintainers.

Licence: MIT (see [LICENSE](LICENSE)).
