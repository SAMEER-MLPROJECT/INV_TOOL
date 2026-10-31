# Development log

All work below happened on 2026-10-31 (IST) in a fresh sandboxed environment with AI assistance (see
AI_AND_THIRD_PARTY_DISCLOSURE.md). No earlier project code or data was present or used.

## Phase A — inspection
- Read the supplied execution directive (problem T2.1 GraphOps, judging dimensions, required modules).
- Tried to open hackfrontindia.tech (theme, cohorts, tracks) and whereuelevate.com (event): **blocked by the
  environment's network allow-list**; web search found no official copy. Submission rules, the official activity
  template and portal status could therefore **not** be verified — recorded as manual actions.
- Tooling: Python 3.13, Node 22, git 2.43, `gh` 2.89 (**token invalid** → cannot publish), Docker CLI present but
  Docker Hub blocked, Chrome available, ffmpeg available. No Neo4j server obtainable (Docker Hub, neo4j.com and
  Maven blocked).

## Phase B — architecture decisions
- **Time on occurrences, not edges.** Aggregating repeated interactions per (source, type, target) keeps the graph
  readable while every timestamp and record survives — required for temporal path checks and for provenance.
- **Rules as first-class objects** (`rules.py`) so every edge, suspicion value and correlation link can cite a rule id.
- **IP→host only via inventory**, marked INFERRED. Rejected heuristic name/IP matching as unexplainable.
- **Deterministic scoring** with a published formula instead of an ML model: there is no labelled data to train or
  validate one.
- Local NetworkX engine as the default; Neo4j as an optional mirror that supplies structural candidates, with the
  temporal check kept in one Python code path so both modes give identical results.
- No Pandas/Plotly: stdlib parsing gives row-level error reporting; the two charts are simple SVG.

## Phase C — engine
- Ingestion adapters for 6 telemetry sources + inventory + a common schema; validation, UTC normalisation,
  duplicate/conflict detection, SHA-256 per file.
- Graph builder with 11 relationship rules, alert context edges and three suspicion rules.
- First path model: earliest-arrival DFS (`t(i+1) ≥ t(i) − skew`).
- Blast radius: hop-bounded earliest-arrival search with four tiers.
- Correlation with union-find; risk scoring with breakdowns; evidence explanations; reports; FastAPI.

## Phase E — synthetic data
- Seeded generator for "Northwind Analytics": routine activity, intrusion chain, benign look-alikes, incomplete and
  conflicting evidence, planted bad records. Verified the planted defects are caught (1 duplicate, 1 conflict,
  5 rejected records).

## Defects found by analysing results, and fixes
1. **Unrelated activity chained into paths.** The admin `a.verma` scored *Critical* paths to FINANCE-DB because his
   day-1 logon to SRV-APP-02 was chained to the attacker's day-2 processes there. Fix: a maximum gap between
   consecutive steps (default 6 h) and exact feasibility via propagation of the *set* of feasible arrival times
   (earliest arrival alone is no longer sufficient once an upper bound exists). Result: admin paths ≈ 50 (*Moderate*),
   attack paths 80–89 (*Critical*).
2. **Blast-radius tier contamination.** The admin's blast radius showed FINANCE-DB as *Suspected lateral movement*
   because SRV-APP-02 → FINANCE-DB carried the attacker's suspicious read. Fix: SUSPECTED requires an unbroken
   suspicious chain from the selected entity.
3. **Ranking weights.** A benign one-hop logon to the domain controller initially ranked *High*. Rebalanced weights
   toward suspicion (0.35) and away from evidence quality (0.05).
4. **Hub heuristic.** "Entity in > 50 % of seeds" treated the compromised workstation itself as a hub and split the
   known-answer incident. Replaced by an infrastructure-degree rule (≥ max(20, 4 × median)); hubs in the sample are
   DC-01 and FS-01 only.
5. **Search budget overrun** by up to one expansion per recursion level; budget now checked before each expansion.
6. **UI**: an unlayered `.mono` rule overrode Tailwind font sizes; blast-radius graph unreadable with hundreds of
   process nodes → process hops collapsed by default with the contracted hop types shown on the edge.
7. **Evidence ordering**: relationship occurrences now list the most suspicious first.

## Phase D — UI
- React + TypeScript + Tailwind + React Flow (dagre layout); seven screens wired to the API; evidence inspector
  drawer reachable from every node, edge, step, record and link; analyst disposition controls.
- Verified visually with Playwright screenshots at 1600×1000.

## Phase F — testing
- 85 tests (unit, integration, API, known-answer, Neo4j adapter with a fake driver, 4 Playwright browser tests);
  93 % statement coverage; ruff clean; TypeScript strict build clean.

## Phase G — Neo4j
- Adapter implemented (schema, batched parameterised sync, Cypher candidate paths, neighbourhood counts) and tested
  with a recording driver. **Not run against a live database** (none available).

## Phase H — documentation and demo
- README, architecture, methodology, validation, limitations, disclosure, security, contributing, expected outcomes.
- Demo video recorded by driving the real UI with Playwright (2 min 47 s), screenshots, exported sample report.

## Phase K — signature features (same day, after the first package)
- **Multichannel corroboration** (`channels.py`): six observation channels, expectation table per relationship type,
  primary / corroborating / silent / blind states, channel agreement; per-path and per-incident matrices in the UI and
  in exported reports.
- **MD deviation** (`deviation.py`): robust Mahalanobis distance. First version used one baseline per relationship
  type, which hid the 48,211-row read among mixed query volumes; switched to the pair's own history when it has ≥ 20
  records. Novelty is held constant inside pair baselines (it would otherwise only flag each pair's first record).
  Suspicion capped at 0.45 after checking that scores and incidents were otherwise unchanged.
- **Containment planner** (`containment.py`): first version weighted candidates by membership in the original paths
  and recommended killing processes that did not yet exist and blocking a logon that had already happened. Rebuilt:
  footholds at time T, simulation of every candidate on a counterfactual graph, single-action completion preferred,
  redundancy pruning. Verified known answers at 20:41Z and 21:10Z.
- 13 new tests (12 backend + 1 browser); 98 passing, 95 % coverage.

## Phase L — real-time live mode
- Gap identified while checking alignment with the problem statement: data arrived only by upload, so "in real time"
  was only partly met.
- Added `live.py`: push API (`/api/stream/events`), shared record-processing path with file ingestion, applier thread
  with ≤ 0.4 s micro-batch rebuilds, version notifications over Server-Sent Events, attack replay with speed control,
  and a Live Monitor screen; blast-radius and graph views now refetch on every version.
- 7 new tests (6 backend + 1 browser): 105 passing, 95 % coverage.

## Phase M — rename of the compromised account (v1.3.0)
- The compromised user in the synthetic scenario was renamed to `sameer` across data, tests, UI defaults,
  documentation, screenshots, video and reports. The generator sorts the account under its former key, so every other
  record, record ID, score and test answer is unchanged (verified by a byte comparison of all seven files with the
  name substituted).

## Phase I/J — repository and packaging
- Local git repository with logical commits; secret scan (pattern search over the tree and history) clean.
- `gh auth status` reported an invalid token, so the GitHub repository was **not** created or pushed.
- Submission ZIP built and verified by extracting it to a clean directory, installing dependencies into a fresh
  virtual environment, starting the server and querying the API.
