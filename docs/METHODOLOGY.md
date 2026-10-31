# Methodology

This document specifies every algorithm and formula used by AttackGraph Lens, with the default parameters. All
analyses are deterministic: the same data and settings always give the same output. Code references are to
`backend/attackgraph/`.

## 1. From records to relationships

Each source record becomes a `NormalizedEvent` (adapter in `ingest/sources.py`). Graph elements are created only by
the rules in `rules.py`; each relationship **occurrence** stores the event uid, timestamp, source system, the
creating rule, its *basis* and a *suspicion* value.

| Rule | Creates | Condition |
|---|---|---|
| R-AUTH-01 | user → host `AUTHENTICATED_TO` | successful logon (failed logons create no edge) |
| R-AUTH-02 | source host → destination host `CONNECTED_TO` | successful logon whose source ≠ destination |
| R-PROC-01 | host → process `EXECUTED` | EDR process start (process keyed by host + image + PID) |
| R-PROC-02 | parent → child `SPAWNED` | EDR record names parent image + PID |
| R-NET-01 | process → host/IP `CONNECTED_TO` / `COMMUNICATED_WITH` | EDR network connection (public IP → `COMMUNICATED_WITH`) |
| R-NET-02 | host/IP → host/IP `CONNECTED_TO` / `COMMUNICATED_WITH` | allowed firewall flow (blocked flows create no edge) |
| R-DNS-01/02 | client → domain `QUERIED`, domain → IP `RESOLVED_TO` | DNS query / answer |
| R-DB-01 | client host → database `ACCESSED` | database audit record |
| R-PRIV-01 | process → user `PRIVILEGE_ESCALATED` | EDR credential access naming a target account |
| R-SVC-01 | process → service `MODIFIED` | EDR service installation |
| R-ALERT-01 | alert → entity `ALERTED_ON` | entity named by a SIEM alert (context edge, never traversed) |

**Basis.** `OBSERVED` when both endpoints are named in the record; `INFERRED` when an IP had to be mapped to a host
through the asset inventory (R-RES-01). Unmapped internal IPs remain `ip:` nodes (`internal_unmanaged`); IPs outside
RFC 1918 / loopback / link-local / ULA are `external`.

**Suspicion of an occurrence** `s ∈ [0,1]` is the maximum of:

- R-SUSP-00: native severity of the record (`info` .05, `low` .25, `medium` .5, `high` .75, `critical` .95; numeric
  0 to 10 or 0 to 100 scaled);
- R-SUSP-01: severity of any alert that lists the event in its evidence references;
- R-SUSP-02: `0.8 × alert severity` when **both** endpoints are named by the same alert (a process counts as its
  host) and the occurrence lies within ± the correlation window of the alert;
- R-SUSP-03: MD behavioural deviation (§7), capped at 0.45 so that it can never cross the threshold on its own.

Alerts with disposition `benign`, `benign_true_positive`, `false_positive` or `closed_benign` raise no suspicion.

## 2. Temporal consistency

For a path of relationships `e1 … ek`, choose one occurrence time `tᵢ` per hop. The path is **temporally consistent**
iff such a choice exists with, for every `i`,

```
t(i) − skew  ≤  t(i+1)  ≤  t(i) + gap
```

- `skew` (default 120 s) tolerates clock differences between source systems;
- `gap` (default 6 h; 0 = unlimited) is the longest interval at which two consecutive steps are still read as one
  chain of activity. Without it, a benign admin logon on Monday followed by an attacker's action on Tuesday would be
  stitched into a single "path".

Feasibility is computed exactly by forward propagation of the **set** of feasible arrival times
(`graph/paths.py: extend`): `A₁ = occ(e₁) ∩ [since − skew, ∞)`, `Aᵢ₊₁ = {t ∈ occ(eᵢ₊₁) : ∃ s ∈ Aᵢ, t − gap ≤ s ≤ t + skew}`.
The path is feasible iff `Aₖ ≠ ∅`. Each step is a sorted-list scan with binary search, `O(m log n)`.

**Evidence selection.** Among the feasible choices, a backward pass picks for the last hop the most suspicious feasible
occurrence and, for each earlier hop, the most suspicious occurrence compatible with the next chosen one (ties → the
closest in time). The analyst therefore sees the off-hours logon, not the first routine logon of the week.

## 3. Attack-path discovery

`find_paths(source, targets, max_hops, rel_types, since)`:

1. Targets default to every host, database or account with criticality ≥ 4 (excluding the source).
2. Depth-first enumeration of **simple** paths (cycles are skipped) up to `max_hops ≤ 8`; at each node the state is
   the feasible-arrival set. Outgoing relationships are explored in order of suspicion, then target criticality.
3. Every reached target yields a candidate. Search stops when the expansion **budget** (default 50,000) or 3,000
   candidates are reached; the result then states `truncated: true`.
4. A structurally existing edge into a target that fails the temporal test is recorded as a **rejected** path with a
   human-readable reason (hop, last occurrence, earliest possible arrival / allowed window).
5. Candidates are explained and ranked (§6); paths that differ only by a process instance (same image, other PID)
   are collapsed.
6. For a single target, the plain shortest path ignoring time (NetworkX BFS) is also reported with its temporal
   validity, to contrast "connected" with "possible".

Neo4j mode replaces step 2 with Cypher variable-length matching (`[*1..k]`, traversable relationships, no repeated
node) and applies steps 3 to 6 unchanged.

## 4. Blast radius

`compute_blast_radius(source, max_hops, temporal, since)`:

- **Temporal mode** (default): start time = `since`, or the first suspicious occurrence touching the entity, or,
  if there is none, unconstrained. A hop-bounded label-correcting search keeps, for each node, the hop at which it was first
  reached and its earliest feasible arrival; a node is reached through an edge only if that edge has an occurrence at
  or after the arrival at its tail (minus skew). The `gap` constraint is deliberately **not** applied: exposure does
  not expire just because an attacker waits.
- **Structural mode**: time ignored.

Each reached node gets one tier:

| Tier | Rule |
|---|---|
| `CONFIRMED_COMPROMISE` | an analyst marked the entity confirmed (never automatic) |
| `SUSPECTED_LATERAL_MOVEMENT` | reached through an **unbroken chain** of suspicious edges (`s ≥ threshold`, default 0.5) that starts at the selected entity |
| `OBSERVED_CONNECTION` | reached in 1 hop with no suspicious evidence |
| `POTENTIAL_EXPOSURE` | reached in ≥ 2 hops of ordinary activity |

The "unbroken chain" condition matters: an IT administrator who legitimately reaches SRV-APP-02 is not "suspected"
just because an attacker later used SRV-APP-02's database connection.

Impact (for ordering the table): `impact = 100 · (0.6·criticality/5 + 0.25/hop + 0.15·[tier ∈ {confirmed, suspected}])`.
The growth curve reports cumulative reachable entities for hop limits 1 to 8 from a single search.

## 5. Alert correlation

**Seeds** = SIEM alerts ∪ records with own severity ≥ threshold. Seed entities = entities named by the alert, plus
entities created by its referenced events (or by the record itself); processes also contribute their host.

**Hubs**: a user/host/database/service whose number of distinct user/host/database/service neighbours is
≥ max(20, 4 × median): cannot by themselves link seeds (in the sample: DC-01 and FS-01, which every user touches).

Seeds are merged with union-find when (sorted by time, pairs within the window `W`, default 90 min):

| Rule | Link condition |
|---|---|
| R-COR-01 | the two seeds share a non-hub entity |
| R-COR-02 | an entity of one is directly connected to an entity of the other by an occurrence within the window |
| R-COR-03 | an alert cites the other seed as evidence |

Every link is stored with its rule and detail. An incident's **supporting events** are its seeds, all events its
alerts cite, and every suspicious occurrence connecting two incident entities inside `[start − W, end + W]` (≤ 250).
The **attack-path hypothesis** is the top-ranked temporal path from the incident's earliest identity (else host) to
any critical asset, starting no earlier than `start − W`.

## 6. Risk ranking

```
score = 100 · Σₖ wₖ · cₖ          Σ wₖ = 1 (weights are normalised),  cₖ ∈ [0, 1]
```

| k | Default wₖ | Path component cₖ | Incident component cₖ |
|---|---|---|---|
| criticality | 0.25 | target criticality / 5 | max criticality of involved entities or hypothesis target / 5 |
| suspicion | 0.35 | mean suspicion of chosen occurrences | 0.6·max + 0.4·mean seed severity (active seeds) |
| corroboration | 0.15 | min(distinct source systems, 4) / 4 | same, over supporting events |
| evidence_quality | 0.05 | fraction of OBSERVED hops | fraction of seeds citing concrete records |
| path_length | 0.10 | 1 / (1 + 0.25·(hops − 1)) | 1 if the hypothesis has a suspicious hop, 0.5 if a benign path to a critical asset exists, else 0 |
| recency | 0.10 | 0.5^(age_h / 48), age relative to the newest event in the dataset | same, from the last seed |

Bands: **Critical ≥ 75**, **High ≥ 55**, **Moderate ≥ 35**, **Low < 35**. Incidents whose seeds were all dismissed as
benign by the source tool are multiplied by 0.3 (and remain visible).

*Corroboration counts source systems, not records*: four alerts from the same SIEM count once.

*Recency* is measured from the newest event in the loaded data rather than from the wall clock, so re-running an
analysis later gives the same score.

**This score is a triage ordering, not a calibrated probability of attack.** Weights were chosen by reasoning about
the problem and checked on the synthetic dataset (attack paths ≈ 80 to 89, benign routes to the same database ≈ 50); they
have not been fitted or validated on real incident data.

## 7. MD deviation score (robust Mahalanobis distance): `deviation.py`

An unsupervised behavioural signal, computed for `AUTHENTICATED_TO`, `CONNECTED_TO`, `COMMUNICATED_WITH` and `ACCESSED`.

**Features** of each occurrence: `hour_sin`, `hour_cos` (time of day, UTC, on the unit circle);
`volume = log10(1 + rows returned or bytes sent)`; `novelty = 1 / (1 + earlier occurrences of the same pair)`.

**Peer baseline.** A source → target pair with ≥ 20 occurrences is compared with its own history (novelty held
constant there, since it would only flag the pair's first record); otherwise the occurrence is compared with all
occurrences of its relationship type (needs ≥ 30).

**Distance.** `z = (x − median) / (1.4826·MAD)` (robust standardisation; falls back to the standard deviation when
MAD = 0), `S = 0.8·cov(z) + 0.2·I` (shrinkage keeps S invertible with few samples),
`D² = zᵀ S⁻¹ z`. The per-feature contributions `zᵢ·(S⁻¹z)ᵢ` sum to D², so every score is decomposed into
*time of day*, *data volume* and *new relationship*.

**Reference.** With 4 features, D² is compared with χ²(4), whose tail is `P(X > d) = e^(−d/2)·(1 + d/2)`; the
reference point is D² = 18.47 (tail 0.001). Real features are not Gaussian, so the tail value is a reference, not a
calibrated probability.

**Rule R-SUSP-03.** Above the reference, suspicion `= 0.45 · min(1, (D² − 18.47)/18.47)`, applied only if higher
than the occurrence's existing suspicion. The cap 0.45 is deliberately below the default threshold 0.5: **deviation
alone can never make an entity "suspected", seed an incident or start a suspicious chain**; it can only add weight to
evidence that other channels already provide. In the sample, nightly backups deviate strongly (night-time, first
observation) yet stay below the threshold, while the 48,211-row read and the 412 MB egress are flagged *and*
corroborated by alerts.

It is a deviation score, not a classifier: there are no labels to train or validate a classifier.

## 8. Multichannel corroboration: `channels.py`

Each record belongs to one observation channel: **identity** (`idp_auth`), **endpoint** (`edr`), **network**
(`firewall`), **DNS**, **data** (`db_audit`), **detection** (`siem_alerts`); custom sources map by category.
Processes are folded into their host. A channel *covers* an entity if it has ever recorded it.

For each attack-path step (relationship `u → v`, chosen occurrence at time `t`):

| Cell state | Meaning |
|---|---|
| primary | the channel of the chosen record |
| corroborating | another record from this channel touches `u` or `v` within ±15 min |
| silent | the channel is *expected* for this kind of step and covers `u` or `v`, but recorded nothing in ±15 min |
| blind | expected, but the channel never covers `u` or `v` (a coverage gap, not suspicious in itself) |
| none | not expected, nothing recorded |

Expected channels: `AUTHENTICATED_TO` identity + endpoint; `EXECUTED`/`SPAWNED`/`MODIFIED` endpoint;
`CONNECTED_TO` network + endpoint; `COMMUNICATED_WITH` network + endpoint + DNS; `ACCESSED` data + network;
`QUERIED`/`RESOLVED_TO` DNS; `PRIVILEGE_ESCALATED` endpoint + identity. Detection is never "expected".

**Channel agreement** = Σ_steps |expected ∩ channels with evidence| / Σ_steps |expected|. Incidents get an
entity × channel matrix of record counts over `[start − W, end + W]`, the share of covering channels that produced
evidence, entities with expected-but-silent channels, and entities seen by a single channel only.

Corroboration means *independent activity on the same entities at the same time*; it is not proof that two channels
saw the identical action. A silent channel may mean a logging gap, tampering or benign absence; it is surfaced for
the analyst, not scored.

## 9. Containment planning and what-if simulation: `containment.py`

**Counterfactual graph.** Containing an entity at time `T` removes every occurrence at or after `T` that touches it
(isolating a host also stops its processes); blocking a relationship removes its occurrences at or after `T`.
Occurrences before `T` stay: history cannot be undone.

**Footholds.** At `T` the adversary holds the source entity plus every user, host, process or service reached from it
through an unbroken suspicious chain before `T`. Spread is measured *from all footholds, after T*: valid paths to
critical assets (§3), and blast radius with tiers (§4).

**Metrics.** critical/high paths remaining, crown jewels (criticality ≥ 4) still *suspected*, suspected and reachable
entity counts; residual risk = Σ scores of remaining valid paths.

**Planner** (greedy, verified):
1. Candidates = footholds plus every non-target entity and relationship on remaining paths (databases are protected
   assets, never containment targets; a process that does not yet exist at `T` cannot be terminated).
2. Each candidate is *simulated* on the counterfactual graph; value = risk reduction / disruption cost.
   Costs: workstation 1, server 3, domain controller 5, user 1, service/admin account 2, process 0.3, service 0.5,
   relationship block 0.8, external address 0.3.
3. If some candidate alone completes containment, the cheapest such candidate is chosen; otherwise the best value.
4. Repeat until *contained* (no critical/high path and no crown jewel suspected) or 5 actions.
5. Prune: any chosen action that the rest of the plan makes redundant is removed and effects are recomputed.

Known answers on the sample (tested): at the first alert (20:41Z) the plan is **isolate WS-014** (one action); at
21:10Z, after the service-account credential was dumped, it is **isolate WS-014 + block svc_backup's logon to
SRV-APP-02**; isolating WS-014 alone then no longer protects FINANCE-DB.

The planner reasons only over observed evidence; it does not know business constraints, so every action is shown
with its disruption cost for the analyst to weigh.

## 10. Real-time live mode: `live.py`

- **Input:** `POST /api/stream/events {source_type?, records[≤ 5000]}` (or the built-in replay). Each batch passes
  through the same adapters, validation and de-duplication as file uploads; provenance is `live:<source>` plus the
  record's position in that stream.
- **Update rule:** accepted events mark the workspace *dirty*; an applier thread recomputes the whole pipeline
  (graph → suspicion → MD → incidents) at most every 0.4 s, so latency from arrival to updated picture is
  ≤ 0.4 s + one rebuild (measured 30 to 90 ms on the sample). Full recomputation was chosen over incremental patching so
  that streamed and uploaded data go through one tested code path.
- **Notification:** every rebuild (stream, upload, settings, analyst mark) increments a version and is pushed over
  Server-Sent Events (`GET /api/stream/updates`); browsers refetch at most once per second.
- **Replay:** records of the sample dataset before the chosen start are preloaded; records inside
  `[start, end]` are sent when `start + (wall-clock elapsed) × speed` passes their timestamp. Inventory is sent first.

## 11. Explainability guarantees

- Every relationship occurrence → event uid → source file + row → verbatim original record.
- Every relationship → creating rule(s) and basis text; every suspicion value → its rule and, where relevant, alert id.
- Every correlation link → rule and detail; every score → component values, weights, contributions and plain-language
  basis.
- Every rejected path → the hop and timestamps that make it impossible.
- SHA-256 of each source file and each exported report; the manifest states that a hash proves integrity relative to
  the recorded digest only, not authenticity or completeness of the evidence.
