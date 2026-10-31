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

- R-SUSP-00 — native severity of the record (`info` .05, `low` .25, `medium` .5, `high` .75, `critical` .95; numeric
  0–10 or 0–100 scaled);
- R-SUSP-01 — severity of any alert that lists the event in its evidence references;
- R-SUSP-02 — `0.8 × alert severity` when **both** endpoints are named by the same alert (a process counts as its
  host) and the occurrence lies within ± the correlation window of the alert.

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
node) and applies steps 3–6 unchanged.

## 4. Blast radius

`compute_blast_radius(source, max_hops, temporal, since)`:

- **Temporal mode** (default): start time = `since`, or the first suspicious occurrence touching the entity, or —
  if none — unconstrained. A hop-bounded label-correcting search keeps, for each node, the hop at which it was first
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
The growth curve reports cumulative reachable entities for hop limits 1–8 from a single search.

## 5. Alert correlation

**Seeds** = SIEM alerts ∪ records with own severity ≥ threshold. Seed entities = entities named by the alert, plus
entities created by its referenced events (or by the record itself); processes also contribute their host.

**Hubs** — a user/host/database/service whose number of distinct user/host/database/service neighbours is
≥ max(20, 4 × median) — cannot by themselves link seeds (in the sample: DC-01 and FS-01, which every user touches).

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
the problem and checked on the synthetic dataset (attack paths ≈ 80–89, benign routes to the same database ≈ 50); they
have not been fitted or validated on real incident data.

## 7. Explainability guarantees

- Every relationship occurrence → event uid → source file + row → verbatim original record.
- Every relationship → creating rule(s) and basis text; every suspicion value → its rule and, where relevant, alert id.
- Every correlation link → rule and detail; every score → component values, weights, contributions and plain-language
  basis.
- Every rejected path → the hop and timestamps that make it impossible.
- SHA-256 of each source file and each exported report; the manifest states that a hash proves integrity relative to
  the recorded digest only, not authenticity or completeness of the evidence.
