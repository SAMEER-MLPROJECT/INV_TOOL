# What is new in AttackGraph Lens

The building blocks are established: graph search, union-find, time-respecting paths (temporal-network research),
attack-path graphs towards critical assets (e.g. BloodHound-style tools), Mahalanobis distance. We do not claim any of
them as inventions. The contribution is how they are combined so that every answer is time-correct, corroborated and
traceable to a source record — and turned into a response decision.

| # | Contribution | Where | Demonstrated by |
|---|---|---|---|
| 1 | **Occurrence-level provenance on every edge** (time, record, file/row, rule, observed vs inferred, suspicion) | `graph/builder.py` | evidence inspector |
| 2 | **Exact temporal feasibility with clock skew and maximum gap** via feasible-arrival-set propagation | `graph/paths.py` | `test_paths.py` |
| 3 | **Most-relevant-record selection** among feasible occurrences (backward pass) | `graph/paths.py` | first step = the 02:10 IST logon, not a routine one |
| 4 | **Rejected impossible routes with reasons**, plus the connectivity-only shortest path for contrast | `graph/paths.py` | backup-server route rejected |
| 5 | **Four evidence tiers in blast radius**; *suspected* needs an unbroken suspicious chain from the selected entity; *confirmed* only by an analyst | `graph/blast.py` | attacker vs IT admin |
| 6 | **Multichannel corroboration** — step × channel and entity × channel matrices separating *silent* (covered but quiet) from *blind* (no coverage) channels; channel agreement | `channels.py` | identity silence at the credential-theft step; EDR-only incident |
| 7 | **MD behavioural deviation capped below the decision threshold** — robust Mahalanobis distance with per-factor decomposition; it can corroborate but never decide | `deviation.py` | backups deviate yet stay unsuspected; exfiltration and bulk read flagged |
| 8 | **Time-aware containment planning on a counterfactual graph** — footholds at decision time `T`, simulated actions, greedy verified plan with redundancy pruning | `containment.py` | 20:41Z → 1 action; 21:10Z → 2 actions |
| 9 | **Rule-cited reasoning everywhere** — 19 published rules for edges, suspicion and correlation | `rules.py` | Settings → rule catalogue |
| 10 | **Honest scoring** — corroboration counts source systems not records; recency relative to the data; dismissed alerts down-weighted, not hidden; every score decomposed and labelled "not a probability" | `risk.py`, `correlate.py` | score breakdowns |

Contributions 6–8 were added as the team's signature: a multichannel view of evidence, a deviation signal that is
explainable and safely bounded, and a step from "what happened" to "what do we cut now".

## Relationship to the team's earlier work

No code, data, results, screenshots or text from earlier projects (including UniAethel) are included. The team's
experience with network-evidence handling and behavioural analysis informed the decision to add multichannel
corroboration and a behavioural deviation signal; both were designed and implemented fresh for this submission and
are documented here in full.
