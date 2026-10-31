# AttackGraph Lens 1.3.0

Graph engine for security teams (hackFront India 2026 · T-2 Cybersecurity · T2.1 GraphOps): maps time-correct attack
paths, shows the blast radius of a compromised system in real time, and turns scattered alerts into one clear
incident picture, with the evidence behind every conclusion.

## Highlights
- **Real-time live mode**: push API (`POST /api/stream/events`), micro-batched graph updates (≤ 0.4 s), Server-Sent
  Events to the browser, and a Live Monitor that replays the sample intrusion as it unfolds.
- **Temporal attack paths**: time-feasibility with clock-skew and maximum-gap constraints; impossible routes rejected
  with reasons; explainable ranking.
- **Blast radius**: hop-by-hop reachability with four evidence tiers (confirmed only by an analyst).
- **Incident correlation**: rule-cited grouping of alerts and high-severity records, timeline and attack-path
  hypothesis.
- **Multichannel corroboration**: which of six observation channels saw each step; silent vs blind gaps.
- **MD behavioural deviation**: robust Mahalanobis score, decomposed per factor, capped below the decision threshold.
- **Containment planner & what-if**: counterfactual simulation at decision time; plans change as the attacker gains
  footholds.
- **Evidence**: every value traces to file, row and verbatim record; SHA-256 manifest for sources and reports.
- **Presentation and demo**: 20-slide deck with PDF (`submission/`), architecture flowchart, and a 4 min 52 s
  recording of the real application (`demo/attackgraph_lens_demo.mp4`).

## Run
Python 3.11+: `./scripts/run_local.sh` (Windows: `scripts\run_local.ps1`) → http://127.0.0.1:8000.
The attached submission ZIP contains the pre-built UI, so Node.js is not required.

## Validation
105 automated tests passing (incl. 6 browser end-to-end), 95 % statement coverage, strict TypeScript build.
Synthetic data only; no detection-accuracy claim. Neo4j adapter implemented but not validated against a live
AuraDB instance. See `docs/VALIDATION_REPORT.md` and `docs/LIMITATIONS.md`.

## AI assistance
Developed with substantial assistance from Anthropic Claude under the team's direction, see
`docs/AI_AND_THIRD_PARTY_DISCLOSURE.md`.
