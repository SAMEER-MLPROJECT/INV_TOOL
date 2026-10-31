# DRAFT — hackFront India 2026 activity document (NOT the official template)

> **Status: unofficial working draft. Manual completion required.**
> The official cohort activity document and the six chapter/activity descriptions could not be accessed from the
> build environment (hackfrontindia.tech and whereuelevate.com were blocked). This draft collects verified project
> facts so the team can copy them into the **official template** from the participant dashboard. Do not submit this
> file in place of the official document.

## Sections the team must complete manually

| Item | Why it cannot be filled here |
|---|---|
| Official template structure, chapter names and activity prompts (all six) | template not accessible |
| Team name, members, roles, registration ID, institution | not provided |
| Completion status of each chapter/activity, dates, certificates | cannot be verified; must not be invented |
| Mentor feedback, attendance | none recorded |
| Prototype-unlock / eligibility confirmation | dashboard not accessible |
| Submission deadline and portal status | not verifiable |
| GitHub repository URL | repository not yet published (see handover) |

## Verified project information (safe to reuse)

**Theme / problem:** T-2 Cybersecurity · T2.1 GraphOps — "Build a graph engine for security teams that maps attack
paths, shows the blast radius of a compromised system in real time, and turns scattered alerts into one clear
incident picture."

**Product:** AttackGraph Lens — *From fragmented security events to explainable attack paths and blast-radius
intelligence.*

**Users:** SOC analysts, threat hunters, incident responders, security administrators, critical-infrastructure
security teams.

**Problem understanding:** Alerts from identity, endpoint, network and database tools arrive in separate consoles;
analysts must rebuild the attack sequence manually, and a pure connectivity graph over-states risk because it ignores
*when* things happened and *why* an edge exists.

**Solution summary:** A temporal knowledge graph in which every relationship keeps its supporting records. On it,
the tool finds time-consistent attack paths (and rejects impossible ones), computes blast radius with four explicit
evidence tiers, correlates alerts into incidents with published rules, and ranks everything with a transparent score.
Every result opens to its source record.

**Innovation (stated precisely):** standard graph algorithms combined with (1) per-edge occurrence provenance,
(2) exact temporal feasibility with clock-skew and maximum-gap constraints, (3) evidence-tiered blast radius where
"suspected" requires an unbroken suspicious chain and "confirmed" requires an analyst, (4) rule-cited correlation and
score breakdowns, (5) multichannel corroboration across six observation channels with silent-vs-blind gap detection,
(6) an explainable MD (robust Mahalanobis) behavioural deviation signal capped below the decision threshold, and
(7) time-aware containment planning with what-if simulation on a counterfactual graph. See docs/NOVELTY.md.

**Technology:** Python, FastAPI, Pydantic, NetworkX, NumPy; React, TypeScript, Tailwind CSS, React Flow; optional Neo4j/AuraDB
adapter; pytest, Playwright; Docker; GitHub Actions.

**Prototype validation (measured):** 98 automated tests passed (unit, integration, API, known-answer, 5 browser
end-to-end), 95 % statement coverage, strict TypeScript build clean. Synthetic dataset only; no accuracy metric
claimed.

**Limitations:** synthetic data; Neo4j adapter not validated on a live database; Docker/CI files not executed; no
authentication; in-memory state.

**Next steps:** connect and demonstrate Neo4j AuraDB; real log connectors; authentication; scale testing; calibrate
ranking on labelled incidents.

**AI use:** developed with substantial assistance from Anthropic Claude under the team's direction (see
`docs/AI_AND_THIRD_PARTY_DISCLOSURE.md`).
