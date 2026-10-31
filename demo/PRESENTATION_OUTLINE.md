# Presentation outline (8–9 slides)

1. **Problem** — Alerts arrive fragmented across identity, endpoint, network and database tools. Analysts must
   reconstruct how far an intrusion went by hand. T2.1 GraphOps asks for attack paths, real-time blast radius and one
   incident picture.
2. **Insight** — Connectivity is not compromise. A useful attack graph must respect *time* (could step B have followed
   step A?) and must show the *evidence* for every edge, or analysts will not trust it.
3. **Solution: AttackGraph Lens** — pipeline diagram (`docs/architecture.png`): ingest → resolve → temporal graph →
   correlate → paths → blast radius → evidence → report.
4. **What is new in our approach** — (a) occurrences with provenance on every edge; (b) exact temporal feasibility with
   skew and gap, plus *rejected* impossible routes; (c) four blast-radius tiers where "suspected" needs an unbroken
   suspicious chain and "confirmed" needs an analyst; (d) published rules and a transparent score. Graph algorithms
   themselves are standard — the contribution is how they are combined and explained.
5. **Signature layer** — multichannel corroboration (which independent channels saw each step, which stayed silent),
   MD behavioural deviation that can corroborate but never decide, and time-aware containment: act at the first alert
   and one isolation suffices; act 30 minutes later and the stolen credential must be cut too.
6. **Live demo** — 4 minutes (DEMO_SCRIPT.md), opening with the real-time replay: alerts stream in and the blast radius
   turns FINANCE-DB *Suspected* as the attack unfolds.
7. **Validation** — 105 automated tests incl. known-answer scenarios and browser tests, 95 % coverage; measured timings;
   explicitly no accuracy claim (synthetic data only).
8. **Engineering** — FastAPI + NetworkX, React + React Flow, optional Neo4j adapter (parameterised Cypher), security
   controls, Docker, CI.
9. **Limits and next steps** — live AuraDB validation, real log connectors (Sysmon, Zeek, cloud audit logs),
   authentication, scale testing, calibrating weights on labelled incidents.
