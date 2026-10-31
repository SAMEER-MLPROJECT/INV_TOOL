# Presentation outline (6–8 slides)

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
5. **Live demo** — 3 minutes (DEMO_SCRIPT.md).
6. **Validation** — 85 automated tests incl. known-answer scenarios and browser tests, 93 % coverage; measured timings;
   explicitly no accuracy claim (synthetic data only).
7. **Engineering** — FastAPI + NetworkX, React + React Flow, optional Neo4j adapter (parameterised Cypher), security
   controls, Docker, CI.
8. **Limits and next steps** — live AuraDB validation, real log connectors (Sysmon, Zeek, cloud audit logs),
   authentication, scale testing, calibrating weights on labelled incidents.
