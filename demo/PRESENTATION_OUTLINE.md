# Presentation outline

The finished deck is `submission/AttackGraph_Lens_T2_Final.pptx` (20 slides, speaker notes on every slide), with a PDF
export alongside and slide-by-slide changes in `submission/PPT_Change_Log.md`.

**Problem and positioning**
1. Cover: from fragmented security events to explainable attack paths and blast-radius intelligence.
2. The problem: seven feeds, seven partial views; T2.1 asks for attack paths, a real-time blast radius and one incident picture.
3. The insight: connectivity is not compromise. Time and evidence decide.

**Novelty, team and architecture**
4. Novelty: temporal feasibility, provenance-native evidence graph, evidence-tiered blast radius, multichannel
   corroboration, counterfactual time-aware containment. The building blocks are established; the integration is the contribution.
5. Team track record: design philosophy inspired by UniAethel, a previous cybersecurity tool shortlisted at SUTRAM 2026
   by NFSU. Separate project; no code, data or results reused.
6. System architecture: six layers around one temporal knowledge graph, plus the live path and graph storage.
7. End to end: six stages, the source-to-graph mapping and the reconciled counts.

**Technical implementation**
8. Worked example: EDR-000399 becomes one evidence-backed edge.
9. Suspicion criterion: s = max(native, alert, 0.8 × proximity, MD) ≥ 0.5.
10. Mahalanobis behavioural deviation: features, robust baseline, shrinkage, D², bounded score.
11. Temporal attack paths: skew and maximum-gap rule; the backup route is rejected.
12. Explainable risk score: six weighted components; a prioritisation score, not a probability.
13. Blast radius: four evidence tiers; attacker vs IT admin.
14. Incident correlation: 8 alerts from 6 sources become INC-0002.
15. Multichannel corroboration: six channels per step; silent vs blind.

**Response and validation**
16. Counterfactual containment: the plan depends on when you act. Advisory only.
17. Real-time processing: push API, micro-batches, Server-Sent Events.
18. Validation: 105 tests, 95 % coverage, known answers; what is not claimed.
19. Engineering, limits and roadmap.
20. Summary: three questions, three traceable answers.
