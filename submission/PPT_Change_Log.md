# PPT change log: AttackGraph_Lens_T2_Presentation.pptx (19 slides) → AttackGraph_Lens_T2_Final.pptx (20 slides)

The final deck was produced by editing the generator of the original deck, so the original visual identity
(dark navy, cyan, amber, red, green; "WHY" box on each slide; judging-dimension tag) and every chart, screenshot
and worked example are carried over. All numbers were re-checked against the running application.

## Slide map

| Final | Title | From original | Change |
|---|---|---|---|
| 1 | AttackGraph Lens (cover) | 1 | New subtitle and competition line; chain visual kept; "|" separators |
| 2 | Alerts arrive in pieces; the attack happens as a chain | 2 | Asks renamed: attack-path discovery, real-time blast radius, unified incident intelligence |
| 3 | Connectivity is not compromise: time and evidence decide | 3 | Rules renamed "Temporal feasibility" and "Evidence provenance"; valid vs impossible route kept |
| 4 | Where AttackGraph Lens goes beyond conventional graph-based security analysis | new | Five contribution areas A to E, the differentiator line, the defensible novelty statement, and a note that the building blocks are established techniques |
| 5 | Built on previous cybersecurity work, designed for explainable investigation | new | UniAethel lineage (see "Team slide" below) |
| 6 | Six layers around one temporal knowledge graph | new (replaces part of 4) | Native, editable architecture flowchart: 6 layers, 7 engines, decision layer, outputs, live path, graph storage. Mahalanobis drawn dashed amber as a supporting module; Neo4j labelled optional and not live-validated |
| 7 | Input → output in six stages, each with one job | 4 + 5 merged | Six stages kept; source-to-graph table kept in compact form; new count-reconciliation strip |
| 8 | One raw record becomes one explainable graph edge | 6 | Panels relabelled raw → normalise + resolve → evidence-backed edge; process, destination IP and inferred host shown separately |
| 9 | Suspicion = the strongest of four signals reaches 0.5 | 7 | Formula, four signals, both worked examples and the max-not-average reasoning kept |
| 10 | How unusual is this behaviour against its own history? (Mahalanobis) | 8 | Kept as a dedicated main-deck slide directly after suspicion. Full method kept (features, baseline, robust z, shrinkage, D², 18.47, bounded score) with a one-line purpose under each formula; chart kept; statement that the distance is a standard measure |
| 11 | A path is valid only if every step can follow the previous one | 9 | Skew and max-gap rule, valid path, rejected backup route and reason kept; timings labelled as synthetic-dataset measurements |
| 12 | Every point of the score is visible and explained | 10 | Model, weights and breakdown kept; "explainable prioritisation score, not a calibrated probability of compromise" added |
| 13 | Same reach, different meaning: four evidence tiers | 11 | Tier names now use the code identifiers (CONFIRMED_COMPROMISE etc.); attacker vs admin chart kept |
| 14 | 8 alerts from 6 sources become one incident: INC-0002 | 12 | Timeline, R-COR-01/02/03 and hub exclusion kept; Critical 92.6 re-verified |
| 15 | Who else saw it? Six independent channels per step | 13 | Matrix cells now carry symbols as well as colour (■ primary, ● corroborating, "none"); "silent" defined as an investigative lead, not proof |
| 16 | What to cut depends on when you act | 14 | Both scenarios kept; method spelled out; advisory-only language added |
| 17 | The picture builds while the attack is still happening | 15 | Streaming chain kept; 38.6 ms marked as a replay measurement on the synthetic data |
| 18 | What we demonstrated, and what we do not claim | 16 | All stats and known-answer checks kept; timings footnoted as medians of 5 runs on one machine |
| 19 | Built to be run and trusted, with its limits stated | 17 + 18 merged | Engineering, limits and next steps in three columns; AI-assistance disclosure kept |
| 20 | T2.1 asked three questions. Each has a traceable answer. | 19 | Outcomes reworded per brief; closing line; only verified file locations cited |

## Content preserved

Every formula, threshold, rule ID, worked example (EDR-000399, backup MD case, hypothesis #2, BKP-01 rejection,
INC-0002, both containment times), chart and screenshot from the original deck is present. Speaker notes are on
every slide.

## Long dashes

All em dashes and en dashes were removed from slide text and speaker notes (0 remaining, checked by extracting all
text). Ranges such as "1 to 5" became "1 to 5". Titles requested with a dash in the brief use a colon instead.

## Team slide (UniAethel)

- Uses the exact framing supplied: "Design philosophy inspired by UniAethel, a previous cybersecurity tool
  shortlisted at SUTRAM 2026 by NFSU."
- States that UniAethel is a separate project, that no UniAethel code, data or results are reused, and that the
  shortlist does not validate AttackGraph Lens and does not imply NFSU development, endorsement or review.
- No team member names, logos, certificates or rankings were added.
- The slide carries no judging-dimension tag, because team credibility is not one of the five official dimensions.

## Count reconciliation (resolved)

Checked against `/api/summary` and `/api/datasets`:

| Count | Meaning |
|---|---|
| 1,258 | rows read across all 7 files |
| 1,251 | accepted (1,258 − 5 rejected − 1 duplicate − 1 ID conflict) |
| 60 | of the accepted rows are asset-inventory reference records, not events |
| 1,191 | events (1,251 − 60) |
| 1,625 | relationship occurrences produced by those events (one event can create several) |
| 968 | distinct typed relationships |
| 349 | entities |

Slide 7 shows this chain explicitly. Test count (105) and coverage (95 %) match `docs/VALIDATION_REPORT.md`.

## Open points and deviations from the brief

1. **UniAethel PDF not supplied.** Only the text brief was attached, so no UniAethel excerpt or visual is used. The
   original project directive also asked not to reuse UniAethel presentation material. The SUTRAM 2026 / NFSU
   shortlist is stated as supplied by the team and has not been independently verified here.
2. **"Normal logon" example.** The brief mentions a normal logon among the Mahalanobis examples. The logon in the
   chart is the attacker's off-hours logon (sameer → WS-014), so it is labelled that way rather than as normal.
3. **Score rounding.** The six component points shown (25.0 + 28.2 + 15.0 + 3.8 + 5.7 + 8.1) sum to 85.8 because
   each is rounded; the application's unrounded total is 85.7. The chart title says the points are rounded.
4. **Title case.** The deck keeps sentence case throughout for consistency; wording follows the brief.
5. **Architecture title.** The kicker reads "System architecture"; the headline states the slide's message
   ("Six layers around one temporal knowledge graph").
6. **PDF.** Exported with LibreOffice, which substitutes metric-compatible fonts for Calibri; PowerPoint renders
   the .pptx with the original fonts.

## QA performed

- File validation (schema, relationships, charts): passed.
- All 20 slides rendered to images and inspected; text overflow fixed on slides 6, 7, 10, 12 and 19.
- Equations and subscripts checked on slides 9, 10, 11 and 12.
- Arrows and flow checked on slides 3, 6, 7 and 8; screenshots legible on 16 and 17.
- Page numbers 2 to 20 present on every content slide.
- Mahalanobis present as dedicated main-deck slide 10, immediately after suspicion (slide 9).
- No new technical or achievement claims beyond the application, its tests and the facts supplied by the team.
