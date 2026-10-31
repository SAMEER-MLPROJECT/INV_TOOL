# Repository map

How the repository is laid out, and where each part of the T2.1 GraphOps problem statement and each judging
dimension is answered.

## 1. Structure

```
attackgraph-lens/
├── README.md                     overview, quick start, sample workflow
├── LICENSE                       MIT
├── SECURITY.md                   security controls and reporting
├── CONTRIBUTING.md               how to contribute
├── requirements.txt              runtime Python dependencies
├── requirements-dev.txt          test and lint dependencies
├── .env.example                  configuration template (no secrets)
├── Dockerfile, docker-compose.yml, .dockerignore
├── .github/workflows/ci.yml      CI: lint, tests, frontend build
│
├── backend/
│   ├── pyproject.toml
│   ├── attackgraph/              the engine (Python package)
│   │   ├── __main__.py           CLI: serve, analyze, path
│   │   ├── config.py             settings, weights, environment variables
│   │   ├── models.py             entities, relationships, occurrences, events
│   │   ├── rules.py              the published rules (R-AUTH, R-NET, R-SUSP, R-COR, ...)
│   │   ├── ingest/
│   │   │   ├── sources.py        one adapter per source format
│   │   │   ├── normalize.py      UTC time, severity words, identifiers
│   │   │   └── loader.py         validation, duplicates, conflicts, file hashes
│   │   ├── graph/
│   │   │   ├── builder.py        temporal knowledge graph, IP to host resolution
│   │   │   ├── paths.py          time-feasible attack paths, rejected routes
│   │   │   └── blast.py          blast radius with four evidence tiers
│   │   ├── deviation.py          MD behavioural deviation (robust Mahalanobis)
│   │   ├── correlate.py          alerts and signals into incidents (union-find)
│   │   ├── channels.py           multichannel corroboration
│   │   ├── containment.py        counterfactual containment planner and what-if
│   │   ├── risk.py               explained priority score
│   │   ├── narrative.py          plain-language explanations
│   │   ├── evidence.py           provenance and SHA-256 manifest
│   │   ├── report.py             HTML, Markdown and JSON reports
│   │   ├── live.py               push API, micro-batching, replay
│   │   ├── workspace.py          ties the pieces together for the API
│   │   ├── api/app.py            FastAPI endpoints, Server-Sent Events
│   │   └── store/neo4j_store.py  optional Neo4j adapter (parameterised Cypher)
│   └── tests/                    105 tests (unit, API, known-answer, live, browser)
│
├── frontend/                     React 19 + TypeScript user interface
│   └── src/
│       ├── App.tsx               layout, sidebar, live indicator
│       ├── pages/                Overview, Live Monitor, Attack Graph, Attack Paths,
│       │                         Blast Radius, Incidents, Evidence, Settings & Data
│       ├── components/           GraphCanvas, Inspector, PathChain, ChannelMatrix,
│       │                         Containment, Charts, EntityPicker, ui
│       └── lib/                  API client, types, hooks, live updates
│
├── data/sample/                  synthetic enterprise dataset (7 files)
│   └── EXPECTED_OUTCOMES.md      the answers the tests check
│
├── scripts/
│   ├── run_local.sh / .ps1       one-command start
│   ├── generate_sample_data.py   deterministic dataset generator
│   ├── benchmark.py              timing measurements
│   └── capture_screenshots.py    regenerates docs/screenshots
│
├── docs/
│   ├── TECHNICAL_ARCHITECTURE.md  components and data flow
│   ├── METHODOLOGY.md             the math and rules, section by section
│   ├── VALIDATION_REPORT.md       test list, timings, what was not measured
│   ├── NOVELTY.md                 what is new and what is standard
│   ├── LIMITATIONS.md             honest limits
│   ├── AI_AND_THIRD_PARTY_DISCLOSURE.md
│   ├── DEVELOPMENT_LOG.md, RELEASE_NOTES.md, REPO_MAP.md
│   ├── architecture.svg / .png
│   └── screenshots/               13 screenshots of the running app
│
├── demo/
│   ├── attackgraph_lens_demo.mp4  recorded walkthrough of the real app
│   ├── record_demo.py             the script that records it
│   ├── DEMO_SCRIPT.md, RECORDING_CHECKLIST.md, PRESENTATION_OUTLINE.md
│   └── sample_incident_report_INC-0002.*, sample_evidence_manifest.json
│
└── submission/
    ├── AttackGraph_Lens_T2_Final.pptx / .pdf   20-slide presentation and its PDF export
    ├── Architecture_Flowchart.svg / .mmd       standalone architecture diagram + Mermaid source
    └── PPT_Change_Log.md                       slide-by-slide changes and open points
```

## 2. Problem statement to code

| T2.1 asks for | Engine | API | Screen | Tests | Explained in |
|---|---|---|---|---|---|
| Map attack paths | `graph/paths.py`, `risk.py` | `POST /api/paths` | Attack Paths | `test_paths.py`, `test_sample_dataset.py` | METHODOLOGY §2, §3, §6 |
| Blast radius in real time | `graph/blast.py`, `live.py` | `GET /api/blast-radius/{id}`, `/api/stream/*` | Blast Radius, Live Monitor | `test_blast.py`, `test_live.py` | METHODOLOGY §4, §10 |
| One clear incident picture | `correlate.py`, `channels.py`, `containment.py`, `report.py` | `GET /api/incidents/{id}`, `/containment`, `/report` | Incidents, Evidence | `test_correlation.py`, `test_novelty.py`, `test_api.py` | METHODOLOGY §5, §8, §9 |
| Evidence behind every conclusion | `evidence.py`, `ingest/loader.py` | `GET /api/events/{uid}`, `/api/evidence/manifest` | Inspector, Evidence | `test_ingest.py`, `test_api.py` | TECHNICAL_ARCHITECTURE |
| Graph backend (Neo4j track) | `store/neo4j_store.py` | `POST /api/backend/neo4j/sync` | Settings & Data | `test_neo4j_adapter.py` | README "Neo4j (optional)" |

## 3. Judging dimensions to evidence

| Dimension | Where to look |
|---|---|
| Problem statement and track alignment | Section 2 above; README "Features"; slides 2, 17 and 20 |
| Innovation and solution effectiveness | `docs/NOVELTY.md`; `deviation.py`, `channels.py`, `containment.py`; slides 4, 9, 10, 15, 16 |
| Technical implementation and code quality | `backend/attackgraph/`, `frontend/src/`; strict TypeScript; ruff; CI workflow |
| Functionality and prototype validation | `docs/VALIDATION_REPORT.md`; `backend/tests/`; `data/sample/EXPECTED_OUTCOMES.md`; demo video |
| Critical thinking and practical implementation | rejected impossible routes; four evidence tiers; capped MD score; `docs/LIMITATIONS.md` |
