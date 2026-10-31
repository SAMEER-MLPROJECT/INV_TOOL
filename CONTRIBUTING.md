# Contributing

1. **Fork and branch** from `main`: `git checkout -b feat/<short-name>`.
2. **Set up**
   ```bash
   python -m venv .venv && source .venv/bin/activate
   pip install -r requirements-dev.txt && python -m playwright install chromium
   cd frontend && npm ci && cd ..
   ```
3. **Develop**: API: `cd backend && python -m attackgraph serve`; UI with hot reload: `cd frontend && npm run dev`
   (proxies `/api` to port 8000).
4. **Keep the explainability contract.** Any new graph element, suspicion source or correlation link must cite a rule
   in `backend/attackgraph/rules.py` and remain traceable to source records. New log sources are added as one
   adapter in `ingest/sources.py`.
5. **Test**: add tests next to the feature, ideally a known-answer case:
   ```bash
   cd backend && pytest && cd ../frontend && npm run build
   ruff check backend/attackgraph backend/tests scripts --select E,F,W,B,I --ignore E501,B008,B905,B007,E741
   ```
   If you change the generator, regenerate `data/sample/` and update `EXPECTED_OUTCOMES.md`.
6. **Commit** with clear messages (`area: what and why`), never including data from real environments or secrets.
7. **Open a pull request** describing the change, how it was tested and any limitation it introduces. CI must pass.

Do not report measured accuracy, latency or user feedback in documentation unless you include the dataset and the
method used to obtain it.
