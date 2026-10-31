#!/usr/bin/env bash
# One-command local start (Linux/macOS): creates .venv, installs dependencies,
# builds the UI if Node.js is available and no build exists, then serves on http://127.0.0.1:8000
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PYTHON:-python3}
if [ ! -d .venv ]; then "$PY" -m venv .venv; fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q -r requirements.txt
if [ ! -f frontend/dist/index.html ]; then
  if command -v npm >/dev/null 2>&1; then
    (cd frontend && npm ci --no-audit --no-fund && npm run build)
  else
    echo "Node.js not found and frontend/dist is missing: the API will run, but the web UI needs 'npm run build' in frontend/." >&2
  fi
fi
cd backend
exec python -m attackgraph serve --host 127.0.0.1 --port "${PORT:-8000}"
