$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
if (-not (Test-Path ".venv")) { python -m venv .venv }
& .\.venv\Scripts\python.exe -m pip install -q -r requirements.txt
if (-not (Test-Path "frontend\dist\index.html")) {
  if (Get-Command npm -ErrorAction SilentlyContinue) {
    Push-Location frontend; npm ci --no-audit --no-fund; npm run build; Pop-Location
  } else {
    Write-Warning "Node.js not found and frontend\dist is missing: the API will run, but the UI needs 'npm run build' in frontend\."
  }
}
Set-Location backend
& ..\.venv\Scripts\python.exe -m attackgraph serve --host 127.0.0.1 --port 8000
