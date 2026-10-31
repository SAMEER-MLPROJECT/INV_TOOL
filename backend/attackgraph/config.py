from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

REPO_ROOT = Path(__file__).resolve().parents[2]


def load_env_file(path: Path | None = None) -> int:
    path = path or REPO_ROOT / ".env"
    if not path.is_file():
        return 0
    n = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and key not in os.environ and value:
            os.environ[key] = value
            n += 1
    return n


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


class DeploymentConfig(BaseModel):
    sample_dir: Path = Field(default_factory=lambda: Path(os.environ.get("AGL_SAMPLE_DIR", REPO_ROOT / "data" / "sample")))
    upload_dir: Path = Field(default_factory=lambda: Path(os.environ.get("AGL_UPLOAD_DIR", REPO_ROOT / "data" / "uploads")))
    export_dir: Path = Field(default_factory=lambda: Path(os.environ.get("AGL_EXPORT_DIR", REPO_ROOT / "data" / "exports")))
    frontend_dist: Path = Field(default_factory=lambda: Path(os.environ.get("AGL_FRONTEND_DIST", REPO_ROOT / "frontend" / "dist")))
    max_upload_bytes: int = Field(default_factory=lambda: _env_int("AGL_MAX_UPLOAD_MB", 20) * 1024 * 1024)
    max_records_per_file: int = Field(default_factory=lambda: _env_int("AGL_MAX_RECORDS_PER_FILE", 200_000))
    graph_backend: str = Field(default_factory=lambda: os.environ.get("AGL_GRAPH_BACKEND", "memory").lower())
    neo4j_uri: str | None = Field(default_factory=lambda: os.environ.get("NEO4J_URI") or None)
    neo4j_user: str | None = Field(default_factory=lambda: os.environ.get("NEO4J_USERNAME") or None)
    neo4j_password: str | None = Field(default_factory=lambda: os.environ.get("NEO4J_PASSWORD") or None, repr=False)
    neo4j_database: str = Field(default_factory=lambda: os.environ.get("NEO4J_DATABASE", "neo4j"))


class RiskWeights(BaseModel):

    criticality: float = 0.25
    suspicion: float = 0.35
    corroboration: float = 0.15
    evidence_quality: float = 0.05
    path_length: float = 0.10
    recency: float = 0.10

    @field_validator("*")
    @classmethod
    def _non_negative(cls, v: float) -> float:
        if v < 0 or v > 10:
            raise ValueError("weights must be between 0 and 10")
        return float(v)

    def normalized(self) -> dict[str, float]:
        raw = self.model_dump()
        total = sum(raw.values()) or 1.0
        return {k: v / total for k, v in raw.items()}


class AnalysisSettings(BaseModel):
    correlation_window_minutes: int = Field(default=90, ge=1, le=7 * 24 * 60)
    clock_skew_seconds: int = Field(default=120, ge=0, le=3600)
    max_hop_gap_hours: float = Field(default=6.0, ge=0, le=24 * 30)
    default_max_hops: int = Field(default=5, ge=1, le=8)
    max_paths: int = Field(default=12, ge=1, le=100)
    search_budget: int = Field(default=50_000, ge=1_000, le=500_000)
    suspicion_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    recency_half_life_hours: float = Field(default=48.0, gt=0, le=24 * 365)
    weights: RiskWeights = Field(default_factory=RiskWeights)
