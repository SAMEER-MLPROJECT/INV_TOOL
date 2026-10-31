"""Transparent, deterministic priority scoring.

    score = 100 * sum_k  w_k * c_k        with  sum_k w_k = 1  and every c_k in [0, 1]

The score is a *triage ranking*, not a probability that an attack happened. Every score
is returned with its full component breakdown so an analyst can see exactly why one
item outranks another. Formulas and default weights are documented in docs/METHODOLOGY.md.
"""
from __future__ import annotations

import math
from datetime import datetime

from .config import RiskWeights

PRIORITY_BANDS = [(75.0, "Critical"), (55.0, "High"), (35.0, "Moderate"), (0.0, "Low")]

COMPONENT_LABELS = {
    "criticality": "Asset criticality",
    "suspicion": "Event suspicion",
    "corroboration": "Independent corroboration",
    "evidence_quality": "Evidence quality",
    "path_length": "Path compactness",
    "recency": "Recency",
}


def priority_label(score: float) -> str:
    for threshold, label in PRIORITY_BANDS:
        if score >= threshold:
            return label
    return "Low"


def length_factor(hops: int) -> float:
    """1 hop -> 1.0, 4 hops -> 0.57, 8 hops -> 0.36."""
    return 1.0 / (1.0 + 0.25 * max(hops - 1, 0))


def recency_factor(last: datetime | None, reference: datetime | None, half_life_hours: float) -> float:
    """Exponential decay relative to the newest event in the dataset (not the wall clock),
    so results are reproducible no matter when the analysis is run."""
    if last is None or reference is None:
        return 0.0
    age_h = max((reference - last).total_seconds() / 3600.0, 0.0)
    return math.pow(0.5, age_h / half_life_hours)


def corroboration_factor(independent_sources: int) -> float:
    """Distinct *source systems* (not records): 1 -> 0.25 ... 4+ -> 1.0."""
    return min(independent_sources, 4) / 4.0


def score(components: dict[str, float], weights: RiskWeights, notes: dict[str, str] | None = None) -> dict:
    w = weights.normalized()
    breakdown = []
    total = 0.0
    for key in COMPONENT_LABELS:
        value = max(0.0, min(1.0, float(components.get(key, 0.0))))
        contribution = 100.0 * w[key] * value
        total += contribution
        breakdown.append({
            "component": key,
            "label": COMPONENT_LABELS[key],
            "value": round(value, 3),
            "weight": round(w[key], 3),
            "contribution": round(contribution, 1),
            "explanation": (notes or {}).get(key, ""),
        })
    total = round(total, 1)
    return {"score": total, "priority": priority_label(total), "breakdown": breakdown,
            "disclaimer": "Heuristic triage ranking; not a calibrated probability of compromise."}
