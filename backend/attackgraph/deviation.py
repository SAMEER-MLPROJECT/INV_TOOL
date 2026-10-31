from __future__ import annotations

import math
from collections import defaultdict

import numpy as np

from .models import RelType

FEATURES = ["hour_sin", "hour_cos", "volume", "novelty"]
FEATURE_LABELS = {"hour_sin": "time of day", "hour_cos": "time of day", "volume": "data volume", "novelty": "new relationship"}
SCORED_TYPES = {RelType.AUTHENTICATED_TO, RelType.CONNECTED_TO, RelType.COMMUNICATED_WITH, RelType.ACCESSED}
MIN_SAMPLES = 30
PAIR_MIN_SAMPLES = 20
SHRINKAGE = 0.2
D2_REFERENCE = 18.47
SUSPICION_CAP = 0.45


def chi2_4_sf(d2: float) -> float:
    h = d2 / 2.0
    return math.exp(-h) * (1.0 + h)


def _volume(raw: dict) -> float:
    for key in ("rows_returned", "bytes_out", "bytes"):
        v = raw.get(key)
        try:
            if v not in (None, ""):
                return math.log10(1.0 + max(float(v), 0.0))
        except (TypeError, ValueError):
            continue
    return 0.0


def score_deviations(g) -> dict:
    models = {}
    groups: dict[str, list] = defaultdict(list)
    for rel in g.rels.values():
        if rel.type in SCORED_TYPES:
            key = f"pair {rel.id}" if len(rel.occurrences) >= PAIR_MIN_SAMPLES else f"type {rel.type.value}"
            for i, occ in enumerate(rel.occurrences):
                groups[key].append((rel, i, occ))
    for key, items in groups.items():
        if len(items) < (PAIR_MIN_SAMPLES if key.startswith("pair") else MIN_SAMPLES):
            models[key] = {"samples": len(items), "scored": False, "reason": "insufficient history"}
            continue
        items.sort(key=lambda t: (t[2].timestamp, t[2].event_uid))
        seen: dict[str, int] = defaultdict(int)
        seen_before: dict[int, int] = {}
        rows, raw_vol = [], []
        for rel, _, occ in items:
            ev = g.events.get(occ.event_uid)
            ang = 2 * math.pi * (occ.timestamp.hour + occ.timestamp.minute / 60) / 24
            vol = _volume(ev.raw if ev else {})
            novelty = 0.0 if key.startswith("pair") else 1.0 / (1.0 + seen[rel.id])
            rows.append([math.sin(ang), math.cos(ang), vol, novelty])
            raw_vol.append(vol)
            seen_before[id(occ)] = seen[rel.id]
            seen[rel.id] += 1
        x = np.asarray(rows, dtype=float)
        med = np.median(x, axis=0)
        mad = 1.4826 * np.median(np.abs(x - med), axis=0)
        std = x.std(axis=0)
        scale = np.where(mad > 1e-9, mad, np.where(std > 1e-9, std, 1.0))
        z = (x - med) / scale
        cov = np.cov(z, rowvar=False)
        s = (1 - SHRINKAGE) * cov + SHRINKAGE * np.eye(len(FEATURES))
        inv = np.linalg.pinv(s)
        d2 = np.einsum("ij,jk,ik->i", z, inv, z)
        contrib = z * (z @ inv)
        typical_vol = 10 ** med[2] - 1
        for (rel, _, occ), dd, cc, xi in zip(items, d2, contrib, x):
            per = {f: float(c) for f, c in zip(FEATURES, cc)}
            grouped = {"time of day": per["hour_sin"] + per["hour_cos"], "data volume": per["volume"],
                       "new relationship": per["novelty"]}
            top = max(grouped, key=grouped.get)
            info = {"baseline": key, "d2": round(float(dd), 2), "reference_tail": float(f"{chi2_4_sf(float(dd)):.3g}"),
                    "top_factor": top, "contributions": {k: round(v, 2) for k, v in grouped.items()},
                    "hour_utc": occ.timestamp.strftime("%H:%M"), "volume": round(10 ** xi[2] - 1),
                    "typical_volume": round(typical_vol), "earlier_same_pair": seen_before[id(occ)]}
            info["explanation"] = _explain(info)
            occ.attributes["deviation"] = info
            if dd > D2_REFERENCE:
                s_dev = round(SUSPICION_CAP * min(1.0, (dd - D2_REFERENCE) / D2_REFERENCE), 3)
                if s_dev > occ.suspicion:
                    occ.suspicion = s_dev
                    occ.attributes["suspicion_rule"] = "R-SUSP-03"
        models[key] = {"samples": len(items), "scored": True, "median": [round(float(m), 3) for m in med],
                               "scale": [round(float(v), 3) for v in scale], "flagged": int((d2 > D2_REFERENCE).sum())}
    g.deviation_models = models
    return models


def _explain(info: dict) -> str:
    parts = []
    c = info["contributions"]
    if c["data volume"] > 2 and info["volume"] > info["typical_volume"]:
        parts.append(f"volume {info['volume']:,} vs baseline median {info['typical_volume']:,}")
    if c["time of day"] > 2:
        parts.append(f"unusual time {info['hour_utc']} UTC")
    if c["new relationship"] > 2:
        parts.append("first observation of this relationship" if info["earlier_same_pair"] == 0
                     else f"only {info['earlier_same_pair']} earlier observation(s)")
    if not parts:
        parts.append("within the normal range for this relationship type")
    return "; ".join(parts)


def top_deviations(g, limit: int = 20) -> list[dict]:
    rows = []
    for rel in g.rels.values():
        for occ in rel.occurrences:
            dev = occ.attributes.get("deviation")
            if dev and dev["d2"] > D2_REFERENCE:
                rows.append({"relationship_id": rel.id, "source": rel.source, "target": rel.target, "type": rel.type.value,
                             "event_uid": occ.event_uid, "timestamp": occ.timestamp.isoformat(),
                             "suspicion": round(occ.suspicion, 3), **dev})
    rows.sort(key=lambda r: -r["d2"])
    return rows[:limit]
