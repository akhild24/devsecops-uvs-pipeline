"""Offline-first EPSS probability lookup from a local JSON snapshot."""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)
DEFAULT_EPSS_PATH = Path(__file__).resolve().parents[1] / "data" / "epss.json"


def get_epss_scores(path: str | Path | None = None) -> dict[str, float]:
    catalog_path = Path(path or os.getenv("EPSS_DATA_PATH", DEFAULT_EPSS_PATH))
    try:
        data = json.loads(catalog_path.read_text(encoding="utf-8"))
        raw = data.get("scores", data) if isinstance(data, dict) else {}
        scores = {}
        for cve, value in raw.items():
            score = float(value)
            if 0 <= score <= 1:
                scores[str(cve).upper()] = score
        return scores
    except (OSError, ValueError, TypeError) as exc:
        logger.warning("Could not load local EPSS catalog at %s: %s", catalog_path, exc)
        return {}


def get_epss_alpha() -> float:
    value = float(os.getenv("EPSS_ALPHA", "1.0"))
    if not 0 <= value < float("inf"):
        raise ValueError("EPSS_ALPHA must be finite and non-negative")
    return value


def get_kev_multiplier() -> float:
    value = float(os.getenv("KEV_MULTIPLIER", "1.25"))
    if not 1 <= value < float("inf"):
        raise ValueError("KEV_MULTIPLIER must be finite and at least 1")
    return value
