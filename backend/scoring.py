"""
Unified Vulnerability Scoring (UVS) Model
==========================================

Implements the formula defined in the PRD (Section 7):

    Raw Score   = (w1 * SAST_Score) + (w2 * SCA_Score) + (w3 * Container_Score)
    Final Score = min(
        100, (Raw Score + optional KEV bonus) * Environment_Multiplier * Delta_Factor
    )

Where each per-tool score is normalized to 0-100 using a severity-weighted
finding density, and SCA additionally considers mean CVSS of dependency
findings.

This module is pure Python with no I/O, so it is fully unit-testable in
isolation (see backend/tests/test_scoring.py).
"""
from __future__ import annotations

from dataclasses import dataclass
import math

from models import Environment, SeverityCounts

# --------------------------------------------------------------------------- #
# Tunable constants (Section 7 of the PRD)
# --------------------------------------------------------------------------- #
W_SAST = 0.35
W_SCA = 0.40
W_CONTAINER = 0.25

SEVERITY_WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1}

# A commit with this many severity-weighted "points" or more is treated as
# maximally risky (100) for the density normalization. Empirically tunable;
# starting value chosen so a handful of Criticals already saturates the score.
MAX_FINDING_POINTS = 50

ENVIRONMENT_MULTIPLIER = {
    Environment.dev: 1.0,
    Environment.staging: 1.1,
    Environment.prod: 1.3,
}

DELTA_IMPROVING = 0.9  # score dropped vs. previous commit -> reward
DELTA_REGRESSING_OR_FIRST = 1.0

RISK_BANDS = (
    (20, "Low", "No blocking — proceed to merge"),
    (50, "Medium", "Warning — review Critical/High findings before merge"),
    (75, "High", "Block merge — fix Critical findings first"),
    (100, "Critical", "Block merge — immediate remediation required"),
)


@dataclass
class UVSResult:
    sast_score: float
    sca_score: float
    container_score: float
    raw_score: float
    environment_multiplier: float
    delta_factor: float
    final_score: float
    risk_level: str
    recommended_action: str


def _severity_density_score(counts: SeverityCounts) -> float:
    """
    Weighted-finding density, normalized 0-100.

    points = critical*10 + high*5 + medium*2 + low*1
    score  = min(100, points / MAX_FINDING_POINTS * 100)
    """
    points = (
        counts.critical * SEVERITY_WEIGHTS["critical"]
        + counts.high * SEVERITY_WEIGHTS["high"]
        + counts.medium * SEVERITY_WEIGHTS["medium"]
        + counts.low * SEVERITY_WEIGHTS["low"]
    )
    return _points_density_score(points)


def _points_density_score(points: float) -> float:
    return min(100.0, (points / MAX_FINDING_POINTS) * 100.0)


def compute_sast_score(counts: SeverityCounts) -> float:
    """Semgrep findings -> 0-100."""
    return _severity_density_score(counts)


def compute_container_score(counts: SeverityCounts) -> float:
    """Trivy findings -> 0-100."""
    return _severity_density_score(counts)


def compute_sca_score(counts: SeverityCounts, mean_cvss: float | None) -> float:
    """
    OWASP Dependency-Check findings -> 0-100.

    Blends the severity-weighted density (as a fallback / stabilizer when
    CVSS data is sparse) with the mean CVSS of dependency findings scaled to
    0-100 (CVSS is natively 0-10). When mean_cvss is unavailable (e.g. zero
    findings), falls back purely to the density score.
    """
    density = _severity_density_score(counts)
    if mean_cvss is None or counts.total() == 0:
        return density
    cvss_component = min(100.0, (mean_cvss / 10.0) * 100.0)
    # Equal blend: CVSS reflects known severity, density reflects volume.
    return round(0.5 * density + 0.5 * cvss_component, 4)


def risk_band_for(score: float) -> tuple[str, str]:
    for upper_bound, level, action in RISK_BANDS:
        if score <= upper_bound:
            return level, action
    # Defensive fallback — should be unreachable given min(100, ...) clamping.
    return "Critical", "Block merge — immediate remediation required"


def compute_uvs_score(
    sast_counts: SeverityCounts,
    sca_counts: SeverityCounts,
    sca_mean_cvss: float | None,
    container_counts: SeverityCounts,
    environment: Environment,
    previous_final_score: float | None,
    sast_points: float | None = None,
    sca_points: float | None = None,
    container_points: float | None = None,
    weights: tuple[float, float, float] | None = None,
) -> UVSResult:
    """
    Compute the full Unified Vulnerability Score for a single commit.

    `previous_final_score` is the Final Score of the immediately preceding
    commit for the same repo (None for the first commit in a repo's history).
    `kev_bonus` is an explicit additive score bump (typically configured per
    known-exploited finding by the API); its default keeps existing scores
    unchanged. This function performs no configuration lookup or I/O.
    """
    sast_score = _points_density_score(sast_points) if sast_points is not None else compute_sast_score(sast_counts)
    sca_density = _points_density_score(sca_points) if sca_points is not None else _severity_density_score(sca_counts)
    if sca_mean_cvss is None or sca_counts.total() == 0:
        sca_score = sca_density
    else:
        sca_score = round(0.5 * sca_density + 0.5 * min(100.0, sca_mean_cvss * 10.0), 4)
    container_score = _points_density_score(container_points) if container_points is not None else compute_container_score(container_counts)

    weights = weights or (W_SAST, W_SCA, W_CONTAINER)
    raw_score = sum(weight * score for weight, score in zip(weights, (sast_score, sca_score, container_score)))
    adjusted_raw_score = raw_score

    env_multiplier = ENVIRONMENT_MULTIPLIER[environment]

    if previous_final_score is None:
        delta_factor = DELTA_REGRESSING_OR_FIRST
    else:
        # "Improving" means raw_score (pre-multiplier trend) is lower than
        # last commit's final score -> reward with a 0.9 multiplier.
        delta_factor = (
            DELTA_IMPROVING
            if adjusted_raw_score < previous_final_score
            else DELTA_REGRESSING_OR_FIRST
        )

    final_score = min(100.0, adjusted_raw_score * env_multiplier * delta_factor)
    risk_level, action = risk_band_for(final_score)

    return UVSResult(
        sast_score=round(sast_score, 4),
        sca_score=round(sca_score, 4),
        container_score=round(container_score, 4),
        raw_score=round(raw_score, 4),
        environment_multiplier=env_multiplier,
        delta_factor=delta_factor,
        final_score=round(final_score, 4),
        risk_level=risk_level,
        recommended_action=action,
    )
