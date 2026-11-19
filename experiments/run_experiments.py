#!/usr/bin/env python3
"""
Phase 5 experiment harness (PRD Section 10, Phase 5 / Synopsis Section 5).

Purpose
-------
Run the UVS model across a set of repositories' commit histories and compare
it against raw mean-CVSS-only prioritization, producing the tables this
project's research paper needs for its Experiments section.

IMPORTANT — what this script does and does not do
---------------------------------------------------
This harness does NOT invoke live Semgrep/Trivy/OWASP Dependency-Check
scans against external GitHub repositories — that requires installing the
tools, cloning repos, and running scans that can take 20+ minutes per repo
(see PRD Section 14 risk: "OWASP Dep-Check slow on large repos"), which is
outside what a single offline session can execute.

Instead, it generates *synthetic but structurally realistic* scan histories
--- each with a believable mix of severities, environments, and a plausible
"code is trending better/worse" pattern across 10 commits per repo --- feeds
them through the REAL scoring.py and parsers.py used in production, and
computes the same statistics the paper needs (Pearson r, prioritization
agreement, score distributions).

Before writing the paper's Experiments section, replace `generate_synthetic_dataset()`
with real scans: run the GitHub Actions workflow (or scanners locally) against
your chosen 5-8 OSS repos' last 10 commits, save each tool's JSON output under
experiments/data/<repo>/<sha>/{semgrep,owasp,trivy}.json, and point
`load_real_dataset()` (stubbed below) at that directory instead.

Usage:
    python3 experiments/run_experiments.py
    python3 experiments/run_experiments.py --repos 8 --commits 10 --seed 42
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import random
import sys
from dataclasses import asdict, dataclass

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from models import Environment, SeverityCounts  # noqa: E402
from scoring import compute_uvs_score, risk_band_for  # noqa: E402

REPO_NAMES = [
    "acme/payments-service",
    "acme/auth-gateway",
    "acme/inventory-api",
    "acme/notification-worker",
    "acme/legacy-monolith",
    "acme/mobile-bff",
    "acme/data-pipeline",
    "acme/admin-portal",
]

LANGUAGES = ["Python", "JavaScript", "Java", "Go", "Python", "TypeScript", "Python", "Java"]


@dataclass
class SyntheticCommit:
    repo: str
    language: str
    commit_index: int
    environment: str
    sast_counts: SeverityCounts
    sca_counts: SeverityCounts
    sca_mean_cvss: float
    container_counts: SeverityCounts


def generate_synthetic_dataset(n_repos: int, n_commits: int, seed: int) -> list[SyntheticCommit]:
    """
    Generates a plausible dataset: each repo starts moderately vulnerable and
    trends toward improvement (mirroring a team responding to the dashboard),
    with occasional regression commits, matching the kind of trajectory the
    PRD's delta-tracking feature is meant to reward/penalize.
    """
    rng = random.Random(seed)
    dataset: list[SyntheticCommit] = []

    for i in range(min(n_repos, len(REPO_NAMES))):
        repo = REPO_NAMES[i]
        lang = LANGUAGES[i]
        # Each repo gets a starting "badness" level and a trend direction
        base_criticals = rng.randint(0, 4)
        base_highs = rng.randint(1, 8)
        trend = rng.choice([-1, -1, 1])  # 2/3 chance of improving over time

        for c in range(n_commits):
            drift = max(0, trend * c // 3)
            sast_counts = SeverityCounts(
                critical=max(0, base_criticals - drift + rng.randint(-1, 1)),
                high=max(0, base_highs - drift + rng.randint(-2, 2)),
                medium=rng.randint(2, 12),
                low=rng.randint(0, 15),
            )
            sca_counts = SeverityCounts(
                critical=max(0, rng.randint(0, 3) - drift // 2),
                high=rng.randint(1, 6),
                medium=rng.randint(0, 8),
                low=rng.randint(0, 5),
            )
            container_counts = SeverityCounts(
                critical=max(0, rng.randint(0, 2) - drift // 2),
                high=rng.randint(0, 5),
                medium=rng.randint(1, 10),
                low=rng.randint(0, 10),
            )
            sca_mean_cvss = round(min(10.0, max(0.0, rng.gauss(6.0 - drift * 0.3, 1.5))), 2)
            environment = rng.choice(["dev", "dev", "staging", "prod"])

            dataset.append(
                SyntheticCommit(
                    repo=repo,
                    language=lang,
                    commit_index=c,
                    environment=environment,
                    sast_counts=sast_counts,
                    sca_counts=sca_counts,
                    sca_mean_cvss=sca_mean_cvss,
                    container_counts=container_counts,
                )
            )
    return dataset


def raw_cvss_baseline(commit: SyntheticCommit) -> float:
    """
    Naive baseline for comparison: mean CVSS scaled to 0-100, ignoring
    reachability/environment/delta context entirely — this is what the
    UVS model is designed to improve on.
    """
    return min(100.0, (commit.sca_mean_cvss / 10.0) * 100.0)


def pearson_r(xs: list[float], ys: list[float]) -> float:
    n = len(xs)
    if n < 2:
        return float("nan")
    mean_x, mean_y = sum(xs) / n, sum(ys) / n
    cov = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    var_x = sum((x - mean_x) ** 2 for x in xs)
    var_y = sum((y - mean_y) ** 2 for y in ys)
    denom = (var_x * var_y) ** 0.5
    return cov / denom if denom else float("nan")


def run(n_repos: int, n_commits: int, seed: int, out_dir: str) -> None:
    dataset = generate_synthetic_dataset(n_repos, n_commits, seed)
    os.makedirs(out_dir, exist_ok=True)

    rows = []
    previous_score_by_repo: dict[str, float | None] = {}

    for commit in dataset:
        prev = previous_score_by_repo.get(commit.repo)
        result = compute_uvs_score(
            sast_counts=commit.sast_counts,
            sca_counts=commit.sca_counts,
            sca_mean_cvss=commit.sca_mean_cvss,
            container_counts=commit.container_counts,
            environment=Environment(commit.environment),
            previous_final_score=prev,
        )
        previous_score_by_repo[commit.repo] = result.final_score
        baseline = raw_cvss_baseline(commit)

        rows.append(
            {
                "repo": commit.repo,
                "language": commit.language,
                "commit_index": commit.commit_index,
                "environment": commit.environment,
                "uvs_final_score": result.final_score,
                "uvs_risk_level": result.risk_level,
                "raw_cvss_baseline": round(baseline, 2),
                "sast_score": result.sast_score,
                "sca_score": result.sca_score,
                "container_score": result.container_score,
                "environment_multiplier": result.environment_multiplier,
                "delta_factor": result.delta_factor,
                "total_findings": (
                    commit.sast_counts.total() + commit.sca_counts.total() + commit.container_counts.total()
                ),
            }
        )

    # --- write raw results CSV (paper's data appendix / Table format) ---
    csv_path = os.path.join(out_dir, "results.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    # --- summary statistics ---
    uvs_scores = [r["uvs_final_score"] for r in rows]
    cvss_scores = [r["raw_cvss_baseline"] for r in rows]
    r_value = pearson_r(uvs_scores, cvss_scores)

    risk_dist: dict[str, int] = {}
    for r in rows:
        risk_dist[r["uvs_risk_level"]] = risk_dist.get(r["uvs_risk_level"], 0) + 1

    # Prioritization disagreement: commits where UVS and raw-CVSS baseline
    # disagree on whether the commit should block a merge (UVS >50 vs
    # baseline >50 threshold), illustrating cases where context changed the
    # outcome.
    disagreements = sum(
        1 for r in rows if (r["uvs_final_score"] > 50) != (r["raw_cvss_baseline"] > 50)
    )

    summary = {
        "repos_tested": min(n_repos, len(REPO_NAMES)),
        "commits_per_repo": n_commits,
        "total_commits": len(rows),
        "pearson_r_uvs_vs_raw_cvss": round(r_value, 4),
        "risk_level_distribution": risk_dist,
        "prioritization_disagreements": disagreements,
        "prioritization_disagreement_rate": round(disagreements / len(rows), 4),
        "mean_uvs_score": round(sum(uvs_scores) / len(uvs_scores), 2),
        "mean_raw_cvss_baseline": round(sum(cvss_scores) / len(cvss_scores), 2),
    }

    summary_path = os.path.join(out_dir, "summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"Wrote {len(rows)} scored commits across {summary['repos_tested']} repos to {csv_path}")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repos", type=int, default=8)
    parser.add_argument("--commits", type=int, default=10)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "data"))
    args = parser.parse_args()
    run(args.repos, args.commits, args.seed, args.out)
