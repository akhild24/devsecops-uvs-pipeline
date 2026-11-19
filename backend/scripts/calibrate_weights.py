"""Compare score/rank sensitivity on the bundled synthetic sample commits."""
from __future__ import annotations

import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parent
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(ROOT))

from models import Environment
from parsers.owasp import parse_owasp
from parsers.semgrep import parse_semgrep
from parsers.trivy import parse_trivy
from scripts.post_samples import SAMPLES
from services.epss import get_epss_scores
from services.findings import effective_finding_points, normalize_scan_findings
from scoring import compute_uvs_score

WEIGHT_SETS = {
    "default": (0.35, 0.40, 0.25),
    "equal": (1 / 3, 1 / 3, 1 / 3),
    "SCA-heavy": (0.25, 0.55, 0.20),
    "SAST-heavy": (0.55, 0.25, 0.20),
}


def main() -> None:
    catalog = get_epss_scores()
    records = []
    for payload in SAMPLES:
        findings = normalize_scan_findings(payload["owasp_raw"], payload["trivy_raw"], set(), catalog)
        owasp = parse_owasp(payload["owasp_raw"])
        trivy = parse_trivy(payload["trivy_raw"])
        semgrep = parse_semgrep(payload["semgrep_raw"])
        for weight_name, weights in WEIGHT_SETS.items():
            for alpha in (0.0, 0.5, 1.0):
                for kev_on in (False, True):
                    result = compute_uvs_score(
                        semgrep.counts, owasp.counts, owasp.mean_cvss, trivy.counts,
                        Environment(payload["environment"]), None,
                        sca_points=effective_finding_points([f for f in findings if f["source_tool"] == "owasp"], 1.25 if kev_on else 1.0, alpha),
                        container_points=effective_finding_points([f for f in findings if f["source_tool"] == "trivy"], 1.25 if kev_on else 1.0, alpha),
                        weights=weights,
                    )
                    scenario = f"{weight_name}|a={alpha:g}|KEV={'on' if kev_on else 'off'}"
                    records.append((scenario, payload["repo"], payload["commit_sha"], result.final_score))
    for scenario in sorted({r[0] for r in records}):
        group = [r for r in records if r[0] == scenario]
        ranks = {row[2]: rank for rank, row in enumerate(sorted(group, key=lambda r: r[3], reverse=True), 1)}
        print(f"\n{scenario}\nrepo\tcommit\tscore\trank")
        for _, repo, sha, score in group:
            print(f"{repo}\t{sha}\t{score:.2f}\t{ranks[sha]}")


if __name__ == "__main__":
    main()
