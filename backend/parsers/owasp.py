"""
Parser for OWASP Dependency-Check JSON output (`dependency-check-report.json`).

Structure (relevant subset):
{
  "dependencies": [
    {
      "vulnerabilities": [
        {
          "severity": "HIGH",             # or cvssv3/cvssv2 severity string
          "cvssv3": {"baseScore": 7.5},
          "cvssv2": {"score": 5.0}
        },
        ...
      ]
    },
    ...
  ]
}

We bucket by the tool-reported severity string and separately compute the
mean CVSS base score (v3 preferred, falling back to v2) across all
vulnerabilities, since the SCA component of the UVS model blends density
with mean CVSS.
"""
from __future__ import annotations

import math

from models import SeverityCounts, ToolFindings

_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "MODERATE": "medium",
    "LOW": "low",
}


def parse_owasp(raw: dict) -> ToolFindings:
    dependencies = raw.get("dependencies", []) if isinstance(raw, dict) else []
    if not isinstance(dependencies, list):
        dependencies = []
    counts = SeverityCounts()
    cvss_scores: list[float] = []
    finding_count = 0

    for dep in dependencies:
        if not isinstance(dep, dict):
            continue
        vulnerabilities = dep.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            continue
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue
            finding_count += 1
            severity_key = _SEVERITY_MAP.get(str(vuln.get("severity", "")).upper(), "medium")
            setattr(counts, severity_key, getattr(counts, severity_key) + 1)

            cvssv3 = vuln.get("cvssv3")
            cvssv2 = vuln.get("cvssv2")
            cvss3 = cvssv3.get("baseScore") if isinstance(cvssv3, dict) else None
            cvss2 = cvssv2.get("score") if isinstance(cvssv2, dict) else None
            score = cvss3 if cvss3 is not None else cvss2
            if score is not None:
                try:
                    numeric_score = float(score)
                except (TypeError, ValueError):
                    continue
                if math.isfinite(numeric_score) and 0 <= numeric_score <= 10:
                    cvss_scores.append(numeric_score)

    mean_cvss = round(sum(cvss_scores) / len(cvss_scores), 2) if cvss_scores else None

    return ToolFindings(
        tool="owasp-dependency-check",
        counts=counts,
        mean_cvss=mean_cvss,
        raw_finding_count=finding_count,
    )
