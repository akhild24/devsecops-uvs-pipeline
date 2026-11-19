"""
Parser for Trivy JSON output (`trivy image --format json`).

Structure (relevant subset):
{
  "Results": [
    {
      "Target": "app:latest (alpine 3.19)",
      "Vulnerabilities": [
        {"Severity": "CRITICAL", ...},
        {"Severity": "HIGH", ...},
        ...
      ]
    },
    ...
  ]
}

Trivy natively reports UNKNOWN/LOW/MEDIUM/HIGH/CRITICAL. UNKNOWN is folded
into Low since it carries no actionable severity signal.
"""
from __future__ import annotations

from models import SeverityCounts, ToolFindings

_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "low",
}


def parse_trivy(raw: dict) -> ToolFindings:
    results = raw.get("Results", []) if isinstance(raw, dict) else []
    if not isinstance(results, list):
        results = []
    counts = SeverityCounts()
    finding_count = 0

    for result in results:
        if not isinstance(result, dict):
            continue
        vulnerabilities = result.get("Vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            continue
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue
            finding_count += 1
            severity_key = _SEVERITY_MAP.get(str(vuln.get("Severity", "")).upper(), "low")
            setattr(counts, severity_key, getattr(counts, severity_key) + 1)

    return ToolFindings(
        tool="trivy",
        counts=counts,
        mean_cvss=None,
        raw_finding_count=finding_count,
    )
