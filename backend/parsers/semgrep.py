"""
Parser for Semgrep OSS JSON output (`semgrep --json`).

Semgrep reports findings under `results[]`, each with
`extra.severity` in {"ERROR", "WARNING", "INFO"}. We map Semgrep's
3-level severity onto our 4-level Critical/High/Medium/Low scale:

    ERROR   -> High      (Semgrep has no built-in "Critical"; rules tagged
                           with metadata.severity=CRITICAL are promoted)
    WARNING -> Medium
    INFO    -> Low

A rule can opt into Critical via `extra.metadata.severity: "CRITICAL"`
(a common convention for curated rulesets like p/security-audit).
"""
from __future__ import annotations

from models import SeverityCounts, ToolFindings


def parse_semgrep(raw: dict) -> ToolFindings:
    results = raw.get("results", []) if isinstance(raw, dict) else []
    if not isinstance(results, list):
        results = []
    counts = SeverityCounts()

    for finding in results:
        if not isinstance(finding, dict):
            continue
        extra = finding.get("extra")
        extra = extra if isinstance(extra, dict) else {}
        metadata = extra.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        custom_severity = str(metadata.get("severity", "")).upper()
        semgrep_severity = str(extra.get("severity", "")).upper()

        if custom_severity == "CRITICAL":
            counts.critical += 1
        elif semgrep_severity == "ERROR":
            counts.high += 1
        elif semgrep_severity == "WARNING":
            counts.medium += 1
        else:  # INFO or unrecognized -> Low
            counts.low += 1

    return ToolFindings(
        tool="semgrep",
        counts=counts,
        mean_cvss=None,
        raw_finding_count=len(results),
    )
