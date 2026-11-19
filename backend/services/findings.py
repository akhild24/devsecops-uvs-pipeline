from __future__ import annotations

import re
from typing import Any

_CVE_PATTERN = re.compile(r"CVE-(?:\d{4}-\d+|DEMO-\d+)", re.IGNORECASE)
_OWASP_SEVERITIES = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "MODERATE": "medium",
    "LOW": "low",
}
_TRIVY_SEVERITIES = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "low",
}


def owasp_package(dependency: dict[str, Any]) -> tuple[str | None, str | None]:
    packages = dependency.get("packages")
    packages = packages if isinstance(packages, list) else []
    package = packages[0] if packages and isinstance(packages[0], dict) else {}
    package_id = str(package.get("id") or "")
    name = package.get("name")
    version = package.get("version")

    if package_id.startswith("pkg:"):
        package_part = package_id.split("/", 1)[-1]
        package_part, separator, package_version = package_part.rpartition("@")
        if not separator:
            package_part = package_id.split("/", 1)[-1]
        name = name or package_part.rsplit("/", 1)[-1]
        version = version or (package_version if separator else None)
    elif package_id:
        name = name or package_id

    name = name or dependency.get("fileName")
    return (str(name) if name else None, str(version) if version else None)


def cve_id(finding: dict[str, Any]) -> str | None:
    for key in ("VulnerabilityID", "name", "cve", "cveID", "vulnerabilityId"):
        value = finding.get(key)
        if value:
            match = _CVE_PATTERN.search(str(value))
            if match:
                return match.group(0).upper()
    return None


def normalize_scan_findings(
    owasp_raw: dict[str, Any],
    trivy_raw: dict[str, Any],
    known_exploited_cves: set[str],
    epss_scores: dict[str, float] | None = None,
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    known = {cve.upper() for cve in known_exploited_cves}
    epss = {key.upper(): value for key, value in (epss_scores or {}).items()}

    dependencies = owasp_raw.get("dependencies", [])
    for dependency in dependencies if isinstance(dependencies, list) else []:
        if not isinstance(dependency, dict):
            continue
        package_name, installed_version = owasp_package(dependency)
        vulnerabilities = dependency.get("vulnerabilities", [])
        for vulnerability in vulnerabilities if isinstance(vulnerabilities, list) else []:
            if not isinstance(vulnerability, dict):
                continue
            identifier = cve_id(vulnerability)
            exploited = bool(identifier and identifier in known)
            probability = epss.get(identifier, 0.0) if identifier else 0.0
            enriched = {**vulnerability, "known_exploited": exploited, "epss_probability": probability}
            normalized.append(
                {
                    "source_tool": "owasp",
                    "package_name": package_name,
                    "installed_version": installed_version,
                    "fixed_version": None,
                    "severity": _OWASP_SEVERITIES.get(
                        str(vulnerability.get("severity", "")).upper(), "medium"
                    ),
                    "cve_id": identifier,
                    "known_exploited": exploited,
                    "epss_probability": probability,
                    "raw_finding": enriched,
                }
            )

    results = trivy_raw.get("Results", [])
    for result in results if isinstance(results, list) else []:
        if not isinstance(result, dict):
            continue
        vulnerabilities = result.get("Vulnerabilities", [])
        for vulnerability in vulnerabilities if isinstance(vulnerabilities, list) else []:
            if not isinstance(vulnerability, dict):
                continue
            identifier = cve_id(vulnerability)
            exploited = bool(identifier and identifier in known)
            probability = epss.get(identifier, 0.0) if identifier else 0.0
            enriched = {**vulnerability, "known_exploited": exploited, "epss_probability": probability}
            normalized.append(
                {
                    "source_tool": "trivy",
                    "package_name": vulnerability.get("PkgName"),
                    "installed_version": vulnerability.get("InstalledVersion"),
                    "fixed_version": vulnerability.get("FixedVersion") or None,
                    "severity": _TRIVY_SEVERITIES.get(
                        str(vulnerability.get("Severity", "")).upper(), "low"
                    ),
                    "cve_id": identifier,
                    "known_exploited": exploited,
                    "epss_probability": probability,
                    "raw_finding": enriched,
                }
            )

    return normalized


def effective_finding_points(findings: list[dict[str, Any]], kev_multiplier: float, epss_alpha: float) -> float:
    """Severity points adjusted per finding for EPSS probability and KEV status."""
    from scoring import SEVERITY_WEIGHTS

    return sum(
        SEVERITY_WEIGHTS.get(str(item.get("severity", "low")).lower(), 1)
        * (1 + epss_alpha * float(item.get("epss_probability", 0.0) or 0.0))
        * (kev_multiplier if item.get("known_exploited") else 1.0)
        for item in findings
    )
