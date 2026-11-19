from __future__ import annotations

from copy import deepcopy
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from database import get_db
from models import CommitScore, Environment, ScanFinding, ScanPayload, WhatIfFix
from parsers.owasp import parse_owasp
from parsers.semgrep import parse_semgrep
from parsers.trivy import parse_trivy
from services.findings import owasp_package
from services.findings import effective_finding_points, normalize_scan_findings
from services.kev import get_known_exploited_cves
from services.epss import get_epss_alpha, get_epss_scores, get_kev_multiplier
from scoring import compute_uvs_score

router = APIRouter(tags=["what-if"])


def _package_groups(owasp_raw: dict, trivy_raw: dict) -> dict[tuple[str, str], dict[str, Any]]:
    groups: dict[tuple[str, str], dict[str, Any]] = {}

    def add(
        tool: str,
        package: str,
        installed_version: str | None,
        fixed_version: str | None,
    ) -> None:
        group = groups.setdefault(
            (tool, package),
            {
                "package": package,
                "installed_version": installed_version,
                "fixed_version": None,
                "findings_removed": 0,
            },
        )
        group["findings_removed"] += 1
        if not group["installed_version"] and installed_version:
            group["installed_version"] = installed_version
        if not group["fixed_version"] and fixed_version:
            group["fixed_version"] = fixed_version

    dependencies = owasp_raw.get("dependencies", [])
    for dependency in dependencies if isinstance(dependencies, list) else []:
        if not isinstance(dependency, dict):
            continue
        package, version = owasp_package(dependency)
        if not package:
            continue
        vulnerabilities = dependency.get("vulnerabilities", [])
        for vulnerability in vulnerabilities if isinstance(vulnerabilities, list) else []:
            if not isinstance(vulnerability, dict):
                continue
            add(
                "owasp",
                package,
                version,
                vulnerability.get("fixedVersion") or vulnerability.get("fixed_version"),
            )

    results = trivy_raw.get("Results", [])
    for result in results if isinstance(results, list) else []:
        if not isinstance(result, dict):
            continue
        vulnerabilities = result.get("Vulnerabilities", [])
        for vulnerability in vulnerabilities if isinstance(vulnerabilities, list) else []:
            if not isinstance(vulnerability, dict):
                continue
            package = vulnerability.get("PkgName")
            if package:
                add(
                    "trivy",
                    str(package),
                    vulnerability.get("InstalledVersion"),
                    vulnerability.get("FixedVersion") or None,
                )

    return groups


def _remove_package_findings(
    owasp_raw: dict, trivy_raw: dict, tool: str, package: str
) -> tuple[dict, dict]:
    simulated_owasp = deepcopy(owasp_raw)
    simulated_trivy = deepcopy(trivy_raw)

    if tool == "owasp":
        dependencies = simulated_owasp.get("dependencies", [])
        for dependency in dependencies if isinstance(dependencies, list) else []:
            if not isinstance(dependency, dict):
                continue
            dependency_package, _ = owasp_package(dependency)
            if dependency_package == package:
                dependency["vulnerabilities"] = []
    else:
        results = simulated_trivy.get("Results", [])
        for result in results if isinstance(results, list) else []:
            if not isinstance(result, dict):
                continue
            vulnerabilities = result.get("Vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                vulnerabilities = []
            result["Vulnerabilities"] = [
                vulnerability
                for vulnerability in vulnerabilities
                if isinstance(vulnerability, dict)
                and vulnerability.get("PkgName") != package
            ]

    return simulated_owasp, simulated_trivy


def generate_top_fixes(
    db: Session, row: CommitScore, limit: int = 3
) -> list[WhatIfFix]:
    payload = db.execute(
        select(ScanPayload).where(ScanPayload.commit_score_id == row.id)
    ).scalar_one_or_none()
    if payload is None:
        raise HTTPException(
            status_code=404,
            detail=f"Raw findings are unavailable for commit '{row.commit_sha}'",
        )

    groups = _package_groups(payload.owasp_raw, payload.trivy_raw)
    persisted_findings = db.execute(
        select(ScanFinding).where(ScanFinding.commit_score_id == row.id)
    ).scalars().all()
    known_by_package: dict[tuple[str, str], int] = {}
    for finding in persisted_findings:
        if finding.known_exploited and finding.package_name:
            key = (finding.source_tool, finding.package_name)
            known_by_package[key] = known_by_package.get(key, 0) + 1
    normalized = normalize_scan_findings(payload.owasp_raw, payload.trivy_raw, get_known_exploited_cves(), get_epss_scores())
    previous = db.execute(
        select(CommitScore)
        .where(CommitScore.repo == row.repo, CommitScore.id < row.id)
        .order_by(CommitScore.id.desc())
        .limit(1)
    ).scalar_one_or_none()
    previous_score = previous.final_score if previous else None
    current_score = row.final_score
    alpha = get_epss_alpha()
    kev_multiplier = get_kev_multiplier()
    suggestions: list[WhatIfFix] = []

    for (tool, package), group in groups.items():
        owasp_raw, trivy_raw = _remove_package_findings(
            payload.owasp_raw, payload.trivy_raw, tool, package
        )
        simulated_owasp_findings = parse_owasp(owasp_raw)
        remaining = [finding for finding in normalized if not (finding["source_tool"] == tool and finding["package_name"] == package)]
        simulated_result = compute_uvs_score(
            sast_counts=parse_semgrep(payload.semgrep_raw).counts,
            sca_counts=simulated_owasp_findings.counts,
            sca_mean_cvss=simulated_owasp_findings.mean_cvss,
            container_counts=parse_trivy(trivy_raw).counts,
            environment=Environment(row.environment),
            previous_final_score=previous_score,
            sca_points=effective_finding_points([f for f in remaining if f["source_tool"] == "owasp"], kev_multiplier, alpha),
            container_points=effective_finding_points([f for f in remaining if f["source_tool"] == "trivy"], kev_multiplier, alpha),
        )
        reduction = round(current_score - simulated_result.final_score, 4)
        if reduction <= 0:
            continue
        suggestions.append(
            WhatIfFix(
                package=group["package"],
                installed_version=group["installed_version"],
                fixed_version=group["fixed_version"],
                fix_known=bool(group["fixed_version"]),
                findings_removed=group["findings_removed"],
                current_score=current_score,
                simulated_score=simulated_result.final_score,
                score_reduction=reduction,
                source_tool=tool,
                known_exploited=known_by_package.get((tool, package), 0) > 0,
            )
        )

    suggestions.sort(
        key=lambda fix: (
            -fix.score_reduction,
            -int(fix.known_exploited),
            fix.package.lower(),
            fix.source_tool,
        )
    )
    return suggestions[:limit]


@router.get("/v1/whatif/{commit_sha}", response_model=list[WhatIfFix])
def get_what_if(
    commit_sha: str,
    limit: int = Query(default=3, ge=1, le=50),
    db: Session = Depends(get_db),
) -> list[WhatIfFix]:
    row = db.execute(
        select(CommitScore)
        .where(CommitScore.commit_sha == commit_sha)
        .order_by(CommitScore.id.desc())
        .limit(1)
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail=f"No score found for commit '{commit_sha}'")
    return generate_top_fixes(db, row, limit)
