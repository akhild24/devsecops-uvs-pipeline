from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from database import get_db
from models import (
    BreakdownResponse,
    CommitScore,
    DeltaResponse,
    Environment,
    FindingDetail,
    ScanFinding,
    ScanPayload,
    ScoreBreakdownComponent,
    ScoreResponse,
    SeverityCounts,
)
from scoring import risk_band_for

router = APIRouter(tags=["score"])


def _get_row(db: Session, commit_sha: str) -> CommitScore:
    row = db.execute(
        select(CommitScore).where(CommitScore.commit_sha == commit_sha).order_by(CommitScore.id.desc())
    ).scalars().first()
    if row is None:
        raise HTTPException(status_code=404, detail=f"No score found for commit '{commit_sha}'")
    return row


@router.get("/v1/score/{commit_sha}", response_model=ScoreResponse)
def get_score(commit_sha: str, db: Session = Depends(get_db)) -> ScoreResponse:
    row = _get_row(db, commit_sha)
    _, action = risk_band_for(row.final_score)
    return ScoreResponse(
        repo=row.repo,
        commit_sha=row.commit_sha,
        environment=Environment(row.environment),
        sast_score=row.sast_score,
        sca_score=row.sca_score,
        container_score=row.container_score,
        raw_score=row.raw_score,
        environment_multiplier=row.environment_multiplier,
        delta_factor=row.delta_factor,
        final_score=row.final_score,
        risk_level=row.risk_level,
        recommended_action=action,
        created_at=row.created_at,
    )


@router.get("/v1/repos")
def list_repos(db: Session = Depends(get_db)) -> list[str]:
    rows = db.execute(select(CommitScore.repo).distinct()).scalars().all()
    return sorted(rows)


@router.get("/v1/history/{repo:path}")
def get_history(repo: str, db: Session = Depends(get_db)):
    rows = db.execute(
        select(CommitScore).where(CommitScore.repo == repo).order_by(CommitScore.id.asc())
    ).scalars().all()
    return [
        {
            "commit_sha": r.commit_sha,
            "final_score": r.final_score,
            "risk_level": r.risk_level,
            "environment": r.environment,
            "created_at": r.created_at,
        }
        for r in rows
    ]


@router.get("/v1/breakdown/{commit_sha}", response_model=BreakdownResponse)
def get_breakdown(commit_sha: str, db: Session = Depends(get_db)) -> BreakdownResponse:
    row = _get_row(db, commit_sha)
    scan_payload = db.execute(
        select(ScanPayload).where(ScanPayload.commit_score_id == row.id)
    ).scalar_one_or_none()
    findings = db.execute(
        select(ScanFinding)
        .where(ScanFinding.commit_score_id == row.id)
        .order_by(ScanFinding.id.asc())
    ).scalars().all()
    semgrep_findings: list[FindingDetail] = []
    raw_results = (scan_payload.semgrep_raw if scan_payload else {}).get("results", [])
    for finding in raw_results if isinstance(raw_results, list) else []:
        if not isinstance(finding, dict):
            continue
        extra = finding.get("extra")
        extra = extra if isinstance(extra, dict) else {}
        metadata = extra.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        raw_severity = str(metadata.get("severity") or extra.get("severity") or "").upper()
        severity = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "ERROR": "high",
            "WARNING": "medium",
            "MEDIUM": "medium",
            "INFO": "low",
            "LOW": "low",
        }.get(raw_severity, "low")
        start = finding.get("start")
        start = start if isinstance(start, dict) else {}
        semgrep_findings.append(
            FindingDetail(
                source_tool="semgrep",
                rule_id=str(finding.get("check_id") or finding.get("rule_id") or "Unknown rule"),
                file_path=str(finding.get("path") or "Unknown file"),
                line_start=start.get("line") if isinstance(start.get("line"), int) else None,
                severity=severity,
                known_exploited=False,
                epss_probability=0.0,
            )
        )
    components = [
        ScoreBreakdownComponent(
            tool="semgrep",
            counts=SeverityCounts(**row.semgrep_counts),
            normalized_score=row.sast_score,
        ),
        ScoreBreakdownComponent(
            tool="owasp-dependency-check",
            counts=SeverityCounts(**row.owasp_counts),
            normalized_score=row.sca_score,
        ),
        ScoreBreakdownComponent(
            tool="trivy",
            counts=SeverityCounts(**row.trivy_counts),
            normalized_score=row.container_score,
        ),
    ]
    return BreakdownResponse(
        repo=row.repo,
        commit_sha=row.commit_sha,
        components=components,
        known_exploited_count=sum(finding.known_exploited for finding in findings),
        findings=semgrep_findings + [
            FindingDetail(
                source_tool=finding.source_tool,
                package_name=finding.package_name,
                installed_version=finding.installed_version,
                fixed_version=finding.fixed_version,
                cve_id=finding.cve_id,
                rule_id=None,
                file_path=None,
                line_start=None,
                severity=finding.severity,
                known_exploited=finding.known_exploited,
                epss_probability=finding.raw_finding.get("epss_probability", 0.0),
            )
            for finding in findings
        ],
    )


@router.get("/v1/delta/{commit_sha}", response_model=DeltaResponse)
def get_delta(commit_sha: str, db: Session = Depends(get_db)) -> DeltaResponse:
    current = _get_row(db, commit_sha)
    previous = db.execute(
        select(CommitScore)
        .where(CommitScore.repo == current.repo, CommitScore.id < current.id)
        .order_by(CommitScore.id.desc())
        .limit(1)
    ).scalar_one_or_none()

    if previous is None:
        return DeltaResponse(
            repo=current.repo,
            commit_sha=current.commit_sha,
            current_score=current.final_score,
            previous_score=None,
            delta=None,
            trend="first-commit",
        )

    delta = round(current.final_score - previous.final_score, 4)
    if delta < 0:
        trend = "improving"
    elif delta > 0:
        trend = "regressing"
    else:
        trend = "flat"

    return DeltaResponse(
        repo=current.repo,
        commit_sha=current.commit_sha,
        current_score=current.final_score,
        previous_score=previous.final_score,
        delta=delta,
        trend=trend,
    )


@router.get("/health")
def health():
    return {"status": "ok"}
