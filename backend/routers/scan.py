from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from database import get_db
from models import (
    CommitScore,
    Environment,
    ScanFinding,
    ScanPayload,
    ScanSubmitRequest,
    ScoreResponse,
)
from parsers.owasp import parse_owasp
from parsers.semgrep import parse_semgrep
from parsers.trivy import parse_trivy
from routers.whatif import generate_top_fixes
from services.findings import effective_finding_points, normalize_scan_findings
from services.kev import get_known_exploited_cves
from services.epss import get_epss_alpha, get_epss_scores, get_kev_multiplier
from scoring import compute_uvs_score

router = APIRouter(tags=["scan"])


def _latest_final_score(db: Session, repo: str) -> float | None:
    row = db.execute(
        select(CommitScore)
        .where(CommitScore.repo == repo)
        .order_by(CommitScore.id.desc())
        .limit(1)
    ).scalar_one_or_none()
    return row.final_score if row else None


def _previous_final_score(
    db: Session, repo: str, existing: CommitScore | None
) -> float | None:
    query = select(CommitScore.final_score).where(CommitScore.repo == repo)
    if existing is not None:
        query = query.where(CommitScore.id < existing.id)
    return db.execute(query.order_by(CommitScore.id.desc()).limit(1)).scalar_one_or_none()


@router.post("/v1/scan/submit", response_model=ScoreResponse)
def submit_scan(payload: ScanSubmitRequest, db: Session = Depends(get_db)) -> ScoreResponse:
    """
    Accepts the raw JSON payloads from Semgrep, OWASP Dependency-Check, and
    Trivy for a single commit, computes the UVS score, and persists it.
    """
    semgrep_findings = parse_semgrep(payload.semgrep_raw)
    owasp_findings = parse_owasp(payload.owasp_raw)
    trivy_findings = parse_trivy(payload.trivy_raw)
    normalized_findings = normalize_scan_findings(
        payload.owasp_raw,
        payload.trivy_raw,
        get_known_exploited_cves(),
        get_epss_scores(),
    )
    epss_alpha = get_epss_alpha()
    kev_multiplier = get_kev_multiplier()
    owasp_norm = [f for f in normalized_findings if f["source_tool"] == "owasp"]
    trivy_norm = [f for f in normalized_findings if f["source_tool"] == "trivy"]

    existing = db.execute(
        select(CommitScore)
        .where(
            CommitScore.repo == payload.repo,
            CommitScore.commit_sha == payload.commit_sha,
        )
        .order_by(CommitScore.id.desc())
        .limit(1)
    ).scalar_one_or_none()
    previous_score = (
        _previous_final_score(db, payload.repo, existing)
        if existing is not None
        else _latest_final_score(db, payload.repo)
    )

    result = compute_uvs_score(
        sast_counts=semgrep_findings.counts,
        sca_counts=owasp_findings.counts,
        sca_mean_cvss=owasp_findings.mean_cvss,
        container_counts=trivy_findings.counts,
        environment=payload.environment,
        previous_final_score=previous_score,
        sca_points=effective_finding_points(owasp_norm, kev_multiplier, epss_alpha),
        container_points=effective_finding_points(trivy_norm, kev_multiplier, epss_alpha),
    )

    if existing is None:
        row = CommitScore(
            repo=payload.repo,
            commit_sha=payload.commit_sha,
            environment=payload.environment.value,
            sast_score=result.sast_score,
            sca_score=result.sca_score,
            container_score=result.container_score,
            raw_score=result.raw_score,
            environment_multiplier=result.environment_multiplier,
            delta_factor=result.delta_factor,
            final_score=result.final_score,
            risk_level=result.risk_level,
            semgrep_counts=semgrep_findings.counts.model_dump(),
            owasp_counts=owasp_findings.counts.model_dump(),
            trivy_counts=trivy_findings.counts.model_dump(),
            owasp_mean_cvss=owasp_findings.mean_cvss,
        )
        db.add(row)
    else:
        row = existing
        row.environment = payload.environment.value
        row.sast_score = result.sast_score
        row.sca_score = result.sca_score
        row.container_score = result.container_score
        row.raw_score = result.raw_score
        row.environment_multiplier = result.environment_multiplier
        row.delta_factor = result.delta_factor
        row.final_score = result.final_score
        row.risk_level = result.risk_level
        row.semgrep_counts = semgrep_findings.counts.model_dump()
        row.owasp_counts = owasp_findings.counts.model_dump()
        row.trivy_counts = trivy_findings.counts.model_dump()
        row.owasp_mean_cvss = owasp_findings.mean_cvss
        db.execute(delete(ScanFinding).where(ScanFinding.commit_score_id == row.id))
        db.execute(delete(ScanPayload).where(ScanPayload.commit_score_id == row.id))
    db.flush()
    db.add(
        ScanPayload(
            commit_score_id=row.id,
            semgrep_raw=payload.semgrep_raw,
            owasp_raw=payload.owasp_raw,
            trivy_raw=payload.trivy_raw,
        )
    )
    db.add_all(
        [
            ScanFinding(commit_score_id=row.id, **finding)
            for finding in normalized_findings
        ]
    )
    db.commit()
    db.refresh(row)

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
        recommended_action=result.recommended_action,
        created_at=row.created_at,
        score=row.final_score,
        risk_band=row.risk_level,
        delta_vs_previous=(
            round(row.final_score - previous_score, 4)
            if previous_score is not None
            else None
        ),
        top_fixes=generate_top_fixes(db, row),
    )
