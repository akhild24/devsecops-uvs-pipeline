"""
Pydantic request/response models + SQLAlchemy ORM models for the
DevSecOps UVS Scoring Engine.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field
from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import declarative_base

Base = declarative_base()


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class Environment(str, Enum):
    dev = "dev"
    staging = "staging"
    prod = "prod"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


# --------------------------------------------------------------------------- #
# Inbound payloads (one per tool) — these are intentionally loose/raw because
# each tool ships its own JSON shape. The parsers/ package normalizes them.
# --------------------------------------------------------------------------- #
class SeverityCounts(BaseModel):
    """Normalized finding counts, already bucketed by severity."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low


class ToolFindings(BaseModel):
    """Normalized output of any one scanner, after parsing."""

    tool: str  # "semgrep" | "owasp-dependency-check" | "trivy"
    counts: SeverityCounts
    mean_cvss: Optional[float] = None  # used by SCA (dependency-check)
    raw_finding_count: int = 0


class ScanSubmitRequest(BaseModel):
    """POST /v1/scan/submit body."""

    repo: str = Field(..., description="owner/repo, e.g. 'octocat/Hello-World'")
    commit_sha: str = Field(..., min_length=7)
    environment: Environment = Environment.dev
    semgrep_raw: dict = Field(default_factory=dict)
    owasp_raw: dict = Field(default_factory=dict)
    trivy_raw: dict = Field(default_factory=dict)
    timestamp: Optional[datetime] = None


class ScoreBreakdownComponent(BaseModel):
    tool: str
    counts: SeverityCounts
    normalized_score: float


class ScoreResponse(BaseModel):
    repo: str
    commit_sha: str
    environment: Environment
    sast_score: float
    sca_score: float
    container_score: float
    raw_score: float
    environment_multiplier: float
    delta_factor: float
    final_score: float
    risk_level: str
    recommended_action: str
    created_at: datetime
    score: Optional[float] = None
    risk_band: Optional[str] = None
    delta_vs_previous: Optional[float] = None
    top_fixes: list[WhatIfFix] = Field(default_factory=list)


class WhatIfFix(BaseModel):
    package: str
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    fix_known: bool = False
    findings_removed: int
    current_score: float
    simulated_score: float
    score_reduction: float
    source_tool: str
    known_exploited: bool = False


class FindingDetail(BaseModel):
    source_tool: str
    package_name: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    cve_id: Optional[str] = None
    rule_id: Optional[str] = None
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    severity: str
    known_exploited: bool
    epss_probability: float = 0.0


class BreakdownResponse(BaseModel):
    repo: str
    commit_sha: str
    components: list[ScoreBreakdownComponent]
    known_exploited_count: int = 0
    findings: list[FindingDetail] = Field(default_factory=list)


class DeltaResponse(BaseModel):
    repo: str
    commit_sha: str
    current_score: float
    previous_score: Optional[float]
    delta: Optional[float]
    trend: str  # "improving" | "regressing" | "flat" | "first-commit"


# --------------------------------------------------------------------------- #
# ORM model — one row per (repo, commit_sha)
# --------------------------------------------------------------------------- #
class CommitScore(Base):
    __tablename__ = "commit_scores"

    id = Column(Integer, primary_key=True, autoincrement=True)
    repo = Column(String, nullable=False, index=True)
    commit_sha = Column(String, nullable=False, index=True)
    environment = Column(String, nullable=False, default="dev")

    sast_score = Column(Float, nullable=False)
    sca_score = Column(Float, nullable=False)
    container_score = Column(Float, nullable=False)
    raw_score = Column(Float, nullable=False)
    environment_multiplier = Column(Float, nullable=False)
    delta_factor = Column(Float, nullable=False)
    final_score = Column(Float, nullable=False)
    risk_level = Column(String, nullable=False)

    semgrep_counts = Column(JSON, nullable=False)
    owasp_counts = Column(JSON, nullable=False)
    trivy_counts = Column(JSON, nullable=False)
    owasp_mean_cvss = Column(Float, nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ScanPayload(Base):
    __tablename__ = "scan_payloads"

    id = Column(Integer, primary_key=True, autoincrement=True)
    commit_score_id = Column(
        Integer, ForeignKey("commit_scores.id"), nullable=False, unique=True, index=True
    )
    semgrep_raw = Column(JSON, nullable=False)
    owasp_raw = Column(JSON, nullable=False)
    trivy_raw = Column(JSON, nullable=False)


class ScanFinding(Base):
    __tablename__ = "scan_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    commit_score_id = Column(
        Integer, ForeignKey("commit_scores.id"), nullable=False, index=True
    )
    source_tool = Column(String, nullable=False)
    package_name = Column(String, nullable=True)
    installed_version = Column(String, nullable=True)
    fixed_version = Column(String, nullable=True)
    cve_id = Column(String, nullable=True)
    severity = Column(String, nullable=False)
    known_exploited = Column(Boolean, nullable=False, default=False)
    epss_probability = Column(Float, nullable=False, default=0.0)
    raw_finding = Column(JSON, nullable=False)
