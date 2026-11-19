"""
SQLAlchemy engine/session setup.

Defaults to a local SQLite file for dev, matching the PRD (Section 5: SQLite
for dev, PostgreSQL for prod). Set DATABASE_URL to override, e.g.:

    DATABASE_URL=postgresql+psycopg2://user:pass@db:5432/devsecops
"""
from __future__ import annotations

import os

from sqlalchemy import create_engine, delete, func, select, text
from sqlalchemy.orm import sessionmaker

from models import Base, CommitScore, ScanFinding, ScanPayload

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./devsecops.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        duplicate_commits = db.execute(
            select(CommitScore.repo, CommitScore.commit_sha)
            .group_by(CommitScore.repo, CommitScore.commit_sha)
            .having(func.count(CommitScore.id) > 1)
        ).all()
        for repo, commit_sha in duplicate_commits:
            rows = db.execute(
                select(CommitScore)
                .where(
                    CommitScore.repo == repo,
                    CommitScore.commit_sha == commit_sha,
                )
                .order_by(CommitScore.id.desc())
            ).scalars().all()
            for duplicate in rows[1:]:
                db.execute(
                    delete(ScanFinding).where(
                        ScanFinding.commit_score_id == duplicate.id
                    )
                )
                db.execute(
                    delete(ScanPayload).where(
                        ScanPayload.commit_score_id == duplicate.id
                    )
                )
                db.delete(duplicate)
        db.commit()
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "uq_commit_scores_repo_commit_sha "
                "ON commit_scores (repo, commit_sha)"
            )
        )


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
