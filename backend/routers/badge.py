from __future__ import annotations

from html import escape

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from database import get_db
from models import CommitScore

router = APIRouter(tags=["badge"])

_BADGE_COLORS = {
    "Low": "brightgreen",
    "Medium": "yellow",
    "High": "orange",
    "Critical": "red",
}
_SVG_COLORS = {
    "brightgreen": "#4c1",
    "yellow": "#dfb317",
    "orange": "#fe7d37",
    "red": "#e05d44",
    "lightgrey": "#9f9f9f",
}


def _latest_score(db: Session, repo: str) -> CommitScore | None:
    return db.execute(
        select(CommitScore)
        .where(CommitScore.repo == repo)
        .order_by(CommitScore.id.desc())
        .limit(1)
    ).scalar_one_or_none()


def _badge_data(db: Session, repo: str) -> dict[str, object]:
    row = _latest_score(db, repo)
    if row is None:
        message = "no data"
        color = "lightgrey"
    else:
        message = f"{row.final_score:.0f} {row.risk_level}"
        color = _BADGE_COLORS.get(row.risk_level, "lightgrey")
    return {
        "schemaVersion": 1,
        "label": "security risk",
        "message": message,
        "color": color,
    }


@router.get("/v1/badge/{owner}/{repo}.svg")
def get_badge_svg(
    owner: str, repo: str, db: Session = Depends(get_db)
) -> Response:
    data = _badge_data(db, f"{owner}/{repo}")
    label = str(data["label"])
    message = str(data["message"])
    color = str(data["color"])
    label_width = 79
    message_width = max(40, len(message) * 7 + 12)
    width = label_width + message_width
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="20" '
        f'role="img" aria-label="{escape(label)}: {escape(message)}">'
        f"<title>{escape(label)}: {escape(message)}</title>"
        f'<linearGradient id="b" x2="0" y2="100%">'
        f'<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        f'<stop offset="1" stop-opacity=".1"/></linearGradient>'
        f'<clipPath id="a"><rect width="{width}" height="20" rx="3"/></clipPath>'
        f'<g clip-path="url(#a)">'
        f'<path fill="#555" d="M0 0h{label_width}v20H0z"/>'
        f'<path fill="{_SVG_COLORS[color]}" d="M{label_width} 0h{message_width}v20H{label_width}z"/>'
        f'<path fill="url(#b)" d="M0 0h{width}v20H0z"/>'
        f"</g>"
        f'<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,sans-serif" '
        f'font-size="11"><text x="{label_width / 2}" y="14">{escape(label)}</text>'
        f'<text x="{label_width + message_width / 2}" y="14">{escape(message)}</text></g>'
        "</svg>"
    )
    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={"Cache-Control": "public, max-age=300"},
    )


@router.get("/v1/badge/{repo:path}")
def get_badge_json(repo: str, db: Session = Depends(get_db)) -> dict[str, object]:
    return _badge_data(db, repo)
