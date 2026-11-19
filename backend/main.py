from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import init_db
from routers import badge, scan, score, whatif


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="DevSecOps UVS Scoring Engine",
    description=(
        "Aggregates Semgrep (SAST), OWASP Dependency-Check (SCA), and Trivy "
        "(container scanning) findings into a single Unified Vulnerability "
        "Score (0-100) per commit."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Dev-friendly CORS so the Vite dashboard (localhost:5173) can call the API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router)
app.include_router(score.router)
app.include_router(whatif.router)
app.include_router(badge.router)
