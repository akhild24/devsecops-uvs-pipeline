# DevSecOps Pipeline with Automated Vulnerability Scoring (UVS)

This project demonstrates a DevSecOps pipeline that ingests raw scanner output, normalizes it, scores each commit, and visualizes the risk in a dashboard.

## Architecture

```mermaid
flowchart LR
    A[GitHub PR / push] --> B[Semgrep SAST]
    A --> C[OWASP Dependency-Check]
    A --> D[Trivy container scan]
    B --> E[submit_scores.py]
    C --> E
    D --> E
    E --> F[FastAPI backend /v1/scan/submit]
    F --> G[UVS scoring engine]
    G --> H[SQLite/Postgres data store]
    H --> I[React dashboard]
    G --> J[What-if remediation suggestions]
    G --> K[Badge + risk API]
    G --> L[Merge gate / PR comment]
```

## Stack

- Backend: FastAPI + SQLAlchemy + SQLite for local dev
- Frontend: React + Vite
- Scanners: Semgrep, OWASP Dependency-Check, Trivy
- CI/CD: GitHub Actions

## Quick start (3 commands)

```bash
docker compose up --build -d
docker compose ps
# Open http://localhost:3000 (demo data is seeded automatically)
```

## Local development

### Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

### Run tests

```bash
cd backend
pytest
# or from repo root
pytest
```

## Scanner commands

Run the three scanner inputs directly if needed:

```bash
# Semgrep
semgrep scan --config p/security-audit --json --output semgrep.json || true

# OWASP Dependency-Check
dependency-check --project demo-app --scan . --out reports --format JSON --suppression scanners/owasp-suppression.xml || true

# Trivy
trivy image --format json --output trivy.json your-image:tag || true
```

The CI workflow in [.github/workflows/devsecops.yml](.github/workflows/devsecops.yml) submits scan JSON to `/v1/scan/submit` and enforces the threshold.

## Dynamic risk badge

When the backend is deployed, replace `YOUR_DEPLOYED_API_HOST` with its public
HTTPS host. This SVG badge reflects the latest score and uses the matching risk
band color:

![Demo security risk](https://YOUR_DEPLOYED_API_HOST/v1/badge/demo/acme-webapp.svg)

The local SVG endpoint is
`http://localhost:8000/v1/badge/demo/acme-webapp.svg`.

## UVS formula

```text
Raw Score = (0.35 × SAST_Score) + (0.40 × SCA_Score) + (0.25 × Container_Score)
Final Score = min(100, Raw Score × Environment_Multiplier × Delta_Factor)
```

Where:
- SAST score = weighted density of Semgrep findings
- SCA score = weighted OWASP findings plus mean CVSS blend
- Container score = weighted Trivy findings
- Environment multiplier: dev=1.0, staging=1.1, prod=1.3
- Delta factor: 0.9 when a commit improves versus the previous commit, otherwise 1.0

Example:

```text
SAST = 30
SCA = 60
Container = 40
Raw Score = (0.35 × 30) + (0.40 × 60) + (0.25 × 40)
          = 10.5 + 24 + 10
          = 44.5

Prod environment: ×1.3
Previous score higher: delta reward = 0.9
Final Score = min(100, 44.5 × 1.3 × 0.9)
            ≈ 52.1
```

Risk categories:
- 0-20 Low
- 21-50 Medium
- 51-75 High
- 76-100 Critical

## GitHub Action setup

1. Push the repo to GitHub.
2. Deploy the FastAPI backend somewhere reachable from GitHub Actions.
3. Set repo variables / secrets:
   - `SCORING_API_URL` = deployed backend URL, for example `https://uvs-api.example.com`
   - `RISK_FAIL_THRESHOLD` = `75`
   - `DASHBOARD_URL` = optional dashboard URL for PR comments
4. Require the `Aggregate & Score` workflow check in branch protection.
5. The score job posts a PR comment and exits with a non-zero status when the score exceeds the threshold.

Fork-originated pull requests may not have permission to publish comments even
when the workflow declares `pull-requests: write`; GitHub restricts fork tokens.
The workflow reports that situation as a warning, while the score threshold
check still runs.

## Demo data and sample runs

The project includes repeatable demo data so the dashboard can be shown without a live scanner feed.

- Sample seed script: [backend/scripts/post_samples.py](backend/scripts/post_samples.py)
- Demo guide: [DEMO.md](DEMO.md)
- Demo data is labeled as sample/demo in the script and in the dashboard footer.

## Known limitations

- This is a demo project, not a production-grade enterprise platform.
- The seeded findings are representative sample data, not live scan output from real repositories.
- Demo CVE IDs use the `CVE-DEMO-*` namespace; the Log4Shell sample uses the real
  `CVE-2021-44228` identifier to demonstrate KEV matching. None of these are a
  claim that the sample repositories were scanned.
- Real scanner execution against production repos requires a live GitHub repo, deployed backend URL, and branch protection configuration.
- The project is intended for teaching and presentation, not large-scale multi-org scanning.

## Repository layout

```text
.
├── .github/workflows/devsecops.yml
├── backend/
│   ├── parsers/
│   ├── routers/
│   ├── scripts/
│   ├── services/
│   ├── tests/
│   ├── database.py
│   ├── main.py
│   ├── models.py
│   ├── scoring.py
│   └── requirements.txt
├── frontend/
├── scanners/
├── docker-compose.yml
├── Dockerfile.backend
├── Dockerfile.frontend
├── DEMO.md
├── .env.example
├── README.md
└── docs/
```
