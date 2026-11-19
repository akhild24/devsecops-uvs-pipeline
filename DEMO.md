# 5-minute UVS demo

## Start the local demo

From the repository root, use two PowerShell windows.

Window 1 — API and SQLite:

```powershell
$env:DATABASE_URL = 'sqlite:///./demo-local.db'
$env:DEMO_DATA_SEED = 'false'
cd backend
..\.venv\Scripts\python.exe -m uvicorn main:app --reload
```

Window 2 — dashboard and sample data:

```powershell
cd frontend
npm run dev
```

In a third PowerShell window, seed the sample commits (the script uses the root virtual environment):

```powershell
..\.venv\Scripts\python.exe backend/scripts/post_samples.py
```

Open <http://localhost:5173>. API docs are at <http://localhost:8000/docs>. The seed script is repeatable and updates matching repo/commit records rather than duplicating them.

## Click-through (about five minutes)

1. **Repository and history (45 sec).** Select `demo/acme-webapp`. Point at the timeline and say: “Each point is one sample commit; the data is illustrative scanner-shaped data, not a live scan.” Select an older commit, then the latest one to show score changes.
2. **Score and risk band (45 sec).** Read the score, Low/Medium/High/Critical band, environment multiplier, and delta factor. Say: “The score combines SAST, dependency, and container signals; production and improving-commit adjustments are explicit.”
3. **Breakdown and findings (60 sec).** Scroll to the severity breakdown. Point out the Semgrep rule/file/line and the OWASP/Trivy package findings. Explain that the sample includes `CVE-2021-44228` to demonstrate KEV matching.
4. **What-if remediation (60 sec).** In “Fix first,” select a package fix. Show the projected score and risk band above the card; select another fix and note that this is an estimate based on removing those findings from the current scan payload.
5. **KEV and badge (45 sec).** Point out the known-exploited flag in finding details. Open <http://localhost:8000/v1/badge/demo/acme-webapp.svg> in another tab. Say: “The SVG message and color are derived from the latest saved score.”
6. **Pipeline (45 sec).** Show `.github/workflows/devsecops.yml`: scanners produce JSON, the score job submits it, comments on pull requests, and compares score with `RISK_FAIL_THRESHOLD`. Explain that actual GitHub comments and branch protection require repository configuration.

## API spot checks

```powershell
Invoke-RestMethod http://localhost:8000/v1/repos
Invoke-RestMethod 'http://localhost:8000/v1/history/demo/acme-webapp'
Invoke-RestMethod http://localhost:8000/v1/breakdown/d3f0b10
Invoke-RestMethod http://localhost:8000/v1/whatif/d3f0b10
Invoke-WebRequest http://localhost:8000/v1/badge/demo/acme-webapp.svg
```

Use a commit SHA returned by the history endpoint if the sample IDs change.

## Known limitations

- Samples are synthetic, except the Log4Shell CVE identifier used to show KEV matching; they do not represent a scan of these repositories.
- EPSS is not part of the score. KEV score boost defaults to zero; set `KEV_BONUS` to a positive number to demonstrate an explicit boost.
- What-if results estimate removing package findings from the saved scan and do not validate an actual dependency upgrade or rerun scanners.
- GitHub Actions, hosted API availability, PR permissions, and branch-protection enforcement must be verified in the target GitHub repository. Fork PR tokens may prevent comments.
- This is a faculty demo, not a production security service.



## EPSS and KEV scoring

For each dependency/container CVE finding:

```text
severity_points = {Critical:10, High:5, Medium:2, Low:1}
EPSS_adjusted_points = severity_points × (1 + EPSS_ALPHA × EPSS_probability)
Finding_points = EPSS_adjusted_points × (KEV_MULTIPLIER if in CISA KEV, else 1)
component_score = min(100, 100 × sum(Finding_points) / MAX_FINDING_POINTS)
SAST_score = min(100, 100 × SAST_severity_points / MAX_FINDING_POINTS)
SCA_score = 0.5 × SCA_component_score + 0.5 × min(100, 10 × mean_CVSS) (when CVSS exists)
Raw = W_SAST×SAST_score + W_SCA×SCA_score + W_CONTAINER×Container_score
Final = min(100, Raw × environment_multiplier × delta_factor)
```

Defaults: weights `W_SAST/W_SCA/W_CONTAINER = 0.35/0.40/0.25`; severity points `10/5/2/1`; `MAX_FINDING_POINTS=50`; `EPSS_ALPHA=1.0`; `KEV_MULTIPLIER=1.25`; environment multipliers dev/staging/prod `1.0/1.1/1.3`; improvement delta factor `0.9`, otherwise `1.0`. An EPSS probability missing from `backend/data/epss.json` is zero and therefore has a neutral factor of 1. The bundled file is an offline snapshot dated 2026-11-17. Its `CVE-DEMO-*` entries are synthetic demonstration estimates, not FIRST.org predictions.

## Why these weights

`backend/scripts/calibrate_weights.py` evaluates every bundled sample commit for the four listed weight sets, EPSS alpha values `0/0.5/1.0`, and KEV multiplier on/off, then prints per-commit score and descending rank. These are demonstration weights chosen for this synthetic dataset, not universal constants.

| Weight set | Weights (SAST/SCA/container) | Highest sample (alpha 1, KEV on) | Highest score | Commits capped at 100 |
|---|---:|---|---:|---:|
| Default | 0.35/0.40/0.25 | d3f0b10 | 91.49 | 0 |
| Equal | 0.333/0.333/0.333 | d3f0b10 | 86.78 | 0 |
| SCA-heavy | 0.25/0.55/0.20 | d3f0b10 | 89.85 | 0 |
| SAST-heavy | 0.55/0.25/0.20 | d3f0b10 | 100.00 | 1 |

This comparison shows the SAST-heavy setting saturates the sample’s deliberately severe commit, while the default keeps it below the cap and preserves separation among the other sample commits. It does not establish that the default is statistically optimal.

For the UI demo, seed the samples, choose `demo/acme-webapp`, then select commit `d3f0b10`. Scroll to **Findings by tool → Package findings**: the Log4Shell CVE row shows its EPSS percentage and **Known exploited** badge. The top **Fix first** card and projection above it show the what-if result. The SVG badge URL is `http://localhost:8000/v1/badge/demo/acme-webapp.svg`.
