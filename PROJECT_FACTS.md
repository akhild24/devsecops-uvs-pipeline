# PROJECT_FACTS

## 1. DATABASE

- Engine: SQLAlchemy. Default `DATABASE_URL` is `sqlite:///./devsecops.db` (relative to backend process working directory); Compose configures PostgreSQL 16 (`postgresql://devsecops:devsecops@db:5432/devsecops`). `Base.metadata.create_all()` creates missing tables; see `backend/database.py:18-21,25-26`.
- SQLite database files present at inspection: `backend/demo-final.sqlite`, `backend/demo-local.db`, `backend/test_client.db`, `backend/test_devsecops.db`. The default `backend/devsecops.db` was not present. `sqlite3` CLI: NOT FOUND (checked with `Get-Command sqlite3`).
- Column details below follow SQLAlchemy declarations in `backend/models.py`. Unspecified defaults are none; unspecified nullability is SQLAlchemy's default nullable. No ORM `relationship()` declarations exist.

### `CommitScore` / `commit_scores` (`backend/models.py:144-166`)

| Column | Type | Nullable | Default | Key / constraints |
|---|---|---:|---|---|
| id | Integer | no | autoincrement | Primary key |
| repo | String | no | none | Indexed; participates in unique `(repo, commit_sha)` index created by `init_db()` |
| commit_sha | String | no | none | Indexed; participates in unique `(repo, commit_sha)` index created by `init_db()` |
| environment | String | no | `"dev"` | none |
| sast_score | Float | no | none | none |
| sca_score | Float | no | none | none |
| container_score | Float | no | none | none |
| raw_score | Float | no | none | none |
| environment_multiplier | Float | no | none | none |
| delta_factor | Float | no | none | none |
| final_score | Float | no | none | none |
| risk_level | String | no | none | none |
| semgrep_counts | JSON | no | none | none |
| owasp_counts | JSON | no | none | none |
| trivy_counts | JSON | no | none | none |
| owasp_mean_cvss | Float | yes | none | none |
| created_at | DateTime | yes | `datetime.now(timezone.utc)` (Python-side) | none |

### `ScanPayload` / `scan_payloads` (`backend/models.py:169-178`)

| Column | Type | Nullable | Default | Key / constraints |
|---|---|---:|---|---|
| id | Integer | no | autoincrement | Primary key |
| commit_score_id | Integer | no | none | Foreign key to `commit_scores.id`; unique and indexed |
| semgrep_raw | JSON | no | none | none |
| owasp_raw | JSON | no | none | none |
| trivy_raw | JSON | no | none | none |

### `ScanFinding` / `scan_findings` (`backend/models.py:181-196`)

| Column | Type | Nullable | Default | Key / constraints |
|---|---|---:|---|---|
| id | Integer | no | autoincrement | Primary key |
| commit_score_id | Integer | no | none | Foreign key to `commit_scores.id`; indexed |
| source_tool | String | no | none | none |
| package_name | String | yes | none | none |
| installed_version | String | yes | none | none |
| fixed_version | String | yes | none | none |
| cve_id | String | yes | none | none |
| severity | String | no | none | none |
| known_exploited | Boolean | no | `False` (Python-side) | none |
| epss_probability | Float | no | `0.0` (Python-side) | none |
| raw_finding | JSON | no | none | none |

- Relationships: the two child tables have foreign-key columns, but no ORM relationship properties. `init_db()` creates unique index `uq_commit_scores_repo_commit_sha` and removes duplicate repo/SHA records before adding it (`backend/database.py:25-51`).
- `sqlite3 <db> ".schema"` and `sqlite3 <db> "SELECT * ... LIMIT 3;"`: NOT FOUND (CLI is not installed). Equivalent SQLite API inspection was attempted on a temporary performance database; its raw JSON rows were too large to include as exact `sqlite3` CLI output. No claim is made here that this reproduces the requested CLI output after a fresh demo seed.

## 2. REST API

FastAPI routes from `backend/routers/*.py` and `backend/main.py`; request validation errors use FastAPI/Pydantic responses (normally HTTP 422). Explicit missing-commit errors use HTTP 404 with `{"detail":"No score found for commit '<sha>'"}`.

| Method / path | Inputs and purpose | Response structure / example | Errors |
|---|---|---|---|
| POST `/v1/scan/submit` | JSON: `repo` string, `commit_sha` string (minimum 7 chars), `environment` enum `dev|staging|prod` default `dev`, `semgrep_raw`, `owasp_raw`, `trivy_raw` objects default `{}`, optional `timestamp` datetime. Parses three reports, scores, stores/upserts commit and findings. | `ScoreResponse`: `repo`, `commit_sha`, `environment`, `sast_score`, `sca_score`, `container_score`, `raw_score`, `environment_multiplier`, `delta_factor`, `final_score`, `risk_level`, `recommended_action`, `created_at`, optional `score`, `risk_band`, `delta_vs_previous`, `top_fixes`. Seed-script console example (real command output, not JSON): `Seeded/updated: d3f0b10 — score 94.055 (Critical)`. | Validation 422. No explicit API-level error mapping beyond framework/database errors. |
| GET `/v1/score/{commit_sha}` | Path `commit_sha` string; fetch score. | `ScoreResponse` fields above (top-level optional aliases may be null/omitted under Pydantic response serialization). Real JSON body example: NOT FOUND (the API JSON response capture was interrupted). | 404 when no commit. |
| GET `/v1/repos` | No inputs; lists distinct repo names. | JSON string array, e.g. seeded repository names include `"demo/acme-webapp"`, `"demo/payments-api"`, `"demo/data-warehouse"`. | No custom errors. |
| GET `/v1/history/{repo:path}` | Path `repo` string, allowing slash-containing owner/repo. | JSON array of objects `{commit_sha, final_score, risk_level, environment, created_at}`. | No custom errors. |
| GET `/v1/breakdown/{commit_sha}` | Path `commit_sha`; component and finding detail. | `{repo, commit_sha, components:[{tool, counts:{critical,high,medium,low}, normalized_score}], known_exploited_count, findings:[{source_tool,package_name,installed_version,fixed_version,cve_id,rule_id,file_path,line_start,severity,known_exploited,epss_probability}]}`. | 404 when no commit. |
| GET `/v1/delta/{commit_sha}` | Path `commit_sha`; compares with previous commit for repo. | `{repo,commit_sha,current_score,previous_score,delta,trend}`; trend is `improving`, `regressing`, `flat`, or `first-commit`. | 404 when no commit. |
| GET `/v1/whatif/{commit_sha}?limit=3` | Path `commit_sha`; query `limit` integer default 3, constrained 1..50. | Array of `{package,installed_version,fixed_version,fix_known,findings_removed,current_score,simulated_score,score_reduction,source_tool,known_exploited}`. | 404 for absent commit; 422 for invalid limit. |
| GET `/v1/badge/{owner}/{repo}.svg` | Path owner/repo. | SVG image, `image/svg+xml`, cache header `public, max-age=300`. | No custom missing-data error; emits “no data” badge. |
| GET `/v1/badge/{repo:path}` | Path repo (including slash). | JSON `{schemaVersion:1,label:"security risk",message,color}`; no data produces `message:"no data"`, `color:"lightgrey"`. | No custom missing-data error. |
| GET `/health` | No inputs. | Actual observed response: `{"status":"ok"}`. | No custom errors. |

- Authentication/API-token checks: NOT FOUND (searched `backend/main.py`, routers, scanner submit client, workflow, and `.env.example`).
- CORS: `allow_origins=["*"]`, `allow_methods=["*"]`, `allow_headers=["*"]` (`backend/main.py:31-35`).
- Request/body-size limit and rate limiting: NOT FOUND (searched FastAPI setup, routers, Docker files, Compose).
- Ports: API 8000, Compose PostgreSQL 5432, Compose dashboard 3000:80; local Vite README/DEMO uses 5173. `backend/entrypoint.sh` starts Uvicorn on 8000.

## 3. SCORING

Exact implementation excerpts (paths are relative to repo):

- Base severity weight, `backend/scoring.py:33`: `SEVERITY_WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1}`
- Density, `backend/scoring.py:77-87`:
  ```python
  def _points_density_score(points: float) -> float:
      return min(100.0, (points / MAX_FINDING_POINTS) * 100.0)
  ```
- SAST and container exact functions, `backend/scoring.py:90-97`:
  ```python
  def compute_sast_score(counts: SeverityCounts) -> float:
      """Semgrep findings -> 0-100."""
      return _severity_density_score(counts)

  def compute_container_score(counts: SeverityCounts) -> float:
      """Trivy findings -> 0-100."""
      return _severity_density_score(counts)
  ```
- EPSS factor, `backend/services/findings.py:129-133`:
  ```python
  SEVERITY_WEIGHTS.get(str(item.get("severity", "low")).lower(), 1)
  * (1 + epss_alpha * float(item.get("epss_probability", 0.0) or 0.0))
  * (kev_multiplier if item.get("known_exploited") else 1.0)
  ```
  `EPSS_ALPHA` comes from `os.getenv("EPSS_ALPHA", "1.0")`; it must be finite and non-negative (`backend/services/epss.py:29-33`).
- KEV multiplier: finding points are multiplied by `kev_multiplier` only when `known_exploited` is true (excerpt above). `KEV_MULTIPLIER` default is `1.25`, must be finite and at least 1 (`backend/services/epss.py:36-40`). This is not the documented `KEV_BONUS`; code does not read `KEV_BONUS`.
- SAST: `compute_sast_score(counts)` returns severity density (`backend/scoring.py:90-92`); scan submission uses Semgrep counts and does not supply EPSS/KEV finding points for SAST.
- SCA: `backend/scoring.py:146-151` uses density derived from enriched finding points when supplied; if CVSS exists and count > 0, `round(0.5 * sca_density + 0.5 * min(100.0, sca_mean_cvss * 10.0), 4)`, else density.
- Container: `backend/scoring.py:152` uses enriched-point density when supplied, otherwise Trivy severity density.
- Raw score, `backend/scoring.py:154-156`: `weights = weights or (W_SAST, W_SCA, W_CONTAINER)` then `raw_score = sum(weight * score for weight, score in zip(weights, (sast_score, sca_score, container_score)))`; `adjusted_raw_score = raw_score`.
- SCA exact function, `backend/scoring.py:100-114`:
  ```python
  density = _severity_density_score(counts)
  if mean_cvss is None or counts.total() == 0:
      return density
  cvss_component = min(100.0, (mean_cvss / 10.0) * 100.0)
  return round(0.5 * density + 0.5 * cvss_component, 4)
  ```
- Weighted raw score exact statement, `backend/scoring.py:154-156`: `raw_score = sum(weight * score for weight, score in zip(weights, (sast_score, sca_score, container_score)))`.
- Environment multipliers, `backend/scoring.py:40-44`: dev `1.0`, staging `1.1`, prod `1.3`.
- Delta, `backend/scoring.py:160-169`: first commit (`previous_final_score is None`) gets `DELTA_REGRESSING_OR_FIRST` = `1.0`; otherwise the “improving” condition is `adjusted_raw_score < previous_final_score`, yielding `DELTA_IMPROVING` = `0.9`; all other cases get `1.0`.
- Cap and bands, `backend/scoring.py:49-54,117-122,171`: `final_score = min(100.0, adjusted_raw_score * env_multiplier * delta_factor)`. Band checks use `score <= upper_bound`: Low ≤20, Medium ≤50, High ≤75, Critical ≤100 (fallback Critical). Workflow threshold enforcement uses strict `score > threshold` (`.github/workflows/devsecops.yml`, threshold step).
- Configurable parameters: `DATABASE_URL` default `sqlite:///./devsecops.db` (`backend/database.py:18`); `EPSS_DATA_PATH` defaults to bundled `backend/data/epss.json` (`backend/services/epss.py:10,14`); `EPSS_ALPHA=1.0`; `KEV_MULTIPLIER=1.25`; `KEV_BONUS` appears in `.env.example`/Compose but is NOT USED by scoring code; `DEMO_DATA_SEED=true` in Compose/entrypoint; CI values `SCORING_API_URL`, `RISK_FAIL_THRESHOLD=75`, `DASHBOARD_URL`; frontend build `VITE_API_URL`. Fixed Python constants: `W_SAST=.35`, `W_SCA=.40`, `W_CONTAINER=.25`, severity points above, `MAX_FINDING_POINTS=50`, environment and delta values, risk bands (`backend/scoring.py:29-53`).
- `backend/scripts/calibrate_weights.py`: imports bundled `SAMPLES`; evaluates weight sets `default`, `equal`, `SCA-heavy`, `SAST-heavy`, EPSS alpha `0, 0.5, 1.0`, and KEV multiplier on/off; prints each scenario's repo, commit, score, descending rank. Run from repository root with `python backend/scripts/calibrate_weights.py` (or from backend with `python scripts/calibrate_weights.py`). It does not write output files.

## 4. KEV AND EPSS DATA

- EPSS: `backend/data/epss.json`, 1,732 bytes, JSON object with `snapshot_date:"2026-11-17"`, `source`, and `scores` map; 55 CVE keys. Scores are loaded from `scores`, converted to floats, and retained only when 0..1 (`backend/services/epss.py:13-26`). Missing/invalid file logs a warning and returns `{}`. `EPSS_DATA_PATH` can override path. No EPSS refresh script/cache found (searched `backend/services`, `backend/scripts`, `backend/data`).
- KEV offline fallback: `backend/data/known_exploited_vulnerabilities.json`, 97 bytes; JSON `{source,cves}`; one CVE (`CVE-2021-44228`); no explicit snapshot date/version field. The cache is `backend/.cache/known_exploited_vulnerabilities.json`, created at runtime; Compose mounts `kev_cache:/app/.cache`. Loader fetches the CISA URL, reads cached CVEs for 24 hours, refreshes after TTL, falls back to stale cache or bundled data on fetch error (`backend/services/kev.py:13-27,50-76,79-131`). No separate refresh script found.

## 5. CI WORKFLOW (`.github/workflows/devsecops.yml`, `scanners/submit_scores.py`)

- Triggers: push to `main`; pull requests targeting `main`.
- Jobs/step order:
  1. `semgrep-scan` (“SAST — Semgrep”): checkout `actions/checkout@v4`; `semgrep/semgrep-action@v1` with `p/security-audit`, SARIF false, continue-on-error; pip install `semgrep==1.86.0`; JSON scan; upload `semgrep-results` using `actions/upload-artifact@v4`.
  2. `owasp-scan` (“SCA — OWASP Dependency-Check”): checkout v4; `dependency-check/Dependency-Check_Action@main`, JSON, suppression file, `--failOnCVSS 11`, continue-on-error; upload `owasp-results` using upload-artifact v4.
  3. `trivy-scan` (“Container Scan — Trivy”): checkout v4; build backend Docker image; `aquasecurity/trivy-action@master`, JSON, severity CRITICAL/HIGH/MEDIUM/LOW, exit-code 0; upload `trivy-results` using upload-artifact v4.
  4. `score` (“Aggregate & Score”): needs three scanners; permissions `contents: read`, `pull-requests: write`; checkout v4; download each artifact using `actions/download-artifact@v4`; submit with Python; parse response; optional PR comment via `actions/github-script@v7.0.1`; enforce threshold.
- Exact version pins: checkout v4, upload/download artifact v4, GitHub script v7.0.1, Semgrep pip 1.86.0. Dependency-Check action uses floating `@main`; Trivy uses floating `@master` (no fixed version pin).
- Workflow env: `ENVIRONMENT` is prod on main, dev otherwise; `SCORING_API_URL` resolves repo variable, then secret, then `http://localhost:8000`; `RISK_FAIL_THRESHOLD` variable or `'75'`; `DASHBOARD_URL` variable or empty. Other repo variables/secrets: NOT FOUND in this workflow.
- PR comment duplicate prevention: body marker `<!-- uvs-risk-report -->`; paginates issue comments, updates the first comment containing marker or creates a new one. Exceptions are converted to `core.warning`; comment failure does not stop score threshold step. Fork PR limitations are not specially detected; comment API failure is caught and warns that fork tokens may be read-only. Workflow has `pull-requests: write` on score job.
- `submit_scores.py`: missing/empty/unparseable scanner files are warned on stderr and converted to `{}`; backend `URLError` returns exit 1; valid response is written if `--response-file`, prints score/action, and returns 0. Non-2xx HTTP errors are `urllib.error.URLError` and return 1. Invalid successful response JSON/key errors are not caught and can traceback (no explicit exit code). It does not require each report to contain findings.
- Backend partial reports: each absent/empty raw object parses as zero findings; backend still computes and persists a score from available reports. For a first commit, no prior score exists and delta factor is 1.0.

## 6. PARSERS

| Parser | Fields read | Normalized findings / severity map |
|---|---|---|
| Semgrep (`backend/parsers/semgrep.py`) | `results[]`, each `extra`, `extra.metadata.severity`, `extra.severity` | Parser returns counts, not per-finding normalized database rows. `metadata.severity=CRITICAL` → critical; `extra.severity=ERROR` → high; WARNING → medium; other/missing → low. Breakdown additionally reads `check_id`/`rule_id`, `path`, `start.line`. |
| Dependency-Check (`backend/parsers/owasp.py`) | `dependencies[]`, `vulnerabilities[]`, `severity`, `cvssv3.baseScore`, fallback `cvssv2.score` | severity CRITICAL→critical, HIGH→high, MEDIUM/MODERATE→medium, LOW→low, unknown→medium. Mean is over valid finite CVSS values 0..10. Normalizer reads `packages[0].id/name/version`, `fileName`, vulnerability `name`/CVE fields, severity; normalized keys include `source_tool`, package/version, `fixed_version` (currently `None` for OWASP), severity, CVE, KEV, EPSS, raw finding. |
| Trivy (`backend/parsers/trivy.py`) | `Results[]`, `Vulnerabilities[]`, `Severity` | CRITICAL→critical, HIGH→high, MEDIUM→medium, LOW/UNKNOWN→low, unknown→low. Normalizer also reads `VulnerabilityID`, `PkgName`, `InstalledVersion`, `FixedVersion`; normalized fields as above with `source_tool:"trivy"`. |

- These parsers receive Python dicts; malformed JSON text is handled upstream by `submit_scores.py` as empty object. Wrong-type arrays, non-dict entries, and absent keys are skipped/treated as empty by parser. Empty reports yield zero findings. Unknown severity maps low for Semgrep/Trivy and medium for OWASP (normalizer maps OWASP unknown to medium too). Semgrep `raw_finding_count` uses `len(results)` even when malformed elements are skipped.

## 7. FRONTEND

- `frontend/package.json`: React `^18.3.1`, React DOM `^18.3.1`, Recharts `^2.12.7`; dev dependencies `@types/react ^18.3.5`, `@types/react-dom ^18.3.0`, `@vitejs/plugin-react ^4.3.1`, TypeScript `^5.5.4`, Vite `^5.4.2`. App source is JSX/JS; TypeScript used for app source: no (TypeScript package and `tsconfig.json` exist).
- Components/page: `Dashboard` calls `/v1/repos`, `/v1/history/{repo}`, `/v1/score/{sha}`, `/v1/breakdown/{sha}`, `/v1/delta/{sha}`, `/v1/whatif/{sha}?limit=3`. It renders `RepoSelector`, `CommitTimeline`, score/risk card, `DeltaBadge`, projected score, `FixFirstCard`, `SeverityBreakdown`, footer.
- Repo selector selects repo (prefers `demo/acme-webapp` when available). Timeline is Recharts line chart with commit score, risk bands, environment, and clickable commits. Severity breakdown shows per-tool donut, count and normalized score; package findings include EPSS percent and “Known exploited” marker. Fix first allows selecting package suggestions and shows simulated score; it is titled “Fix first” in UI (not “Fix These First”). Footer says “Demo/sample data only — for presentation use, not live production scan results.” No badge endpoint is called by the dashboard.
- States: loading indicator; API unreachable message when repo load fails; empty repo message; empty breakdown selection message; no package fixes; what-if error message. History/score errors set shared error state; no dedicated empty history state beyond zero repo list.
- `npm run build` succeeded. Vite 5.4.21; output: `charts-B0_Xk53C.js 552.42 kB` (gzip 156.19 kB), others: index JS 3.15 kB, Dashboard JS 15.20 kB, CSS 0.72 kB, HTML 0.73 kB. Warning exact:
  ```
  (!) Some chunks are larger than 500 kB after minification. Consider:
  - Using dynamic import() to code-split the application
  - Use build.rollupOptions.output.manualChunks to improve chunking: https://rollupjs.org/configuration-options/#output-manualchunks
  - Adjust chunk size limit for this warning via build.chunkSizeWarningLimit.
  ```

## 8. DOCKER / RUN

- Compose services: `db` image `postgres:16-alpine`, 5432:5432, named volume `db_data:/var/lib/postgresql/data`, health check `pg_isready`; `api` built from `Dockerfile.backend`, 8000:8000, volume `kev_cache:/app/.cache`, depends on healthy DB; `frontend` built from `Dockerfile.frontend`, 3000:80, depends on healthy API.
- Compose env: DB user/password/database `devsecops`; API `DATABASE_URL` default PostgreSQL URL, `KEV_BONUS` default `0.0`, `DEMO_DATA_SEED` default `true`; frontend build arg `VITE_API_URL` default `http://localhost:8000`.
- Auto-seeding: `backend/entrypoint.sh` starts uvicorn, then runs `python scripts/post_samples.py --api-url http://127.0.0.1:8000` when `[ "${DEMO_DATA_SEED:-true}" = "true" ]`.
- `docker compose up --build -d`: attempted, failed before startup: Docker CLI could not connect to `//./pipe/dockerDesktopLinuxEngine` (“The system cannot find the file specified”). Dashboard loading at localhost:3000 and Compose-seeded data: NOT FOUND (Compose startup failed before any container started). `docker compose down` was not run because Compose did not start.
- Python: Docker backend `python:3.11-slim`; local configured Python 3.11.9. Node: Docker build `node:20-alpine`; local Node `v26.3.1`. `backend/requirements.txt` exact:
  ```
  fastapi==0.115.0
  uvicorn[standard]==0.30.6
  sqlalchemy==2.0.35
  pydantic==2.9.2
  python-multipart==0.0.9
  psycopg2-binary==2.9.9
  pytest==8.3.3
  httpx==0.27.2
  pytest-cov==5.0.0
  ```

## 9. TESTS

`cd backend; python -m pytest -v`: **75 passed, 0 failed**, one Starlette/AnyIO deprecation warning, 12.22 seconds.

| File / area | Count | Test names |
|---|---:|---|
| `tests/test_api.py` | 17 | `test_health`; `test_submit_clean_commit`; `test_resubmitting_same_repo_commit_updates_instead_of_duplicating`; `test_whatif_returns_package_fixes_and_unknown_owasp_version`; `test_whatif_limit_zero_findings_and_missing_commit`; `test_vulnerable_demo_sample_has_visible_fix_suggestions`; `test_known_exploited_findings_are_stored_and_prioritized`; `test_configured_kev_multiplier_is_applied_during_submission`; `test_breakdown_known_exploited_count_is_zero_for_clean_scan`; `test_badges_return_latest_scan_and_no_data_fallback`; `test_svg_badge_has_image_content_type_and_cache_header`; `test_submit_and_get_score`; `test_get_score_404_for_unknown_commit`; `test_history_returns_ordered_commits`; `test_breakdown_has_three_tools`; `test_list_repos`; `test_delta_reflects_previous_commit` |
| `tests/test_contribution_factors.py` | 4 | `test_kev_multiplier_increases_finding_contribution`; `test_epss_increases_finding_contribution`; `test_missing_epss_has_neutral_factor`; `test_zero_alpha_and_neutral_kev_multiplier_reproduce_base_points` |
| `tests/test_epss.py` | 2 | `test_epss_scores_load_from_mocked_local_catalog`; `test_epss_alpha_default_and_configurable` |
| `tests/test_kev.py` | 6 | `test_kev_fetcher_uses_cisa_feed_url`; `test_kev_feed_is_cached_for_24_hours`; `test_kev_refresh_failure_uses_stale_cache`; `test_kev_failure_without_cache_returns_empty_set_with_warning`; `test_kev_offline_fallback_is_used_and_cached`; `test_kev_multiplier_defaults_on` |
| `tests/test_parsers.py` | 14 | Semgrep: `test_empty_results`, `test_maps_error_to_high`, `test_maps_warning_to_medium_and_info_to_low`, `test_metadata_critical_override`, `test_missing_results_key_does_not_crash`, `test_partial_and_malformed_results_are_skipped_safely`; OWASP: `test_empty_dependencies`, `test_counts_and_mean_cvss`, `test_dependency_with_no_vulnerabilities`, `test_malformed_dependency_and_cvss_fields_are_tolerated`; Trivy: `test_empty_results`, `test_counts_by_severity`, `test_result_with_no_vulnerabilities_key`, `test_malformed_result_and_vulnerability_entries_are_tolerated` |
| `tests/test_post_samples.py` | 2 | `test_demo_sample_is_submitted_to_the_api`; `test_demo_sample_is_idempotently_upserted_even_when_already_present` |
| `tests/test_scoring.py` | 29 | Severity density: `test_zero_findings_scores_zero`, `test_all_critical_saturates_at_100`, `test_more_than_max_points_clamped_not_overflowed`, `test_single_low_finding_is_small_but_nonzero`, `test_severity_ordering_respected`; SCA: `test_zero_findings_no_cvss_scores_zero`, `test_blends_density_and_cvss`, `test_cvss_capped_at_100_equivalent`, `test_falls_back_to_density_when_cvss_missing_but_findings_exist`; risk bands: parametrized `test_band_boundaries` (11 cases: 0/Low, 20/Low, 20.5/Medium, 21/Medium, 50/Medium, 50.5/High, 51/High, 75/High, 75.5/Critical, 76/Critical, 100/Critical); full scoring: `test_clean_commit_scores_zero`, `test_dev_vs_prod_environment_multiplier_changes_score`, `test_delta_factor_rewards_improvement`, `test_delta_factor_does_not_reward_regression`, `test_first_commit_uses_neutral_delta_factor`, `test_all_critical_prod_commit_is_blocked_critical`, `test_final_score_never_exceeds_100`, `test_per_finding_multipliers_increase_score`, `test_weights_sum_matches_prd_spec` |
| `tests/test_submit_scores.py` | 1 | `test_submit_scores_saves_response_and_leaves_threshold_gate_to_workflow` |

## 10. PERFORMANCE

Measured against a local SQLite-backed FastAPI process on this machine; temporary benchmark script is in session storage outside the repository. Synthetic payload has 500 Semgrep findings and zero OWASP/Trivy findings. `submit` creates one commit; benchmark then creates 100 commits (alternating 500 and zero Semgrep findings); what-if runs on the 500-Semgrep commit (no package suggestions).

| Measurement | Observed time |
|---|---:|
| Submit, score, store 500 findings | 0.1811 s |
| GET what-if for that commit | 0.0159 s |
| GET history containing 100 commits | 0.0135 s |
| GET SVG badge | 0.0050 s |
| Five simultaneous submission requests | 1.2007 s total; 0 errors |

Machine: 8 logical processors; `Win32_OperatingSystem.TotalVisibleMemorySize` reported 16,493,352 KiB RAM. These are measurements from this run only.

## 11. SECURITY

- Authentication/token: NOT FOUND (backend routers/application and `scanners/submit_scores.py` have no auth/token check).
- CORS allows all origins, methods, and headers (see section 2). HTTPS termination/configuration: NOT FOUND in app, Compose, Dockerfiles, and workflow; URLs can be provided externally.
- Request size limit/rate limit: NOT FOUND in backend configuration and Compose.
- Input validation: Pydantic request model requires repo and SHA with minimum length 7; environment is enum; scanner raw reports are dicts; what-if limit is 1..50. Parsers defensively skip malformed entries.
- Secrets handling: workflow resolves scoring endpoint from repository variable or secret; `.env.example` contains local defaults and placeholder-compatible service values, not credentials for a remote system. Compose database credentials are literal defaults `devsecops`/`devsecops`.
- SQL access: SQLAlchemy ORM/select expressions for normal DB paths; raw SQL `CREATE UNIQUE INDEX IF NOT EXISTS` is issued through `text()` in `backend/database.py:45-51`. No SQL string interpolation with request values found in route queries.

## 12. DEMO DATA

- `backend/scripts/post_samples.py` defines 3 history repositories: `demo/acme-webapp`, `demo/payments-api`, `demo/data-warehouse`; 9 commits each (27 history submissions), environments dev/staging/prod. It also appends one `VULNERABLE_PAYLOAD` for `demo/acme-webapp` SHA `d3f0b10`, so `SAMPLES` contains 28 total payloads.
- Summing payload contents for all `SAMPLES`, including the extra vulnerable payload: 154 Semgrep + 28 OWASP + 32 Trivy = 214 findings. This is payload count before deduplication/persistence.
- CVEs: the sample includes `CVE-2021-44228`, `CVE-DEMO-0001` through `CVE-DEMO-0003`, and DEMO ranges represented in the file (`1001`–`1007`, `1010`–`1016`, `2001`–`2009`, `2101`–`2109`, `3001`–`3007`, `3101`–`3109`). The separate `VULNERABLE_PAYLOAD` uses actual `CVE-2021-44228` and `CVE-DEMO-0001`..`0003`.
- Script comments call these demo-only/sample data. UI footer labels “Demo/sample data only — for presentation use, not live production scan results.” README also says demo/sample in script and dashboard footer.

## 13. REPOSITORY FACTS

- Two-level tree (source/config directories and files; generated `.venv`, caches, node_modules omitted):
  ```
  .github/workflows/devsecops.yml
  backend/{data,parsers,routers,scripts,services,tests}/
  backend/{database.py,entrypoint.sh,main.py,models.py,requirements.txt,scoring.py}
  docs/{DevSecOps_PRD.docx,DevSecOps_Synopsis_Presentation.pptx,Synopsis_DevSecOps.docx}
  experiments/run_experiments.py
  frontend/{src,package.json,package-lock.json,index.html,tsconfig.json,vite.config.js}
  scanners/{owasp-suppression.xml,semgrep-config.yml,submit_scores.py,trivy-config.yaml}
  {DEMO.md,README.md,docker-compose.yml,Dockerfile.backend,Dockerfile.frontend,RUN_ME.bat,pytest.ini,.env.example}
  ```
- README headings: `DevSecOps Pipeline with Automated Vulnerability Scoring (UVS)`, Architecture, Stack, Quick start (3 commands), Local development, Backend, Frontend, Run tests, Scanner commands, Dynamic risk badge, UVS formula, GitHub Action setup, Demo data and sample runs, Known limitations, Repository layout.
- DEMO headings: `5-minute UVS demo`, Start the local demo, Click-through (about five minutes), API spot checks, Known limitations, EPSS and KEV scoring, Why these weights.
- Root license file: NOT FOUND (checked root files for `LICENSE*`/`COPYING*`).
- `git shortlog -sne --all`: `5 akhild24 <akhildwivedi453@gmail.com>`. First and last commit across refs are both `2026-11-22T16:08:54+05:30`, hash `ce2de3a`. `git rev-list --all --count -- <path>` reports 3 commits each touching backend, frontend, .github, scanners, and docs.

## 14. KNOWN GAPS

- README describes SQLite/Postgres and says Docker Compose seeds demo data; Compose config and entrypoint do implement those. README mentions a “KEV bonus” in scoring prose, while implementation uses per-finding KEV multiplier and no `KEV_BONUS`; `.env.example`/Compose still define `KEV_BONUS`.
- DEMO describes “Fix first” as estimates and KEV matching; these are implemented. README/DEMO do not establish auth; auth is absent. Reachability analysis: NOT FOUND (searched README/DEMO, backend, frontend, scanners).
- TODO/FIXME comments: NOT FOUND (searched backend, frontend, scanners, experiments).

END OF FACTS
