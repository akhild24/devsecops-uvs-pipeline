import os

# Use an isolated in-memory-like sqlite file for tests, set BEFORE importing
# database/main so the engine binds to it.
os.environ["DATABASE_URL"] = "sqlite:///./test_devsecops.db"

import pytest
from fastapi.testclient import TestClient

from database import engine, init_db
from main import app
from routers import scan as scan_router


@pytest.fixture(scope="module", autouse=True)
def _setup_db():
    init_db()
    yield
    engine.dispose()
    if os.path.exists("./test_devsecops.db"):
        os.remove("./test_devsecops.db")


client = TestClient(app)


@pytest.fixture(autouse=True)
def _prevent_kev_network(monkeypatch):
    monkeypatch.setattr(scan_router, "get_known_exploited_cves", lambda: set())
    monkeypatch.delenv("KEV_MULTIPLIER", raising=False)


CLEAN_PAYLOAD = {
    "repo": "octocat/Hello-World",
    "commit_sha": "abc1234",
    "environment": "dev",
    "semgrep_raw": {"results": []},
    "owasp_raw": {"dependencies": []},
    "trivy_raw": {"Results": []},
}

VULNERABLE_PAYLOAD = {
    "repo": "octocat/Hello-World",
    "commit_sha": "def5678",
    "environment": "prod",
    "semgrep_raw": {"results": [{"extra": {"severity": "ERROR", "metadata": {}}}] * 5},
    "owasp_raw": {
        "dependencies": [
            {"vulnerabilities": [{"severity": "CRITICAL", "cvssv3": {"baseScore": 9.8}}]}
        ]
    },
    "trivy_raw": {"Results": [{"Vulnerabilities": [{"Severity": "HIGH"}] * 3}]},
}


def _submit(payload):
    resp = client.post("/v1/scan/submit", json=payload)
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_submit_clean_commit():
    body = _submit(CLEAN_PAYLOAD)
    assert body["final_score"] == 0.0
    assert body["risk_level"] == "Low"
    assert body["score"] == 0.0
    assert body["risk_band"] == "Low"
    assert body["delta_vs_previous"] is None
    assert body["commit_sha"] == CLEAN_PAYLOAD["commit_sha"]
    assert body["top_fixes"] == []


def test_resubmitting_same_repo_commit_updates_instead_of_duplicating():
    repo = "demo/idempotency"
    payload = {**CLEAN_PAYLOAD, "repo": repo, "commit_sha": "idem0001"}
    _submit(payload)
    updated = {
        **payload,
        "semgrep_raw": {
            "results": [
                {
                    "check_id": "python.security.demo-rule",
                    "path": "src/example.py",
                    "start": {"line": 23},
                    "extra": {
                        "severity": "ERROR",
                        "metadata": {"severity": "HIGH"},
                    },
                }
            ]
        },
    }
    _submit(updated)

    history = client.get(f"/v1/history/{repo}").json()
    assert [item["commit_sha"] for item in history] == ["idem0001"]
    details = client.get("/v1/breakdown/idem0001").json()["findings"]
    assert details == [
        {
            "source_tool": "semgrep",
            "package_name": None,
            "installed_version": None,
            "fixed_version": None,
            "cve_id": None,
            "rule_id": "python.security.demo-rule",
            "file_path": "src/example.py",
            "line_start": 23,
            "severity": "high",
            "known_exploited": False,
            "epss_probability": 0.0,
            "epss_probability": 0.0,
        }
    ]


def test_whatif_returns_package_fixes_and_unknown_owasp_version():
    payload = {
        "repo": "test/whatif",
        "commit_sha": "whatif123",
        "semgrep_raw": {"results": [{"extra": {"severity": "ERROR", "metadata": {}}}]},
        "owasp_raw": {
            "dependencies": [
                {
                    "packages": [{"id": "pkg:maven/example/lib-a@1.2", "name": "lib-a", "version": "1.2"}],
                    "vulnerabilities": [
                        {"severity": "CRITICAL", "cvssv3": {"baseScore": 9.8}}
                    ],
                }
            ]
        },
        "trivy_raw": {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "PkgName": "lib-b",
                            "InstalledVersion": "2.0",
                            "FixedVersion": "2.1",
                            "Severity": "HIGH",
                        },
                        {
                            "PkgName": "lib-b",
                            "InstalledVersion": "2.0",
                            "FixedVersion": "2.1",
                            "Severity": "HIGH",
                        },
                    ]
                }
            ]
        },
    }
    assert client.post("/v1/scan/submit", json=payload).status_code == 200

    response = client.get("/v1/whatif/whatif123")

    assert response.status_code == 200
    fixes = response.json()
    assert len(fixes) == 2
    assert fixes[0]["score_reduction"] >= fixes[1]["score_reduction"]
    by_package = {fix["package"]: fix for fix in fixes}
    assert by_package["lib-b"]["fixed_version"] == "2.1"
    assert by_package["lib-b"]["findings_removed"] == 2
    assert by_package["lib-b"]["fix_known"] is True
    assert by_package["lib-a"]["fixed_version"] is None
    assert by_package["lib-a"]["fix_known"] is False
    assert by_package["lib-a"]["source_tool"] == "owasp"
    assert all(fix["score_reduction"] > 0 for fix in fixes)


def test_whatif_limit_zero_findings_and_missing_commit():
    _submit(CLEAN_PAYLOAD)
    response = client.get("/v1/whatif/abc1234")
    assert response.status_code == 200
    assert response.json() == []
    assert client.get("/v1/whatif/abc1234?limit=0").status_code == 422
    assert client.get("/v1/whatif/not-found").status_code == 404


def test_vulnerable_demo_sample_has_visible_fix_suggestions():
    from scripts.post_samples import VULNERABLE_PAYLOAD as demo_payload

    payload = {
        **demo_payload,
        "repo": "test/demo-fix-suggestions",
        "commit_sha": "demofix123",
    }
    assert client.post("/v1/scan/submit", json=payload).status_code == 200

    response = client.get("/v1/whatif/demofix123")

    assert response.status_code == 200
    fixes = response.json()
    assert fixes
    assert {fix["package"] for fix in fixes} == {"log4j-core", "openssl"}


def test_known_exploited_findings_are_stored_and_prioritized(monkeypatch):
    monkeypatch.setattr(
        scan_router,
        "get_known_exploited_cves",
        lambda: {"CVE-2026-2222"},
    )
    payload = {
        "repo": "test/kev",
        "commit_sha": "kevtest1",
        "semgrep_raw": {"results": []},
        "owasp_raw": {"dependencies": []},
        "trivy_raw": {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "PkgName": "known-lib",
                            "InstalledVersion": "1.0",
                            "FixedVersion": "1.1",
                            "VulnerabilityID": "CVE-2026-2222",
                            "Severity": "HIGH",
                        },
                        {
                            "PkgName": "other-lib",
                            "InstalledVersion": "1.0",
                            "FixedVersion": "1.1",
                            "VulnerabilityID": "CVE-2026-3333",
                            "Severity": "HIGH",
                        },
                    ]
                }
            ]
        },
    }
    response = client.post("/v1/scan/submit", json=payload)
    assert response.status_code == 200

    breakdown = client.get("/v1/breakdown/kevtest1").json()
    assert breakdown["known_exploited_count"] == 1
    known_finding = next(item for item in breakdown["findings"] if item["known_exploited"])
    assert known_finding["cve_id"] == "CVE-2026-2222"
    assert known_finding["package_name"] == "known-lib"

    fixes = client.get("/v1/whatif/kevtest1").json()
    assert fixes[0]["package"] == "known-lib"
    assert fixes[0]["known_exploited"] is True


def test_configured_kev_multiplier_is_applied_during_submission(monkeypatch):
    monkeypatch.setattr(
        scan_router,
        "get_known_exploited_cves",
        lambda: {"CVE-2026-4444"},
    )
    payload = {
        "repo": "test/kev-bonus",
        "commit_sha": "kevbonus1",
        "semgrep_raw": {"results": []},
        "owasp_raw": {"dependencies": []},
        "trivy_raw": {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "PkgName": "bonus-lib",
                            "VulnerabilityID": "CVE-2026-4444",
                            "Severity": "HIGH",
                        }
                    ]
                }
            ]
        },
    }

    monkeypatch.setenv("KEV_MULTIPLIER", "1.25")
    bumped_score = client.post("/v1/scan/submit", json=payload).json()["score"]
    monkeypatch.setenv("KEV_MULTIPLIER", "1")
    baseline_payload = {**payload, "repo": "test/kev-bonus-disabled", "commit_sha": "kevbonus2"}
    baseline_score = client.post("/v1/scan/submit", json=baseline_payload).json()["score"]

    assert bumped_score > baseline_score


def test_breakdown_known_exploited_count_is_zero_for_clean_scan():
    _submit(CLEAN_PAYLOAD)
    response = client.get(f"/v1/breakdown/{CLEAN_PAYLOAD['commit_sha']}")
    assert response.status_code == 200
    assert response.json()["known_exploited_count"] == 0


def test_badges_return_latest_scan_and_no_data_fallback():
    no_data = client.get("/v1/badge/missing/repository")
    assert no_data.status_code == 200
    assert no_data.json() == {
        "schemaVersion": 1,
        "label": "security risk",
        "message": "no data",
        "color": "lightgrey",
    }

    first = {
        **CLEAN_PAYLOAD,
        "repo": "badge/example",
        "commit_sha": "badge001",
    }
    second = {
        **VULNERABLE_PAYLOAD,
        "repo": "badge/example",
        "commit_sha": "badge002",
    }
    client.post("/v1/scan/submit", json=first)
    latest_score = client.post("/v1/scan/submit", json=second).json()["score"]

    badge = client.get("/v1/badge/badge/example")
    assert badge.status_code == 200
    assert badge.json()["message"].startswith(f"{latest_score:.0f} ")
    assert badge.json()["color"] in {"brightgreen", "yellow", "orange", "red"}


def test_svg_badge_has_image_content_type_and_cache_header():
    response = client.get("/v1/badge/missing/repository.svg")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/svg+xml")
    assert response.headers["cache-control"] == "public, max-age=300"
    assert "<svg" in response.text
    assert "no data" in response.text


def test_submit_and_get_score():
    _submit(VULNERABLE_PAYLOAD)
    resp = client.get(f"/v1/score/{VULNERABLE_PAYLOAD['commit_sha']}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["final_score"] > 0
    assert body["environment"] == "prod"


def test_get_score_404_for_unknown_commit():
    resp = client.get("/v1/score/does-not-exist")
    assert resp.status_code == 404


def test_history_returns_ordered_commits():
    _submit(CLEAN_PAYLOAD)
    _submit(VULNERABLE_PAYLOAD)
    resp = client.get("/v1/history/octocat/Hello-World")
    assert resp.status_code == 200
    shas = [c["commit_sha"] for c in resp.json()]
    assert "abc1234" in shas
    assert "def5678" in shas


def test_breakdown_has_three_tools():
    _submit(VULNERABLE_PAYLOAD)
    resp = client.get(f"/v1/breakdown/{VULNERABLE_PAYLOAD['commit_sha']}")
    assert resp.status_code == 200
    tools = {c["tool"] for c in resp.json()["components"]}
    assert tools == {"semgrep", "owasp-dependency-check", "trivy"}


def test_list_repos():
    _submit(CLEAN_PAYLOAD)
    resp = client.get("/v1/repos")
    assert resp.status_code == 200
    assert "octocat/Hello-World" in resp.json()


def test_delta_reflects_previous_commit():
    _submit(CLEAN_PAYLOAD)
    _submit(VULNERABLE_PAYLOAD)
    resp = client.get(f"/v1/delta/{VULNERABLE_PAYLOAD['commit_sha']}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["previous_score"] == 0.0
    assert body["trend"] in {"improving", "regressing", "flat"}



