import argparse
import sys
import time

import httpx

DEFAULT_API = "http://127.0.0.1:8000"

# Demo-only seeded data for presentation. The UI labels this as sample data
# and should never be presented as live repository findings.

CLEAN_PAYLOAD = {
    "repo": "octocat/Hello-World",
    "commit_sha": "abc1234",
    "environment": "dev",
    "semgrep_raw": {"results": []},
    "owasp_raw": {"dependencies": []},
    "trivy_raw": {"Results": []},
}

VULNERABLE_PAYLOAD = {
    "repo": "demo/acme-webapp",
    "commit_sha": "d3f0b10",
    "environment": "prod",
    "semgrep_raw": {
        "results": [
            {
                "check_id": f"python.security.demo-rule-{index:02d}",
                "path": f"src/demo_module_{index:02d}.py",
                "start": {"line": index + 10},
                "extra": {
                    "severity": "ERROR",
                    "metadata": {"message": "Demo-only sample finding"},
                },
            }
            for index in range(20)
        ]
    },
    "owasp_raw": {
        "dependencies": [
            {
                "packages": [
                    {
                        "id": "pkg:maven/example/log4j-core@2.14.1",
                        "name": "log4j-core",
                        "version": "2.14.1",
                    }
                ],
                "vulnerabilities": [
                    {
                        "name": "CVE-2021-44228",
                        "severity": "CRITICAL",
                        "fixedVersion": "2.17.1",
                        "cvssv3": {"baseScore": 9.8},
                    }
                ],
            }
        ]
    },
    "trivy_raw": {
        "Results": [
            {
                "Target": "demo-image",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": f"CVE-DEMO-000{i}",
                        "PkgName": "openssl",
                        "InstalledVersion": "3.0.10",
                        "FixedVersion": "3.0.13",
                        "Severity": "HIGH",
                    }
                    for i in range(1, 4)
                ],
            }
        ]
    },
}


def build_demo_payload(repo: str, commit_sha: str, environment: str, semgrep_count: int, owasp_packages: list[dict], trivy_vulns: list[dict]) -> dict:
    return {
        "repo": repo,
        "commit_sha": commit_sha,
        "environment": environment,
        "semgrep_raw": {
            "results": [
                {
                    "check_id": f"demo.rule-{i + 1:02d}",
                    "path": f"src/demo_file_{i + 1:02d}.py",
                    "start": {"line": i + 1},
                    "extra": {
                        "severity": "ERROR" if i % 2 == 0 else "WARNING",
                        "metadata": {"message": "Demo-only sample finding"},
                    },
                }
                for i in range(semgrep_count)
            ]
        },
        "owasp_raw": {"dependencies": owasp_packages},
        "trivy_raw": {"Results": [{"Target": "demo-image", "Vulnerabilities": trivy_vulns}]},
    }


DEMO_HISTORY = {
    "demo/acme-webapp": [
        ("a1b2c3d", "dev", 4, [{"packages": [{"id": "pkg:maven/com.acme/payments@1.0.0", "name": "payments", "version": "1.0.0"}], "vulnerabilities": [{"name": "CVE-DEMO-1001", "severity": "HIGH", "cvssv3": {"baseScore": 7.2}}]}], [{"VulnerabilityID": "CVE-DEMO-2001", "PkgName": "openssl", "InstalledVersion": "3.0.10", "FixedVersion": "3.0.12", "Severity": "HIGH"}]),
        ("b2c3d4e", "dev", 7, [{"packages": [{"id": "pkg:maven/com.acme/payments@1.0.0", "name": "payments", "version": "1.0.0"}], "vulnerabilities": [{"name": "CVE-DEMO-1001", "severity": "HIGH", "cvssv3": {"baseScore": 7.2}}, {"name": "CVE-DEMO-1002", "severity": "CRITICAL", "cvssv3": {"baseScore": 9.4}}]}], [{"VulnerabilityID": "CVE-DEMO-2001", "PkgName": "openssl", "InstalledVersion": "3.0.10", "FixedVersion": "3.0.12", "Severity": "HIGH"}, {"VulnerabilityID": "CVE-DEMO-2002", "PkgName": "libssl", "InstalledVersion": "2.2.0", "FixedVersion": "2.2.8", "Severity": "MEDIUM"}]),
        ("c3d4e5f", "dev", 9, [{"packages": [{"id": "pkg:maven/com.acme/payments@1.0.0", "name": "payments", "version": "1.0.0"}], "vulnerabilities": [{"name": "CVE-DEMO-1001", "severity": "HIGH", "cvssv3": {"baseScore": 7.2}}, {"name": "CVE-DEMO-1002", "severity": "CRITICAL", "cvssv3": {"baseScore": 9.4}}, {"name": "CVE-DEMO-1003", "severity": "MEDIUM", "cvssv3": {"baseScore": 5.8}}]}], [{"VulnerabilityID": "CVE-DEMO-2001", "PkgName": "openssl", "InstalledVersion": "3.0.10", "FixedVersion": "3.0.12", "Severity": "HIGH"}, {"VulnerabilityID": "CVE-DEMO-2003", "PkgName": "nginx", "InstalledVersion": "1.18.0", "FixedVersion": "1.18.2", "Severity": "LOW"}]),
        ("d4e5f6a", "staging", 6, [{"packages": [{"id": "pkg:maven/com.acme/payments@1.0.0", "name": "payments", "version": "1.0.0"}], "vulnerabilities": [{"name": "CVE-DEMO-1002", "severity": "CRITICAL", "cvssv3": {"baseScore": 9.4}}]}], [{"VulnerabilityID": "CVE-DEMO-2004", "PkgName": "busybox", "InstalledVersion": "1.33", "FixedVersion": "1.35", "Severity": "HIGH"}]),
        ("e5f6a7b", "staging", 3, [{"packages": [{"id": "pkg:maven/com.acme/payments@1.0.1", "name": "payments", "version": "1.0.1"}], "vulnerabilities": [{"name": "CVE-DEMO-1004", "severity": "MEDIUM", "cvssv3": {"baseScore": 4.8}}]}], [{"VulnerabilityID": "CVE-DEMO-2005", "PkgName": "openssl", "InstalledVersion": "3.0.12", "FixedVersion": "3.0.14", "Severity": "HIGH"}]),
        ("f6a7b8c", "prod", 20, [{"packages": [{"id": "pkg:maven/com.acme/payments@1.0.1", "name": "payments", "version": "1.0.1"}], "vulnerabilities": [{"name": "CVE-DEMO-1005", "severity": "HIGH", "cvssv3": {"baseScore": 8.1}}, {"name": "CVE-DEMO-1006", "severity": "CRITICAL", "cvssv3": {"baseScore": 9.1}}]}], [{"VulnerabilityID": "CVE-DEMO-2006", "PkgName": "openssl", "InstalledVersion": "3.0.12", "FixedVersion": "3.0.14", "Severity": "CRITICAL"}, {"VulnerabilityID": "CVE-DEMO-2007", "PkgName": "libxml2", "InstalledVersion": "2.9.12", "FixedVersion": "2.9.14", "Severity": "HIGH"}]),
        ("a7b8c9d", "prod", 2, [{"packages": [{"id": "pkg:maven/com.acme/payments@1.0.2", "name": "payments", "version": "1.0.2"}], "vulnerabilities": [{"name": "CVE-DEMO-1007", "severity": "MEDIUM", "cvssv3": {"baseScore": 5.1}}]}], [{"VulnerabilityID": "CVE-DEMO-2008", "PkgName": "openssl", "InstalledVersion": "3.0.14", "FixedVersion": "3.0.16", "Severity": "MEDIUM"}]),
        ("b8c9d0e", "prod", 1, [], [{"VulnerabilityID": "CVE-DEMO-2009", "PkgName": "curl", "InstalledVersion": "7.74.0", "FixedVersion": "7.79.0", "Severity": "LOW"}]),
        ("c9d0e1f", "prod", 0, [], []),
    ],
    "demo/payments-api": [
        ("p1a2b3c", "dev", 6, [{"packages": [{"id": "pkg:nuget/Payments.Api/stack@2.2.0", "name": "stack", "version": "2.2.0"}], "vulnerabilities": [{"name": "CVE-DEMO-1010", "severity": "HIGH", "cvssv3": {"baseScore": 8.9}}]}], [{"VulnerabilityID": "CVE-DEMO-2101", "PkgName": "openssl", "InstalledVersion": "3.0.8", "FixedVersion": "3.0.11", "Severity": "HIGH"}]),
        ("p2b3c4d", "dev", 8, [{"packages": [{"id": "pkg:nuget/Payments.Api/stack@2.2.0", "name": "stack", "version": "2.2.0"}], "vulnerabilities": [{"name": "CVE-DEMO-1010", "severity": "HIGH", "cvssv3": {"baseScore": 8.9}}, {"name": "CVE-DEMO-1011", "severity": "CRITICAL", "cvssv3": {"baseScore": 9.7}}]}], [{"VulnerabilityID": "CVE-DEMO-2102", "PkgName": "cacerts", "InstalledVersion": "2.0", "FixedVersion": "2.1", "Severity": "HIGH"}, {"VulnerabilityID": "CVE-DEMO-2103", "PkgName": "libcurl", "InstalledVersion": "7.68", "FixedVersion": "7.78", "Severity": "MEDIUM"}]),
        ("p3c4d5e", "dev", 9, [{"packages": [{"id": "pkg:nuget/Payments.Api/stack@2.2.1", "name": "stack", "version": "2.2.1"}], "vulnerabilities": [{"name": "CVE-DEMO-1012", "severity": "CRITICAL", "cvssv3": {"baseScore": 9.9}}]}], [{"VulnerabilityID": "CVE-DEMO-2104", "PkgName": "libxml2", "InstalledVersion": "2.9.8", "FixedVersion": "2.9.10", "Severity": "CRITICAL"}]),
        ("p4d5e6f", "staging", 5, [{"packages": [{"id": "pkg:nuget/Payments.Api/stack@2.2.1", "name": "stack", "version": "2.2.1"}], "vulnerabilities": [{"name": "CVE-DEMO-1013", "severity": "MEDIUM", "cvssv3": {"baseScore": 5.2}}]}], [{"VulnerabilityID": "CVE-DEMO-2105", "PkgName": "openssl", "InstalledVersion": "3.0.10", "FixedVersion": "3.0.13", "Severity": "HIGH"}]),
        ("p5e6f7a", "staging", 4, [], [{"VulnerabilityID": "CVE-DEMO-2106", "PkgName": "openssl", "InstalledVersion": "3.0.13", "FixedVersion": "3.0.15", "Severity": "LOW"}]),
        ("p6f7a8b", "prod", 7, [{"packages": [{"id": "pkg:nuget/Payments.Api/stack@2.3.0", "name": "stack", "version": "2.3.0"}], "vulnerabilities": [{"name": "CVE-DEMO-1014", "severity": "CRITICAL", "cvssv3": {"baseScore": 9.2}}, {"name": "CVE-DEMO-1015", "severity": "HIGH", "cvssv3": {"baseScore": 7.9}}]}], [{"VulnerabilityID": "CVE-DEMO-2107", "PkgName": "curl", "InstalledVersion": "7.74", "FixedVersion": "7.80", "Severity": "HIGH"}]),
        ("p7a8b9c", "prod", 3, [{"packages": [{"id": "pkg:nuget/Payments.Api/stack@2.3.0", "name": "stack", "version": "2.3.0"}], "vulnerabilities": [{"name": "CVE-DEMO-1016", "severity": "MEDIUM", "cvssv3": {"baseScore": 5.6}}]}], [{"VulnerabilityID": "CVE-DEMO-2108", "PkgName": "openssl", "InstalledVersion": "3.0.15", "FixedVersion": "3.0.16", "Severity": "MEDIUM"}]),
        ("p8b9c0d", "prod", 2, [], [{"VulnerabilityID": "CVE-DEMO-2109", "PkgName": "nginx", "InstalledVersion": "1.21.4", "FixedVersion": "1.21.6", "Severity": "LOW"}]),
        ("p9c0d1e", "prod", 1, [], []),
    ],
    "demo/data-warehouse": [
        ("d1a2b3c", "dev", 5, [{"packages": [{"id": "pkg:golang/github.com/example/db@0.9.0", "name": "db", "version": "0.9.0"}], "vulnerabilities": [{"name": "CVE-DEMO-3001", "severity": "HIGH", "cvssv3": {"baseScore": 7.5}}]}], [{"VulnerabilityID": "CVE-DEMO-3101", "PkgName": "postgresql", "InstalledVersion": "14.0", "FixedVersion": "14.3", "Severity": "HIGH"}]),
        ("d2b3c4d", "dev", 7, [{"packages": [{"id": "pkg:golang/github.com/example/db@0.9.0", "name": "db", "version": "0.9.0"}], "vulnerabilities": [{"name": "CVE-DEMO-3001", "severity": "HIGH", "cvssv3": {"baseScore": 7.5}}, {"name": "CVE-DEMO-3002", "severity": "CRITICAL", "cvssv3": {"baseScore": 9.3}}]}], [{"VulnerabilityID": "CVE-DEMO-3102", "PkgName": "postgresql", "InstalledVersion": "14.0", "FixedVersion": "14.3", "Severity": "CRITICAL"}, {"VulnerabilityID": "CVE-DEMO-3103", "PkgName": "libssl", "InstalledVersion": "2.0", "FixedVersion": "2.1", "Severity": "MEDIUM"}]),
        ("d3c4d5e", "dev", 8, [{"packages": [{"id": "pkg:golang/github.com/example/db@0.9.1", "name": "db", "version": "0.9.1"}], "vulnerabilities": [{"name": "CVE-DEMO-3003", "severity": "CRITICAL", "cvssv3": {"baseScore": 9.5}}]}], [{"VulnerabilityID": "CVE-DEMO-3104", "PkgName": "postgresql", "InstalledVersion": "14.3", "FixedVersion": "14.5", "Severity": "MEDIUM"}]),
        ("w4e5f6a", "staging", 4, [{"packages": [{"id": "pkg:golang/github.com/example/db@0.9.2", "name": "db", "version": "0.9.2"}], "vulnerabilities": [{"name": "CVE-DEMO-3004", "severity": "MEDIUM", "cvssv3": {"baseScore": 5.6}}]}], [{"VulnerabilityID": "CVE-DEMO-3105", "PkgName": "openssl", "InstalledVersion": "3.0.11", "FixedVersion": "3.0.13", "Severity": "HIGH"}]),
        ("d5f6a7b", "staging", 2, [], [{"VulnerabilityID": "CVE-DEMO-3106", "PkgName": "openssl", "InstalledVersion": "3.0.13", "FixedVersion": "3.0.15", "Severity": "LOW"}]),
        ("d6a7b8c", "prod", 6, [{"packages": [{"id": "pkg:golang/github.com/example/db@0.9.3", "name": "db", "version": "0.9.3"}], "vulnerabilities": [{"name": "CVE-DEMO-3005", "severity": "HIGH", "cvssv3": {"baseScore": 8.3}}, {"name": "CVE-DEMO-3006", "severity": "CRITICAL", "cvssv3": {"baseScore": 9.1}}]}], [{"VulnerabilityID": "CVE-DEMO-3107", "PkgName": "openssl", "InstalledVersion": "3.0.15", "FixedVersion": "3.0.16", "Severity": "CRITICAL"}]),
        ("d7b8c9d", "prod", 4, [{"packages": [{"id": "pkg:golang/github.com/example/db@0.9.4", "name": "db", "version": "0.9.4"}], "vulnerabilities": [{"name": "CVE-DEMO-3007", "severity": "MEDIUM", "cvssv3": {"baseScore": 5.1}}]}], [{"VulnerabilityID": "CVE-DEMO-3108", "PkgName": "openssl", "InstalledVersion": "3.0.16", "FixedVersion": "3.0.17", "Severity": "MEDIUM"}]),
        ("d8c9d0e", "prod", 1, [], [{"VulnerabilityID": "CVE-DEMO-3109", "PkgName": "curl", "InstalledVersion": "7.76", "FixedVersion": "7.81", "Severity": "LOW"}]),
        ("d9d0e1f", "prod", 0, [], []),
    ],
}

DEMO_SAMPLES = [
    build_demo_payload(repo, commit_sha, environment, semgrep_count, owasp_packages, trivy_vulns)
    for repo, history in DEMO_HISTORY.items()
    for commit_sha, environment, semgrep_count, owasp_packages, trivy_vulns in history
]

SAMPLES = (*DEMO_SAMPLES, VULNERABLE_PAYLOAD)


def wait_for_api(client: httpx.Client, api: str, timeout: float = 45.0) -> None:
    deadline = time.monotonic() + timeout
    while True:
        try:
            response = client.get(f"{api}/health")
            response.raise_for_status()
            return
        except httpx.RequestError:
            if time.monotonic() >= deadline:
                raise RuntimeError(f"Scoring API did not become ready at {api} within {timeout:g}s")
            time.sleep(1)


def seed_sample(client: httpx.Client, api: str, payload: dict) -> None:
    sha = payload["commit_sha"]
    response = client.post(f"{api}/v1/scan/submit", json=payload)
    response.raise_for_status()
    result = response.json()
    print(f"Seeded/updated: {sha} — score {result['final_score']} ({result['risk_level']})")


def main() -> int:
    parser = argparse.ArgumentParser(description="Load repeatable sample findings into a running UVS API.")
    parser.add_argument("--api-url", default=DEFAULT_API, help="Scoring API base URL")
    args = parser.parse_args()
    api = args.api_url.rstrip("/")

    try:
        with httpx.Client(timeout=10.0) as client:
            wait_for_api(client, api)
            for payload in SAMPLES:
                seed_sample(client, api, payload)
    except (httpx.HTTPError, RuntimeError) as exc:
        print(f"Could not load demo samples: {exc}", file=sys.stderr)
        return 1

    print(f"Demo dashboard: {api.replace(':8000', ':5173')}")
    print(f"API docs: {api}/docs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
