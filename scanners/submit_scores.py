#!/usr/bin/env python3
"""
Reads the three raw scanner JSON artifacts produced by the GitHub Actions
workflow and POSTs them to the FastAPI Scoring Engine's /v1/scan/submit
endpoint. Used by the `score` job in .github/workflows/devsecops.yml.

Usage:
    python3 submit_scores.py \
        --repo owner/name --commit-sha <sha> --environment prod \
        --semgrep results/semgrep.json \
        --owasp results/dependency-check-report.json \
        --trivy results/trivy.json \
        --api-url http://localhost:8000
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request


def load_json_safely(path: str) -> dict:
    """Missing/empty scan artifacts are treated as zero-findings, not errors —
    a tool can legitimately produce an empty result on a clean repo."""
    try:
        with open(path, "r") as f:
            content = f.read().strip()
            return json.loads(content) if content else {}
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"warning: could not read {path} ({exc}); treating as empty", file=sys.stderr)
        return {}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--environment", default="dev", choices=["dev", "staging", "prod"])
    parser.add_argument("--semgrep", required=True)
    parser.add_argument("--owasp", required=True)
    parser.add_argument("--trivy", required=True)
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--response-file")
    args = parser.parse_args()

    payload = {
        "repo": args.repo,
        "commit_sha": args.commit_sha,
        "environment": args.environment,
        "semgrep_raw": load_json_safely(args.semgrep),
        "owasp_raw": load_json_safely(args.owasp),
        "trivy_raw": load_json_safely(args.trivy),
    }

    url = f"{args.api_url.rstrip('/')}/v1/scan/submit"
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read())
    except urllib.error.URLError as exc:
        print(f"error: could not reach scoring engine at {url}: {exc}", file=sys.stderr)
        return 1

    if args.response_file:
        with open(args.response_file, "w", encoding="utf-8") as response_file:
            json.dump(body, response_file, indent=2)

    print(f"UVS Final Score: {body['score']} ({body['risk_band']})")
    print(f"Recommended action: {body['recommended_action']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
