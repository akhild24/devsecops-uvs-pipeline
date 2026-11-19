import json
import sys

from scanners import submit_scores


def test_submit_scores_saves_response_and_leaves_threshold_gate_to_workflow(
    tmp_path, monkeypatch
):
    scan_paths = []
    for name in ("semgrep", "owasp", "trivy"):
        path = tmp_path / f"{name}.json"
        path.write_text("{}", encoding="utf-8")
        scan_paths.append(path)
    response_path = tmp_path / "response.json"
    response_body = {
        "score": 90.0,
        "risk_band": "Critical",
        "recommended_action": "Block merge",
        "top_fixes": [],
    }

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self):
            return json.dumps(response_body).encode("utf-8")

    monkeypatch.setattr(
        submit_scores.urllib.request,
        "urlopen",
        lambda request, timeout: FakeResponse(),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "submit_scores.py",
            "--repo",
            "test/repo",
            "--commit-sha",
            "abc1234",
            "--semgrep",
            str(scan_paths[0]),
            "--owasp",
            str(scan_paths[1]),
            "--trivy",
            str(scan_paths[2]),
            "--api-url",
            "https://api.example.test",
            "--response-file",
            str(response_path),
        ],
    )

    assert submit_scores.main() == 0
    assert json.loads(response_path.read_text(encoding="utf-8")) == response_body
