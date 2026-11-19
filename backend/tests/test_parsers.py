from parsers.owasp import parse_owasp
from parsers.semgrep import parse_semgrep
from parsers.trivy import parse_trivy


class TestSemgrepParser:
    def test_empty_results(self):
        findings = parse_semgrep({"results": []})
        assert findings.counts.total() == 0

    def test_maps_error_to_high(self):
        raw = {"results": [{"extra": {"severity": "ERROR", "metadata": {}}}]}
        findings = parse_semgrep(raw)
        assert findings.counts.high == 1

    def test_maps_warning_to_medium_and_info_to_low(self):
        raw = {
            "results": [
                {"extra": {"severity": "WARNING", "metadata": {}}},
                {"extra": {"severity": "INFO", "metadata": {}}},
            ]
        }
        findings = parse_semgrep(raw)
        assert findings.counts.medium == 1
        assert findings.counts.low == 1

    def test_metadata_critical_override(self):
        raw = {"results": [{"extra": {"severity": "ERROR", "metadata": {"severity": "CRITICAL"}}}]}
        findings = parse_semgrep(raw)
        assert findings.counts.critical == 1
        assert findings.counts.high == 0

    def test_missing_results_key_does_not_crash(self):
        findings = parse_semgrep({})
        assert findings.counts.total() == 0

    def test_partial_and_malformed_results_are_skipped_safely(self):
        findings = parse_semgrep(
            {"results": [None, "bad", {"extra": None}, {"extra": {"severity": "ERROR"}}]}
        )
        assert findings.counts.high == 1
        assert findings.raw_finding_count == 4


class TestOwaspParser:
    def test_empty_dependencies(self):
        findings = parse_owasp({"dependencies": []})
        assert findings.counts.total() == 0
        assert findings.mean_cvss is None

    def test_counts_and_mean_cvss(self):
        raw = {
            "dependencies": [
                {
                    "vulnerabilities": [
                        {"severity": "HIGH", "cvssv3": {"baseScore": 8.0}},
                        {"severity": "CRITICAL", "cvssv3": {"baseScore": 9.5}},
                    ]
                },
                {"vulnerabilities": [{"severity": "LOW", "cvssv2": {"score": 2.0}}]},
            ]
        }
        findings = parse_owasp(raw)
        assert findings.counts.high == 1
        assert findings.counts.critical == 1
        assert findings.counts.low == 1
        assert findings.mean_cvss == round((8.0 + 9.5 + 2.0) / 3, 2)

    def test_dependency_with_no_vulnerabilities(self):
        raw = {"dependencies": [{"vulnerabilities": []}, {}]}
        findings = parse_owasp(raw)
        assert findings.counts.total() == 0

    def test_malformed_dependency_and_cvss_fields_are_tolerated(self):
        findings = parse_owasp(
            {
                "dependencies": [
                    None,
                    {"vulnerabilities": "invalid"},
                    {
                        "vulnerabilities": [
                            None,
                            {"severity": "HIGH", "cvssv3": {"baseScore": "not-a-score"}},
                        ]
                    },
                ]
            }
        )
        assert findings.counts.high == 1
        assert findings.mean_cvss is None


class TestTrivyParser:
    def test_empty_results(self):
        findings = parse_trivy({"Results": []})
        assert findings.counts.total() == 0

    def test_counts_by_severity(self):
        raw = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {"Severity": "CRITICAL"},
                        {"Severity": "HIGH"},
                        {"Severity": "UNKNOWN"},
                    ]
                }
            ]
        }
        findings = parse_trivy(raw)
        assert findings.counts.critical == 1
        assert findings.counts.high == 1
        assert findings.counts.low == 1  # UNKNOWN folded into low

    def test_result_with_no_vulnerabilities_key(self):
        raw = {"Results": [{"Target": "clean-image"}]}
        findings = parse_trivy(raw)
        assert findings.counts.total() == 0

    def test_malformed_result_and_vulnerability_entries_are_tolerated(self):
        findings = parse_trivy(
            {"Results": [None, {"Vulnerabilities": "invalid"}, {"Vulnerabilities": [None, {"Severity": "HIGH"}]}]}
        )
        assert findings.counts.high == 1
        assert findings.raw_finding_count == 1
