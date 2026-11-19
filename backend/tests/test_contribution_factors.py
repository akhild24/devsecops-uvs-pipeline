from services.findings import effective_finding_points, normalize_scan_findings


def one_finding(cve="CVE-2026-4444", epss=None, kev=None):
    return normalize_scan_findings(
        {}, {"Results": [{"Vulnerabilities": [{"PkgName": "pkg", "Severity": "HIGH", "VulnerabilityID": cve}]}]},
        kev or set(), epss or {},
    )


def test_kev_multiplier_increases_finding_contribution():
    finding = one_finding(kev={"CVE-2026-4444"})
    assert effective_finding_points(finding, 1.25, 1) > effective_finding_points(finding, 1, 1)


def test_epss_increases_finding_contribution():
    baseline = one_finding()
    enriched = one_finding(epss={"CVE-2026-4444": 0.5})
    assert enriched[0]["epss_probability"] == 0.5
    assert effective_finding_points(enriched, 1, 1) > effective_finding_points(baseline, 1, 1)


def test_missing_epss_has_neutral_factor():
    finding = one_finding("CVE-2099-9999")
    assert finding[0]["epss_probability"] == 0
    assert effective_finding_points(finding, 1, 1) == 5


def test_zero_alpha_and_neutral_kev_multiplier_reproduce_base_points():
    finding = one_finding(kev={"CVE-2026-4444"}, epss={"CVE-2026-4444": 0.9})
    assert effective_finding_points(finding, 1, 0) == 5
