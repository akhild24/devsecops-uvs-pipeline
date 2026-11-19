from services.epss import get_epss_alpha, get_epss_scores


def test_epss_scores_load_from_mocked_local_catalog(tmp_path, monkeypatch):
    catalog = tmp_path / "epss.json"
    catalog.write_text('{"scores":{"CVE-2026-1234":0.4}}', encoding="utf-8")
    monkeypatch.setenv("EPSS_DATA_PATH", str(catalog))
    assert get_epss_scores() == {"CVE-2026-1234": 0.4}


def test_epss_alpha_default_and_configurable(monkeypatch):
    monkeypatch.delenv("EPSS_ALPHA", raising=False)
    assert get_epss_alpha() == 1.0
    monkeypatch.setenv("EPSS_ALPHA", "2")
    assert get_epss_alpha() == 2.0
