import logging

from services import kev


def test_kev_fetcher_uses_cisa_feed_url(monkeypatch):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self):
            return b'{"vulnerabilities":[{"cveID":"CVE-2026-5678"}]}'

    calls = []

    def fake_urlopen(request, timeout):
        calls.append((request.full_url, timeout))
        return FakeResponse()

    monkeypatch.setattr(kev.urllib.request, "urlopen", fake_urlopen)

    assert kev.fetch_kev_data() == {
        "vulnerabilities": [{"cveID": "CVE-2026-5678"}]
    }
    assert calls == [(kev.KEV_FEED_URL, 15)]


def test_kev_feed_is_cached_for_24_hours(tmp_path, monkeypatch):
    calls = []

    def fake_fetch():
        calls.append(True)
        return {"vulnerabilities": [{"cveID": "CVE-2026-1234"}]}

    monkeypatch.setattr(kev, "fetch_kev_data", fake_fetch)
    cache_path = tmp_path / "kev.json"

    assert kev.get_known_exploited_cves(cache_path, now=100) == {"CVE-2026-1234"}
    assert kev.get_known_exploited_cves(
        cache_path, now=100 + kev.KEV_CACHE_TTL_SECONDS - 1
    ) == {"CVE-2026-1234"}
    assert len(calls) == 1


def test_kev_refresh_failure_uses_stale_cache(tmp_path, monkeypatch, caplog):
    cache_path = tmp_path / "kev.json"
    monkeypatch.setattr(
        kev,
        "fetch_kev_data",
        lambda: {"vulnerabilities": [{"cveID": "CVE-2026-1234"}]},
    )
    kev.get_known_exploited_cves(cache_path, now=100)
    monkeypatch.setattr(kev, "fetch_kev_data", lambda: (_ for _ in ()).throw(OSError("offline")))

    with caplog.at_level(logging.WARNING):
        cves = kev.get_known_exploited_cves(
            cache_path, now=100 + kev.KEV_CACHE_TTL_SECONDS + 1
        )

    assert cves == {"CVE-2026-1234"}
    assert "Could not refresh CISA KEV feed" in caplog.text


def test_kev_failure_without_cache_returns_empty_set_with_warning(
    tmp_path, monkeypatch, caplog
):
    monkeypatch.setattr(kev, "fetch_kev_data", lambda: (_ for _ in ()).throw(OSError("offline")))

    with caplog.at_level(logging.WARNING):
        cves = kev.get_known_exploited_cves(
            tmp_path / "missing.json",
            now=100,
            fallback_path=tmp_path / "missing-fallback.json",
        )

    assert cves == set()
    assert "No cached or fallback CISA KEV data is available" in caplog.text


def test_kev_offline_fallback_is_used_and_cached(tmp_path, monkeypatch):
    cache_path = tmp_path / "cache.json"
    fallback_path = tmp_path / "fallback.json"
    fallback_path.write_text(
        '{"cves":["CVE-2021-44228"]}', encoding="utf-8"
    )
    monkeypatch.setattr(
        kev, "fetch_kev_data", lambda: (_ for _ in ()).throw(OSError("offline"))
    )

    cves = kev.get_known_exploited_cves(
        cache_path, now=100, fallback_path=fallback_path
    )

    assert cves == {"CVE-2021-44228"}
    assert kev._read_cache(cache_path) == ({"CVE-2021-44228"}, 100.0)


def test_kev_multiplier_defaults_on(monkeypatch):
    from services.epss import get_kev_multiplier
    monkeypatch.delenv("KEV_MULTIPLIER", raising=False)
    assert get_kev_multiplier() == 1.25
