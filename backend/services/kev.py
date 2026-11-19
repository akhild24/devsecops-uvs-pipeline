from __future__ import annotations

import json
import logging
import os
import time
import urllib.request
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
KEV_CACHE_TTL_SECONDS = 24 * 60 * 60
DEFAULT_CACHE_PATH = (
    Path(__file__).resolve().parents[1]
    / ".cache"
    / "known_exploited_vulnerabilities.json"
)
DEFAULT_FALLBACK_PATH = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "known_exploited_vulnerabilities.json"
)


def fetch_kev_data() -> dict[str, Any]:
    """Fetch the CISA feed. Kept separate so network access is easy to mock."""
    request = urllib.request.Request(
        KEV_FEED_URL, headers={"User-Agent": "DevSecOps-UVS/1.0"}
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


def _feed_cves(feed: dict[str, Any]) -> set[str]:
    vulnerabilities = feed["vulnerabilities"]
    if not isinstance(vulnerabilities, list):
        raise ValueError("CISA KEV feed has an invalid vulnerabilities field")
    return {
        str(item["cveID"]).upper()
        for item in vulnerabilities
        if isinstance(item, dict) and item.get("cveID")
    }


def _read_cache(path: Path) -> tuple[set[str], float] | None:
    try:
        cache = json.loads(path.read_text(encoding="utf-8"))
        cves = cache["cves"]
        fetched_at = float(cache["fetched_at"])
        if not isinstance(cves, list):
            raise ValueError("cached CVE list is invalid")
        return {str(cve).upper() for cve in cves}, fetched_at
    except FileNotFoundError:
        return None
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        logger.warning("Could not read CISA KEV cache at %s: %s", path, exc)
        return None


def _read_fallback(path: Path) -> set[str]:
    try:
        catalog = json.loads(path.read_text(encoding="utf-8"))
        cves = catalog["cves"]
        if not isinstance(cves, list):
            raise ValueError("fallback CVE list is invalid")
        return {str(cve).upper() for cve in cves}
    except FileNotFoundError:
        logger.warning("Offline CISA KEV fallback is missing at %s", path)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        logger.warning("Could not read offline CISA KEV fallback at %s: %s", path, exc)
    return set()


def get_known_exploited_cves(
    cache_path: Path | str | None = None,
    now: float | None = None,
    fallback_path: Path | str | None = None,
) -> set[str]:
    """Return KEV CVE IDs, refreshing the on-disk cache every 24 hours."""
    path = Path(cache_path) if cache_path is not None else DEFAULT_CACHE_PATH
    current_time = time.time() if now is None else now
    cached = _read_cache(path)
    if cached and current_time - cached[1] < KEV_CACHE_TTL_SECONDS:
        return cached[0]

    try:
        cves = _feed_cves(fetch_kev_data())
    except (OSError, TimeoutError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        logger.warning("Could not refresh CISA KEV feed: %s", exc)
        if cached is not None:
            return cached[0]
        fallback = _read_fallback(
            Path(fallback_path) if fallback_path is not None else DEFAULT_FALLBACK_PATH
        )
        if fallback:
            logger.warning("Using bundled offline CISA KEV fallback catalog")
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    json.dumps(
                        {"fetched_at": current_time, "cves": sorted(fallback)}
                    ),
                    encoding="utf-8",
                )
            except OSError as write_error:
                logger.warning(
                    "Could not cache offline CISA KEV fallback at %s: %s",
                    path,
                    write_error,
                )
            return fallback
        logger.warning("No cached or fallback CISA KEV data is available; treating findings as not listed")
        return set()

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = path.with_suffix(path.suffix + ".tmp")
        temporary_path.write_text(
            json.dumps({"fetched_at": current_time, "cves": sorted(cves)}),
            encoding="utf-8",
        )
        temporary_path.replace(path)
    except OSError as exc:
        logger.warning("Could not write CISA KEV cache at %s: %s", path, exc)

    return cves


