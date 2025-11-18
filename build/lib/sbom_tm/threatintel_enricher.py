from __future__ import annotations

import logging
import json
from datetime import datetime, timedelta, UTC
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import requests

LOGGER = logging.getLogger(__name__)

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

_kev_cache: Optional[set[str]] = None
_kev_cache_expiry: Optional[datetime] = None
_CACHE_FILENAME = "cisa_kev.json"
_CACHE_TTL = timedelta(hours=6)


def load_cisa_kev(force_refresh: bool = False) -> set[str]:
    global _kev_cache, _kev_cache_expiry

    if (
        not force_refresh
        and _kev_cache is not None
        and _kev_cache_expiry is not None
        and datetime.now(UTC) < _kev_cache_expiry
    ):
        return _kev_cache

    cache_file = _cache_file_path()
    if not force_refresh and cache_file.exists():
        try:
            cached_data = json.loads(cache_file.read_text(encoding="utf-8"))
            expires_at = cached_data.get("expires_at")
            if expires_at:
                expiry = datetime.fromisoformat(expires_at).replace(tzinfo=UTC)
                if datetime.now(UTC) < expiry:
                    kev = {str(item).upper() for item in cached_data.get("cves", [])}
                    _kev_cache = kev
                    _kev_cache_expiry = expiry
                    return kev
        except (json.JSONDecodeError, OSError, ValueError) as exc:
            LOGGER.warning("[ThreatIntel] Failed to load KEV cache: %s", exc)

    try:
        response = requests.get(CISA_KEV_URL, timeout=10)
        response.raise_for_status()
        data = response.json()
        kev = {
            str(item.get("cveID") or item.get("cveId") or "").upper()
            for item in data.get("vulnerabilities", [])
            if item.get("cveID") or item.get("cveId")
        }
        _kev_cache = kev
        _kev_cache_expiry = datetime.now(UTC) + _CACHE_TTL
        _write_cache_file(cache_file, kev, _kev_cache_expiry)
        return kev
    except Exception as exc:  # pragma: no cover - best-effort network call
        LOGGER.warning("[ThreatIntel] Failed to load CISA KEV feed: %s", exc)
        _kev_cache = set()
        _kev_cache_expiry = datetime.now(UTC) + timedelta(minutes=15)
        _write_cache_file(cache_file, _kev_cache, _kev_cache_expiry)
        return _kev_cache


def _resolve_cve_identifier(payload: Dict[str, Any]) -> str:
    """Extract the best CVE identifier from a Trivy vulnerability payload."""

    candidates: Iterable[Optional[str]] = (
        payload.get("VulnerabilityID"),
        payload.get("vulnerability_id"),
        payload.get("CVE"),
        payload.get("cve"),
        payload.get("id"),
    )
    for candidate in candidates:
        if candidate:
            return str(candidate).upper()
    return ""


def enrich_with_threatintel(components: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Add threat intelligence metadata (currently CISA KEV) to vulnerabilities."""

    kev_cves = load_cisa_kev()

    for component in components:
        vulnerabilities = component.get("vulnerabilities") or []
        for vuln in vulnerabilities:
            cve_id = _resolve_cve_identifier(vuln)
            kev_listed = bool(cve_id and cve_id in kev_cves)
            existing = vuln.get("threatintel") or {}
            existing.update(
                {
                    "kev_listed": kev_listed,
                    "chatter_score": 0.9 if kev_listed else 0.1,
                    "sources": ["CISA KEV"] if kev_listed else [],
                }
            )
            vuln["threatintel"] = existing
    return components


def _cache_file_path() -> Path:
    from .config import get_settings

    settings = get_settings()
    settings.cache_dir.mkdir(parents=True, exist_ok=True)
    return settings.cache_dir / _CACHE_FILENAME


def _write_cache_file(path: Path, kev: Iterable[str], expiry: datetime) -> None:
    try:
        payload = {
            "cves": sorted({str(item).upper() for item in kev}),
            "expires_at": expiry.isoformat(),
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
    except OSError as exc:
        LOGGER.debug("[ThreatIntel] Unable to persist KEV cache: %s", exc)
