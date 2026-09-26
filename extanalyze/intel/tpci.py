"""
TPCI threat intelligence source.
Dataset: The Privacy Commons Institute chrome-mal-ids
URL: https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids
Format: JSON with meta + extensions[] array
License: CC BY 4.0
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import requests

_RAW_URL = (
    "https://raw.githubusercontent.com/The-Privacy-Commons-Institute/"
    "chrome-mal-ids/master/data/current-list.json"
)
_CACHE_DIR = Path.home() / ".extanalyze" / "cache"
_CACHE_TTL_SECONDS = 86400  # 24 hours


@dataclass
class TPCIResult:
    hit: bool
    ext_id: str
    name: str
    browser: str  # "chrome", "edge", "both"
    threat_types: list[str]
    still_active: bool | str  # bool or "unknown"
    confirm_mal: int  # 0-3 (see SCHEMA.md)
    ownership_transfer: bool
    notes: str
    source_url: str
    article_url: str
    tpci_behavioral: str  # "malicious","suspicious","elevated","below-threshold","unknown"
    crx_sha256: str  # SHA256 of analyzed CRX (may be empty)
    date_added: str


# Module-level cache: {ext_id -> dict}
_INDEX: dict[str, dict] | None = None
_CACHE_FILE: Path | None = None


def _cache_path() -> Path:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    today = date.today().strftime("%Y%m%d")
    return _CACHE_DIR / f"tpci_{today}.json"


def _is_cache_valid(path: Path) -> bool:
    if not path.exists():
        return False
    age = time.time() - path.stat().st_mtime
    return age < _CACHE_TTL_SECONDS


def _download_and_cache(cache_path: Path) -> dict:
    print("[intel/tpci] Downloading TPCI dataset...", file=sys.stderr)
    try:
        resp = requests.get(_RAW_URL, timeout=30)
        resp.raise_for_status()
    except Exception as e:
        print(f"[intel/tpci] Download failed: {e}", file=sys.stderr)
        return {}

    data = resp.json()
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(data, f)

    return data


def _build_index(data: dict) -> dict[str, dict]:
    """Build ext_id -> entry dict from TPCI JSON structure."""
    extensions = data.get("extensions", [])
    return {entry["ext_id"]: entry for entry in extensions if "ext_id" in entry}


def _ensure_loaded() -> None:
    global _INDEX
    if _INDEX is not None:
        return

    cache_path = _cache_path()

    if _is_cache_valid(cache_path):
        with open(cache_path, encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = _download_and_cache(cache_path)

    _INDEX = _build_index(data)
    print(f"[intel/tpci] Loaded {len(_INDEX):,} entries", file=sys.stderr)


def lookup(ext_id: str) -> TPCIResult:
    """Look up an extension ID in the TPCI database."""
    _ensure_loaded()

    entry = (_INDEX or {}).get(ext_id.lower())

    if entry is None:
        return TPCIResult(
            hit=False,
            ext_id=ext_id,
            name="",
            browser="",
            threat_types=[],
            still_active="unknown",
            confirm_mal=0,
            ownership_transfer=False,
            notes="",
            source_url="",
            article_url="",
            tpci_behavioral="unknown",
            crx_sha256="",
            date_added="",
        )

    return TPCIResult(
        hit=True,
        ext_id=ext_id,
        name=entry.get("name", ""),
        browser=entry.get("browser", ""),
        threat_types=entry.get("threat_types", []),
        still_active=entry.get("still_active", "unknown"),
        confirm_mal=_parse_confirm_mal(entry),
        ownership_transfer=entry.get("ownership_transfer", False),
        notes=entry.get("notes", ""),
        source_url=entry.get("source", ""),
        article_url=entry.get("article", ""),
        tpci_behavioral=entry.get("tpci_behavioral", "unknown"),
        crx_sha256=entry.get("tpci_crx_hash", ""),
        date_added=entry.get("date_added", ""),
    )


def _parse_confirm_mal(entry: dict) -> int:
    """
    Parse CONFIRM-MAL value. Field name varies between JSON versions.
    For entries without explicit confirm_mal but with threat_types present,
    default to 1 (researcher confirmed) as that's what presence in the DB implies.
    """
    for key in ("confirm_mal", "CONFIRM-MAL", "confirm-mal"):
        v = entry.get(key)
        if v is not None:
            try:
                return int(v)
            except (ValueError, TypeError):
                return 0

    # No confirm_mal field: if threat_types are populated, treat as confirm=1
    if entry.get("threat_types"):
        return 1
    return 0
