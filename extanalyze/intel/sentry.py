"""
malicious_extension_sentry threat intelligence source.
Dataset: github.com/toborrm9/malicious_extension_sentry
Format: CSV with extension_id, name, reason, source, date, blocklist, store, version, sha256
"""

from __future__ import annotations

import csv
import io
import sys
import time
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import requests

from ..core.http import get_limited

_RAW_URL = (
    "https://raw.githubusercontent.com/toborrm9/malicious_extension_sentry/"
    "main/malicious_extensions_detailed.csv"
)
_CACHE_DIR = Path.home() / ".extanalyze" / "cache"
_CACHE_TTL_SECONDS = 86400  # 24 hours
_MAX_DATASET_BYTES = 25 * 1024 * 1024  # 25 MB cap on the downloaded dataset

_INDEX: dict[str, dict] | None = None


@dataclass
class SentryResult:
    hit: bool
    ext_id: str
    name: str
    reason: str  # "Policy Violation", "Malware", etc.
    source: str
    date_added: str
    blocklist: bool  # True = actively blocklisted (higher severity)
    store: str  # "Google Chrome", "Firefox", etc.
    version: str
    sha256: str  # SHA256 of analyzed build
    sha256_match: bool | None  # None = not checked; True/False = compared to downloaded file


def _cache_path() -> Path:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    today = date.today().strftime("%Y%m%d")
    return _CACHE_DIR / f"sentry_{today}.csv"


def _is_cache_valid(path: Path) -> bool:
    if not path.exists():
        return False
    return (time.time() - path.stat().st_mtime) < _CACHE_TTL_SECONDS


def _download_and_cache(cache_path: Path) -> str:
    print("[intel/sentry] Downloading malicious_extension_sentry dataset...", file=sys.stderr)
    try:
        resp = get_limited(_RAW_URL, max_bytes=_MAX_DATASET_BYTES, timeout=30)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"[intel/sentry] Download failed: {e}", file=sys.stderr)
        return ""

    text = resp.text
    with open(cache_path, "w", encoding="utf-8") as f:
        f.write(text)
    return text


def _build_index(csv_text: str) -> dict[str, dict]:
    """Build extension_id -> row dict from CSV content."""
    index: dict[str, dict] = {}
    # Strip BOM if present (file may be UTF-8 with BOM)
    csv_text = csv_text.lstrip("\ufeff")
    reader = csv.DictReader(io.StringIO(csv_text))
    for row in reader:
        ext_id = row.get("extension_id", "").strip().lower()
        if ext_id:
            # Keep latest entry if duplicated
            index[ext_id] = row
    return index


def _ensure_loaded() -> None:
    global _INDEX
    if _INDEX is not None:
        return

    cache_path = _cache_path()

    if _is_cache_valid(cache_path):
        with open(cache_path, encoding="utf-8") as f:
            csv_text = f.read()
    else:
        csv_text = _download_and_cache(cache_path)

    _INDEX = _build_index(csv_text) if csv_text else {}
    print(f"[intel/sentry] Loaded {len(_INDEX):,} entries", file=sys.stderr)


def lookup(ext_id: str, downloaded_sha256: str | None = None) -> SentryResult:
    """
    Look up extension ID in sentry dataset.
    If downloaded_sha256 is provided, cross-check against stored SHA256.
    """
    _ensure_loaded()

    entry = (_INDEX or {}).get(ext_id.lower())

    if entry is None:
        return SentryResult(
            hit=False,
            ext_id=ext_id,
            name="",
            reason="",
            source="",
            date_added="",
            blocklist=False,
            store="",
            version="",
            sha256="",
            sha256_match=None,
        )

    stored_sha256 = entry.get("sha256", "").strip()
    sha256_match: bool | None = None
    if downloaded_sha256 and stored_sha256:
        sha256_match = downloaded_sha256.lower() == stored_sha256.lower()

    blocklist_raw = entry.get("blocklist", "false").strip().lower()
    blocklist = blocklist_raw in ("true", "1", "yes")

    return SentryResult(
        hit=True,
        ext_id=ext_id,
        name=entry.get("name", ""),
        reason=entry.get("reason", ""),
        source=entry.get("source", ""),
        date_added=entry.get("insert_date_fmt", ""),
        blocklist=blocklist,
        store=entry.get("store", ""),
        version=entry.get("version", ""),
        sha256=stored_sha256,
        sha256_match=sha256_match,
    )
