"""
retire_js.py — Detect known-vulnerable JavaScript libraries bundled in the extension.

Port of the Retire.js detection logic from ExtAnalysis.
Uses the retire.js vulnerability database fetched from GitHub on first run, cached locally.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import requests

_CACHE_DIR = Path.home() / ".extanalyze" / "cache"
_RETIRE_DB_PATH = _CACHE_DIR / "retirejs_db.json"
_RETIRE_DB_URL = (
    "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json"
)
_CACHE_TTL_SECONDS = 86400  # 24 hours

_db_cache: dict | None = None


def _load_db() -> dict:
    global _db_cache
    if _db_cache is not None:
        return _db_cache

    _CACHE_DIR.mkdir(parents=True, exist_ok=True)

    # Use cache if fresh
    if _RETIRE_DB_PATH.exists():
        import time

        age = time.time() - _RETIRE_DB_PATH.stat().st_mtime
        if age < _CACHE_TTL_SECONDS:
            try:
                _db_cache = json.loads(_RETIRE_DB_PATH.read_text())
                return _db_cache
            except (json.JSONDecodeError, OSError):
                pass

    # Fetch fresh copy
    try:
        resp = requests.get(_RETIRE_DB_URL, timeout=10)
        resp.raise_for_status()
        _RETIRE_DB_PATH.write_text(resp.text)
        _db_cache = resp.json()
    except Exception as e:
        print(f"[deep/retirejs] Could not fetch vulnerability DB: {e}", file=sys.stderr)
        _db_cache = {}

    return _db_cache or {}


def _semver_at_or_above(version: str, threshold: str) -> bool:
    """Return True if version >= threshold using simple semver comparison."""

    def parts(v: str) -> list[int]:
        nums = re.split(r"[.\-]", v)
        result = []
        for n in nums:
            try:
                result.append(int(n))
            except ValueError:
                break
        return result or [0]

    return parts(version) >= parts(threshold)


def _is_vulnerable(version: str, vulnerabilities: list[dict]) -> list[dict]:
    """Return the subset of vulnerabilities that affect this version."""
    hits = []
    for vuln in vulnerabilities:
        below = vuln.get("below", "")
        at_or_above = vuln.get("atOrAbove", "")
        try:
            if below and _semver_at_or_above(version, below):
                continue  # version is >= below, so not vulnerable
            if at_or_above and not _semver_at_or_above(version, at_or_above):
                continue  # version is below atOrAbove, so not vulnerable
            hits.append(vuln)
        except Exception:  # noqa: S112 BLE001
            continue
    return hits


def scan_file(rel_path: str, content: str) -> list[dict]:
    """
    Scan a single JS file for known-vulnerable library patterns.
    Returns list of hit dicts: {component, version, detection, vulnerabilities}.
    """
    db = _load_db()
    if not db:
        return []

    sha1 = hashlib.sha1(content.encode("utf-8", errors="replace")).hexdigest()  # noqa: S324
    results = []

    for component, info in db.items():
        extractors = info.get("extractors", {})
        vulnerabilities = info.get("vulnerabilities", [])

        # 1. SHA1 hash match
        for known_hash in extractors.get("hashes", {}).get("sha1", []):
            if sha1 == known_hash.get("hash", ""):
                version = known_hash.get("version", "unknown")
                vuln_hits = _is_vulnerable(version, vulnerabilities)
                if vuln_hits:
                    results.append(
                        {
                            "component": component,
                            "version": version,
                            "detection": "sha1_hash",
                            "file": rel_path,
                            "vulnerabilities": vuln_hits,
                        }
                    )

        # 2. filecontent regex match
        for pattern_str in extractors.get("filecontent", []):
            try:
                m = re.search(pattern_str, content)
                if m:
                    version = m.group(1) if m.lastindex and m.lastindex >= 1 else "unknown"
                    vuln_hits = _is_vulnerable(version, vulnerabilities)
                    if vuln_hits:
                        results.append(
                            {
                                "component": component,
                                "version": version,
                                "detection": "filecontent",
                                "file": rel_path,
                                "vulnerabilities": vuln_hits,
                            }
                        )
                        break  # one hit per component per file
            except re.error:
                continue

        # 3. filecontentreplace (regex with replacement to extract version)
        for entry in extractors.get("filecontentreplace", []):
            try:
                if isinstance(entry, list) and len(entry) == 2:
                    pattern_str, replacement = entry
                    m = re.search(pattern_str, content)
                    if m:
                        version = re.sub(pattern_str, replacement, m.group(0))
                        vuln_hits = _is_vulnerable(version, vulnerabilities)
                        if vuln_hits:
                            results.append(
                                {
                                    "component": component,
                                    "version": version,
                                    "detection": "filecontentreplace",
                                    "file": rel_path,
                                    "vulnerabilities": vuln_hits,
                                }
                            )
                            break
            except (re.error, IndexError, TypeError):
                continue

    return results
