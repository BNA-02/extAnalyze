"""
vt_lookup.py — Optional VirusTotal domain reputation lookup.

Only runs when VIRUSTOTAL_API_KEY environment variable is set.
Uses VT API v3 (free tier: 4 lookups/min, 500/day).
"""

from __future__ import annotations

import os
import sys
import time

import requests

from extanalyze.core.http import get_limited

_VT_API_URL = "https://www.virustotal.com/api/v3/domains/{domain}"
_RATE_LIMIT_DELAY = 15  # seconds between requests on free tier (4/min)


def lookup_domains(domains: list[str]) -> list[dict]:
    """
    Check each domain against VirusTotal.
    Returns list of {domain, malicious, suspicious, stats, error}.
    Only runs if VIRUSTOTAL_API_KEY is set.
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return []

    results = []
    headers = {"x-apikey": api_key, "Accept": "application/json"}

    for i, domain in enumerate(domains[:20]):  # cap at 20 to avoid burning quota
        if i > 0:
            time.sleep(_RATE_LIMIT_DELAY)

        try:
            resp = get_limited(
                _VT_API_URL.format(domain=domain),
                headers=headers,
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                results.append(
                    {
                        "domain": domain,
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "stats": stats,
                        "error": None,
                    }
                )
            elif resp.status_code == 404:
                results.append(
                    {
                        "domain": domain,
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 0,
                        "stats": {},
                        "error": "not_found",
                    }
                )
            elif resp.status_code == 401:
                print("[deep/vt] Invalid API key", file=sys.stderr)
                break
            elif resp.status_code == 429:
                print("[deep/vt] Rate limited — stopping VT lookups", file=sys.stderr)
                break
            else:
                results.append(
                    {
                        "domain": domain,
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 0,
                        "stats": {},
                        "error": f"http_{resp.status_code}",
                    }
                )
        except requests.RequestException as e:
            results.append(
                {
                    "domain": domain,
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "stats": {},
                    "error": str(e),
                }
            )

    return results
