"""
Store metadata: fetch name, description, category, developer from CWS or AMO.
Also handles the Google CRX API liveness check.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import requests

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}

_CWS_DETAIL_URL = "https://chromewebstore.google.com/detail/{ext_id}"
_AMO_API_URL = "https://addons.mozilla.org/api/v5/addons/addon/{ext_id}/"
_EDGE_PRODUCT_API_URL = (
    "https://microsoftedge.microsoft.com/addons/getproductdetailsbycrxid/{ext_id}"
)
_CRX_LIVENESS_URL = (
    "https://clients2.google.com/service/update2/crx"
    "?response=updatecheck"
    "&prodversion=120.0.0.0"
    "&x=id%3D{ext_id}%26uc"
)

# Consent bypass cookie - suppresses GDPR consent redirect for EU regions.
# If this stops working, extanalyze falls back to scraping whatever the redirect serves.
_CWS_COOKIES = (
    "SOCS=CAISNQgDEitib3FfaWRlbnRpdHlmcm9udGVuZHVpc2VydmVyXzIwMjMwODI5LjA3X3AwGgJlbiACGgYIgLDF0AY"
)


@dataclass
class StoreMeta:
    name: str
    description: str
    category: str
    developer: str
    version: str
    install_count: str  # "200,000" formatted, or "" if unavailable
    available: bool
    source: str  # "cws", "amo", "unknown"
    verified: bool  # CWS: publisher has verified badge
    established: bool  # CWS: "established publisher" program member


@dataclass
class LivenessResult:
    """Result of Google CRX API liveness probe."""

    google_malware_confirmed: bool  # _malware="true" in response
    store_likely_removed: bool  # noupdate without malware = almost certainly removed
    status_xml: str  # raw status value from XML for logging
    raw_response: str  # first 500 chars of response for debugging


def fetch_edge_meta(ext_id: str, timeout: int = 10) -> StoreMeta:
    """
    Fetch Edge Add-ons metadata via the public product API.

    The Edge product API returns: name, developer, category, activeInstallCount,
    averageRating, version, and the full manifest JSON. It is the authoritative
    source for Edge extensions — never query CWS for Edge IDs.

    Also returns 'isBadgedAsFeatured' (established) and publisher metadata.
    """
    url = _EDGE_PRODUCT_API_URL.format(ext_id=ext_id)
    try:
        resp = requests.get(url, headers=_HEADERS, timeout=timeout)
    except requests.RequestException:
        return _empty_meta("edge")

    if resp.status_code != 200:
        return StoreMeta(
            name="",
            description="",
            category="",
            developer="",
            version="",
            install_count="",
            available=False,
            source="edge",
            verified=False,
            established=False,
        )

    data = resp.json()
    name = data.get("name", "")
    if not name:
        return _empty_meta("edge")

    description = data.get("shortDescription", "") or data.get("description", "")
    category = data.get("category", "")
    developer = data.get("developer", "")
    version = data.get("version", "")
    installs = data.get("activeInstallCount", "")
    install_count = f"{installs:,}" if isinstance(installs, int) else str(installs)

    # Edge uses 'isBadgedAsFeatured' for curated/featured extensions.
    # Publisher verification is implied by the availability field including 'License'.
    established = bool(data.get("isBadgedAsFeatured", False))
    # Verified: Edge doesn't have an explicit flag, but rated publishers with
    # 'License' in availability list have been reviewed by Microsoft.
    availability = data.get("availability", [])
    verified = "License" in availability

    return StoreMeta(
        name=name,
        description=description,
        category=category,
        developer=developer,
        version=version,
        install_count=install_count,
        available=True,
        source="edge",
        verified=verified,
        established=established,
    )


def fetch_cws_meta(ext_id: str, timeout: int = 10) -> StoreMeta:
    """
    Scrape Chrome Web Store page for extension metadata.
    Always queries live store - used regardless of catalog hit, to get
    developer name, verified/established status, and confirm availability.
    """
    url = _CWS_DETAIL_URL.format(ext_id=ext_id)
    session = requests.Session()
    # Set cookie on both the CWS domain and the consent redirect domain
    session.cookies.set("SOCS", _CWS_COOKIES.split("=", 1)[1], domain=".google.com")

    try:
        resp = session.get(
            url,
            headers=_HEADERS,
            timeout=timeout,
            allow_redirects=True,
        )
    except requests.RequestException:
        return _empty_meta("cws")

    available = resp.status_code == 200

    # Detect consent redirect — page title will be "Before you continue" or
    # final URL will be consent.google.com
    html = resp.text
    is_consent_page = (
        "consent.google.com" in resp.url
        or "Before you continue" in html[:500]
        or "<title>Before you continue</title>" in html
    )

    if is_consent_page:
        # Extension exists (we got a redirect, not 404) but we can't scrape details
        return StoreMeta(
            name="",
            description="",
            category="",
            developer="",
            version="",
            install_count="",
            available=True,
            source="cws",
            verified=False,
            established=False,
        )

    if not available:
        return StoreMeta(
            name="",
            description="",
            category="",
            developer="",
            version="",
            install_count="",
            available=False,
            source="cws",
            verified=False,
            established=False,
        )

    # Extension name from <title> tag (most reliable, server-rendered)
    name = ""
    title_m = re.search(r"<title>([^<]+)</title>", html)
    if title_m:
        name = title_m.group(1).replace(" - Chrome Web Store", "").strip()

    # Developer name from the publisher address block
    dev_m = re.search(r'class="mdSapd">([^<\n]+)', html)
    developer = dev_m.group(1).strip() if dev_m else ""

    # Description from og:description
    description = _extract_og(html, "og:description")

    # User/install count: embedded in JSON array as integer after category array
    # Pattern: ["category",null,N],1,1,USER_COUNT,
    user_m = re.search(r'\["[^"]+",null,\d+\],(?:1|null),(?:1|null),(\d{3,}),', html)
    install_count = f"{int(user_m.group(1)):,}" if user_m else ""

    # Established publisher: position after user count in the same JSON array
    est_m = re.search(r'\["[^"]+",null,\d+\],(?:1|null),(?:1|null),\d+,(1|null),', html)
    established = est_m is not None and est_m.group(1) == "1"

    # Verified publisher: position 8 in the extension JSON array
    ver_m = re.search(
        rf'"{re.escape(ext_id)}","[^"]*","[^"]*",[\d.]+,\d+,(?:"[^"]*"|null),"[^"]*",(?:"[^"]*"|null),(1|null)',
        html,
    )
    verified = ver_m is not None and ver_m.group(1) == "1"

    # Category from JSON
    cat_m = re.search(r'"applicationCategory":\s*"([^"]+)"', html)
    category = cat_m.group(1) if cat_m else ""

    return StoreMeta(
        name=name,
        description=description,
        category=category,
        developer=developer,
        version="",
        install_count=install_count,
        available=True,
        source="cws",
        verified=verified,
        established=established,
    )


def fetch_amo_meta(ext_id: str, timeout: int = 10) -> StoreMeta:
    """Fetch Firefox AMO metadata via public API."""
    url = _AMO_API_URL.format(ext_id=ext_id)
    try:
        resp = requests.get(url, headers=_HEADERS, timeout=timeout)
    except requests.RequestException:
        return _empty_meta("amo")

    if resp.status_code != 200:
        return StoreMeta(
            name="",
            description="",
            category="",
            developer="",
            version="",
            install_count="",
            available=False,
            source="amo",
            verified=False,
            established=False,
        )

    data = resp.json()

    name_raw = data.get("name", {})
    name = name_raw.get("en-US", "") if isinstance(name_raw, dict) else str(name_raw)

    summary_raw = data.get("summary", {})
    description = (
        summary_raw.get("en-US", "") if isinstance(summary_raw, dict) else str(summary_raw)
    )

    # AMO API returns categories as either:
    # - flat list: ['privacy-security']  (new format)
    # - dict by app: {'firefox': ['privacy-security']}  (older format)
    categories_raw = data.get("categories", [])
    if isinstance(categories_raw, list):
        cat_list = categories_raw
    elif isinstance(categories_raw, dict):
        cat_list = categories_raw.get("firefox", categories_raw.get("android", []))
    else:
        cat_list = []
    category = cat_list[0] if cat_list else ""

    authors = data.get("authors", [])
    developer = authors[0].get("name", "") if authors else ""

    version = data.get("current_version", {}).get("version", "")
    downloads = data.get("average_daily_users", "")

    # AMO 'promoted' list with category='recommended' = Mozilla-recommended (equivalent to verified)
    promoted = data.get("promoted") or []
    promoted_cats = [p.get("category", "") for p in promoted] if isinstance(promoted, list) else []
    verified = "recommended" in promoted_cats
    # 'line' = curated/featured by AMO staff — closest to 'established'
    established = "line" in promoted_cats or "featured" in promoted_cats

    return StoreMeta(
        name=name,
        description=description,
        category=category,
        developer=developer,
        version=version,
        install_count=str(downloads),
        available=True,
        source="amo",
        verified=verified,
        established=established,
    )


def check_crx_liveness(ext_id: str, timeout: int = 10) -> LivenessResult:
    """
    Probe the Google CRX update API for malware flag and liveness.

    Response scenarios:
    - _malware="true"  -> Google confirmed malware
    - status="ok"      -> extension is live and clean by Google's view
    - status="noupdate" (no _malware) -> 99.6% probability the extension was removed
    - Network error    -> return unknown state
    """
    url = _CRX_LIVENESS_URL.format(ext_id=ext_id)
    try:
        resp = requests.get(url, headers=_HEADERS, timeout=timeout)
        xml = resp.text[:2000]  # don't store huge responses
    except requests.RequestException as e:
        return LivenessResult(
            google_malware_confirmed=False,
            store_likely_removed=False,
            status_xml="error",
            raw_response=str(e)[:500],
        )

    google_malware = '_malware="true"' in xml or "_malware='true'" in xml

    # Extract status attribute
    status_match = re.search(r'status="([^"]+)"', xml)
    status = status_match.group(1) if status_match else "unknown"

    # noupdate without malware flag = removed (per TPCI research: 99.6% accuracy)
    likely_removed = (status == "noupdate") and not google_malware

    return LivenessResult(
        google_malware_confirmed=google_malware,
        store_likely_removed=likely_removed,
        status_xml=status,
        raw_response=xml[:500],
    )


# ── Helpers ──────────────────────────────────────────────────────────────────


def _extract_og(html: str, prop: str) -> str:
    m = re.search(rf'<meta[^>]+property="{re.escape(prop)}"[^>]+content="([^"]*)"', html)
    if not m:
        m = re.search(rf'<meta[^>]+content="([^"]*)"[^>]+property="{re.escape(prop)}"', html)
    return m.group(1) if m else ""


def _extract_meta(html: str, name: str) -> str:
    m = re.search(rf'<meta[^>]+name="{re.escape(name)}"[^>]+content="([^"]*)"', html)
    return m.group(1) if m else ""


def _empty_meta(source: str) -> StoreMeta:
    return StoreMeta(
        name="",
        description="",
        category="",
        developer="",
        version="",
        install_count="",
        available=False,
        source=source,
        verified=False,
        established=False,
    )
