"""
Store metadata: fetch name, description, category, developer from CWS or AMO.
Also handles the Google CRX API liveness check.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

import requests
from lxml import etree

from .http import get_limited

_ID_RE = re.compile(r"^[a-p]{32}$")

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


def probe_stores(ext_id: str, timeout: int = 8) -> list[str]:
    """
    Probe Chrome and Edge stores to determine where a 32-char CRX ID is listed.

    Uses the Google CRX update API (fast, definitive for Chrome) and the Edge
    product API (equally fast) in parallel via a simple sequential check - both
    are sub-second responses.

    Returns a list of browser strings: ["chrome"], ["edge"], ["chrome", "edge"],
    or [] if found nowhere (unknown/removed extension).

    Decision matrix:
      CRX status ok/noupdate + Edge 200  → ["chrome", "edge"]
      CRX status ok/noupdate + Edge 404  → ["chrome"]
      CRX error-unknownApplication + Edge 200 → ["edge"]
      CRX error-unknownApplication + Edge 404 → []
    """
    browsers: list[str] = []

    # Check Chrome (Google CRX API - fastest, most reliable)
    crx_url = _CRX_LIVENESS_URL.format(ext_id=ext_id)
    try:
        resp = get_limited(crx_url, headers=_HEADERS, timeout=timeout)
        xml = resp.text
        status_m = re.search(r'status="([^"]+)"', xml)
        crx_status = status_m.group(1) if status_m else "unknown"
        on_chrome = crx_status in ("ok", "noupdate")
    except requests.RequestException:
        on_chrome = False

    if on_chrome:
        browsers.append("chrome")

    # Check Edge (product API)
    edge_url = _EDGE_PRODUCT_API_URL.format(ext_id=ext_id)
    try:
        resp = get_limited(edge_url, headers=_HEADERS, timeout=timeout)
        on_edge = resp.status_code == 200 and bool(resp.json().get("name"))
    except Exception:
        on_edge = False

    if on_edge:
        browsers.append("edge")

    return browsers


def fetch_edge_meta(ext_id: str, timeout: int = 10) -> StoreMeta:
    """
    Fetch Edge Add-ons metadata via the public product API.

    The Edge product API returns: name, developer, category, activeInstallCount,
    averageRating, version, and the full manifest JSON. It is the authoritative
    source for Edge extensions - never query CWS for Edge IDs.

    Also returns 'isBadgedAsFeatured' (established) and publisher metadata.
    """
    url = _EDGE_PRODUCT_API_URL.format(ext_id=ext_id)
    try:
        resp = get_limited(url, headers=_HEADERS, timeout=timeout)
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
    Fetch Chrome Web Store metadata via the internal batchexecute JSON API.

    Uses the xY2Ddd RPC endpoint that the CWS frontend itself calls, returning
    a structured JSON array - no HTML scraping, no regex fragility.

    Response schema (data[0] is the main extension record):
      data[0][0]  str   extension ID
      data[0][2]  str   name
      data[0][3]  float rating
      data[0][4]  int   review count
      data[0][6]  str   short description
      data[0][7]  str   website URL
      data[0][8]  bool  verified publisher
      data[0][9]  bool  established / featured publisher
      data[0][11] list  [category_slug, None, category_id]
      data[0][14] int   install count (raw integer)
      data[0][18] str   manifest JSON (embedded)
      data[10]    list  [email, address, ..., dev_short_name, company_name, ...]

    Returns _empty_meta("cws") when the extension is not on the Chrome Web Store
    (inner JSON is null), which correctly handles Edge-only IDs.
    """
    session = requests.Session()
    session.cookies.set("SOCS", _CWS_COOKIES.split("=", 1)[1], domain=".google.com")

    f_req = json.dumps([[["xY2Ddd", f'["{ext_id}"]', None, "generic"]]])
    api_url = (
        "https://chromewebstore.google.com"
        "/_/ChromeWebStoreConsumerFeUi/data/batchexecute"
        f"?rpcids=xY2Ddd&source-path=/detail/{ext_id}&hl=en"
    )
    post_headers = {
        **_HEADERS,
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        "X-Same-Domain": "1",
        "Origin": "https://chromewebstore.google.com",
        "Referer": f"https://chromewebstore.google.com/detail/{ext_id}",
    }

    try:
        resp = session.post(api_url, data={"f.req": f_req}, headers=post_headers, timeout=timeout)
    except requests.RequestException:
        return _empty_meta("cws")

    if resp.status_code != 200:
        return _empty_meta("cws")

    # Strip )]}'\n\n XSSI prefix
    text = resp.text
    if text.startswith(")]}'"):
        text = text[4:].lstrip()

    try:
        outer = json.loads(text)
        inner_str = outer[0][2]  # None when extension not on CWS
    except (json.JSONDecodeError, IndexError, TypeError):
        return _empty_meta("cws")

    if not inner_str:
        # Extension not found on Chrome Web Store (Edge-only, removed, or unknown)
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

    try:
        data = json.loads(inner_str)
    except (json.JSONDecodeError, TypeError):
        return _empty_meta("cws")

    # Parse the main extension record (data[0])
    rec = data[0] if data and isinstance(data[0], list) else []

    name = rec[2] if len(rec) > 2 and isinstance(rec[2], str) else ""
    if not name:
        return _empty_meta("cws")

    description = rec[6] if len(rec) > 6 and isinstance(rec[6], str) else ""
    if not description:
        description = data[6] if len(data) > 6 and isinstance(data[6], str) else ""

    # Install count is a raw integer at rec[14]
    install_raw = rec[14] if len(rec) > 14 and isinstance(rec[14], int) else 0
    install_count = f"{install_raw:,}" if install_raw else ""

    # Verified (rec[8]) and established (rec[9]) are booleans in the record
    verified = bool(rec[8]) if len(rec) > 8 else False
    established = bool(rec[9]) if len(rec) > 9 else False

    # Category slug at rec[11] = [slug, None, id]
    cat_info = rec[11] if len(rec) > 11 and isinstance(rec[11], list) else []
    category = cat_info[0] if cat_info else ""

    # Developer: data[10] = [email, address, ..., dev_short, company, ...]
    dev_info = data[10] if len(data) > 10 and isinstance(data[10], list) else []
    # Prefer company name (index 6) if present, fall back to short name (index 5)
    developer = ""
    if len(dev_info) > 6 and isinstance(dev_info[6], str) and dev_info[6]:
        developer = dev_info[6]
    elif len(dev_info) > 5 and isinstance(dev_info[5], str) and dev_info[5]:
        developer = dev_info[5]

    # Version is in the embedded manifest JSON at rec[18], or fall through
    version = data[13] if len(data) > 13 and isinstance(data[13], str) else ""

    return StoreMeta(
        name=name,
        description=description,
        category=category,
        developer=developer,
        version=version,
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
        resp = get_limited(url, headers=_HEADERS, timeout=timeout)
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
    # 'line' = curated/featured by AMO staff - closest to 'established'
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
        resp = get_limited(url, headers=_HEADERS, timeout=timeout)
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


@dataclass
class UpdateInfo:
    """One extension's answer from the batched Google update API."""

    ext_id: str
    status: str  # ok | noupdate | error-unknownApplication | error | ...
    version: str = ""
    size_bytes: int = 0
    sha256: str = ""
    codebase: str = ""
    malware: bool = False  # _malware flag


_UPDATE_BATCH_URL = (
    "https://clients2.google.com/service/update2/crx?response=updatecheck&prodversion=130.0"
    "&acceptformat=crx3"
)
MAX_UPDATE_BATCH = 50


def check_updates(ext_ids: list[str], timeout: int = 20) -> dict[str, UpdateInfo]:
    """Ask the update API about many extensions at once, without downloading anything.

    With v=0.0.0 every live extension answers with its current version, size and SHA-256, so
    this is the cheap way to detect changes. Unknown or removed IDs come back with an error or
    `noupdate` status. Batches are capped at MAX_UPDATE_BATCH IDs per request.
    """
    out: dict[str, UpdateInfo] = {}
    for i in range(0, len(ext_ids), MAX_UPDATE_BATCH):
        batch = ext_ids[i : i + MAX_UPDATE_BATCH]
        query = "".join(f"&x=id%3D{e}%26v%3D0.0.0%26uc" for e in batch if _ID_RE.match(e))
        if not query:
            continue
        try:
            resp = get_limited(_UPDATE_BATCH_URL + query, headers=_HEADERS, timeout=timeout)
            out.update(parse_update_response(resp.content))
        except requests.RequestException:
            for e in batch:
                out.setdefault(e, UpdateInfo(e, "error"))
    return out


def parse_update_response(xml_bytes: bytes) -> dict[str, UpdateInfo]:
    """Parse a (possibly multi-app) update API response. Hardened against hostile XML."""
    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
    try:
        root = etree.fromstring(xml_bytes, parser)  # noqa: S320 - entity resolution disabled
    except etree.XMLSyntaxError:
        return {}
    out: dict[str, UpdateInfo] = {}
    for app in root.iter("{*}app"):
        ext_id = app.get("appid", "")
        if not _ID_RE.match(ext_id):
            continue
        check = next(app.iter("{*}updatecheck"), None)
        status = (check.get("status") if check is not None else None) or app.get("status", "")
        info = UpdateInfo(ext_id=ext_id, status=status)
        if check is not None:
            info.version = (check.get("version") or "")[:64]
            info.sha256 = (check.get("hash_sha256") or "")[:64]
            info.codebase = (check.get("codebase") or "")[:500]
            info.malware = (check.get("_malware") or "").lower() == "true"
            size = check.get("size") or ""
            info.size_bytes = int(size) if size.isdigit() else 0
        out[ext_id] = info
    return out


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
