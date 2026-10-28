"""
Manifest parser: load manifest.json into a typed dataclass.
Handles MV2/MV3 differences in field structure.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

# URL pattern: anything that looks like a host permission
_URL_PATTERN_RE = re.compile(r"^(https?://|wss?://|\*://|<all_urls>|file://|\*)")
_GOOGLE_UPDATE_DOMAINS = {
    "clients2.google.com",
    "update.googleapis.com",
    "gvt1.com",
    "gvt2.com",
    # Edge Add-ons official update channel - not attacker-controlled
    "edge.microsoft.com",
    "extensionwebstorebase",
}


@dataclass
class ExtensionManifest:
    # Core identity
    manifest_version: int  # 2 or 3
    name: str  # May be empty or a __MSG_ placeholder
    version: str
    description: str

    # Permissions (normalized: named perms only, URL patterns split out)
    permissions: list[str]  # declared named permissions
    optional_permissions: list[str]  # optional named permissions
    host_permissions: list[str]  # URL patterns (MV3: own field; MV2: extracted from permissions)
    optional_host_permissions: list[str]

    # Content scripts
    content_scripts: list[dict]
    content_scripts_all_urls: bool  # True if any content script matches <all_urls> or *://*/*

    # Background
    background_scripts: list[str]  # MV2: background.scripts[]
    background_page: str  # MV2: background.page
    background_service_worker: str  # MV3: background.service_worker
    background_persistent: bool | None  # MV2 only: background.persistent

    # Security
    content_security_policy: str  # raw CSP string
    has_unsafe_eval: bool  # True if CSP contains 'unsafe-eval'
    update_url: str  # non-empty = extension has update channel
    update_url_non_google: bool  # True if update_url points to non-Google host
    web_accessible_resources: list  # WAR entries

    # Connectivity
    externally_connectable: dict  # sites that can message this extension
    oauth2: dict  # present = accesses OAuth tokens

    # Raw
    raw: dict  # original manifest dict


def parse_manifest(path: Path) -> ExtensionManifest:
    """Parse manifest.json from an extracted extension directory."""
    with open(path, encoding="utf-8-sig") as f:
        raw = json.load(f)

    mv = int(raw.get("manifest_version", 2))
    name = raw.get("name", "")
    version = str(raw.get("version", ""))
    description = raw.get("description", "")

    # Normalize permissions: split URL patterns from named permissions
    raw_perms = raw.get("permissions", [])
    named_perms, host_perms_mv2 = _split_permissions(raw_perms)

    raw_optional = raw.get("optional_permissions", [])
    named_optional, host_optional_mv2 = _split_permissions(raw_optional)

    # MV3 has separate host_permissions field
    raw_host_perms = raw.get("host_permissions", [])
    raw_optional_host_perms = raw.get("optional_host_permissions", [])

    if mv == 3:
        host_permissions = list(raw_host_perms)
        optional_host_permissions = list(raw_optional_host_perms)
    else:
        # MV2: host perms live inside permissions[]
        host_permissions = host_perms_mv2
        optional_host_permissions = host_optional_mv2

    # Normalize <all_urls> shorthand
    host_permissions = _normalize_host_permissions(host_permissions)

    # Content scripts
    content_scripts = raw.get("content_scripts", [])
    cs_all_urls = _content_scripts_match_all(content_scripts)

    # Background
    bg = raw.get("background", {})
    bg_scripts = bg.get("scripts", [])
    bg_page = bg.get("page", "")
    bg_service_worker = bg.get("service_worker", "")
    bg_persistent = bg.get("persistent", None)

    # CSP
    csp_raw = raw.get("content_security_policy", "")
    if isinstance(csp_raw, dict):
        # MV3: CSP is a dict with extension_pages and sandbox keys
        csp_raw = csp_raw.get("extension_pages", "")
    has_unsafe_eval = "unsafe-eval" in csp_raw

    # Update URL
    update_url = raw.get("update_url", "")
    update_url_non_google = _is_non_google_update_url(update_url)

    # Web accessible resources
    war = raw.get("web_accessible_resources", [])

    # External connectivity
    ext_conn = raw.get("externally_connectable", {})

    # OAuth2
    oauth2 = raw.get("oauth2", {})

    return ExtensionManifest(
        manifest_version=mv,
        name=name,
        version=version,
        description=description,
        permissions=named_perms,
        optional_permissions=named_optional,
        host_permissions=host_permissions,
        optional_host_permissions=optional_host_permissions,
        content_scripts=content_scripts,
        content_scripts_all_urls=cs_all_urls,
        background_scripts=bg_scripts,
        background_page=bg_page,
        background_service_worker=bg_service_worker,
        background_persistent=bg_persistent,
        content_security_policy=csp_raw,
        has_unsafe_eval=has_unsafe_eval,
        update_url=update_url,
        update_url_non_google=update_url_non_google,
        web_accessible_resources=war,
        externally_connectable=ext_conn,
        oauth2=oauth2,
        raw=raw,
    )


def get_all_permissions(manifest: ExtensionManifest) -> list[str]:
    """
    Return the unified set of all declared permission strings (named + host).
    Useful for combo matching.
    """
    return list(
        set(
            manifest.permissions
            + manifest.host_permissions
            + manifest.optional_permissions
            + manifest.optional_host_permissions
        )
    )


def has_permission(manifest: ExtensionManifest, perm: str) -> bool:
    return perm in get_all_permissions(manifest)


# ── Private helpers ──────────────────────────────────────────────────────────


def _split_permissions(perms: list) -> tuple[list[str], list[str]]:
    """Split a permission list into (named_perms, url_patterns)."""
    named, urls = [], []
    for p in perms:
        if not isinstance(p, str):
            continue
        if _URL_PATTERN_RE.match(p) or p == "<all_urls>":
            urls.append(p)
        else:
            named.append(p)
    return named, urls


def _normalize_host_permissions(host_perms: list[str]) -> list[str]:
    """Ensure <all_urls> is always represented consistently."""
    out = []
    for p in host_perms:
        # *://*/* and http://*/* https://*/* all functionally equal <all_urls>
        if p in ("*://*/*", "http://*/*", "https://*/*"):
            p = "<all_urls>"
        out.append(p)
    return list(set(out))


def _content_scripts_match_all(content_scripts: list[dict]) -> bool:
    """Return True if any content script targets all URLs."""
    all_url_patterns = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}
    for cs in content_scripts:
        matches = cs.get("matches", [])
        for m in matches:
            if m in all_url_patterns:
                return True
    return False


def _is_non_google_update_url(update_url: str) -> bool:
    """Return True if update_url is non-empty and points to a non-Google host."""
    if not update_url:
        return False
    for domain in _GOOGLE_UPDATE_DOMAINS:
        if domain in update_url:
            return False
    return True
