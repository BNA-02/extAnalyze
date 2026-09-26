"""
intel_extractor.py — Extract URLs, IPs, emails, base64, comments, bitcoin addresses.
Based on ExtAnalysis intel.py patterns with improvements.
"""

from __future__ import annotations

import re
from pathlib import Path

# ── Regexes ───────────────────────────────────────────────────────────────────

_URL_RE = re.compile(
    r"(https?|ftp)://([\w_\-]+(?:\.[\w_\-]+)+)"
    r"([\w.,@?^=%&:/~+#\-]*[\w@?^=%&/~+#\-])?",
    re.IGNORECASE,
)

_IPV4_RE = re.compile(r"(?<![a-zA-Z0-9])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![a-zA-Z0-9])")

_EMAIL_RE = re.compile(
    r"([a-zA-Z0-9.\-_]+(?:@| ?\[(?:at)\] ?)[a-zA-Z0-9.\-]+(?:\.| ?\[(?:dot)\] ?)[a-zA-Z]+)"
)

# Padded base64 — minimum 12 chars (to reduce noise vs ExtAnalysis 8-char min)
_BASE64_RE = re.compile(r"(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)")

# JS inline + block + HTML comments
_COMMENT_JS_INLINE_RE = re.compile(r"//(.+?)$", re.MULTILINE)
_COMMENT_JS_BLOCK_RE = re.compile(r"/\*(.+?)\*/", re.DOTALL)
_COMMENT_HTML_RE = re.compile(r"<!--(.+?)-->", re.DOTALL)

# Bitcoin P2PKH/P2SH addresses
_BTC_RE = re.compile(r"(?<![a-zA-Z0-9])([13][a-km-zA-HJ-NP-Z1-9]{26,33})(?![a-zA-Z0-9])")

# Domain extraction from URL
_DOMAIN_FROM_URL_RE = re.compile(r"^(?:https?://)?(?:[^@/\n]+@)?(?:www\.)?([^:/?#\n]+)")

_SCANNABLE_EXTS = {".js", ".html", ".htm", ".json", ".css"}


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def extract_intel(tmp_dir: Path, all_files: list[str]) -> dict:
    """
    Scan all text files for URLs, IPs, emails, base64 strings, comments, and BTC addresses.
    Returns a dict with lists for each category.
    """
    urls: list[dict] = []
    ips: list[dict] = []
    emails: list[dict] = []
    base64s: list[dict] = []
    comments: list[dict] = []
    btc: list[dict] = []

    seen_urls: set[str] = set()
    seen_ips: set[str] = set()

    for rel_path in all_files:
        if not any(rel_path.endswith(ext) for ext in _SCANNABLE_EXTS):
            continue

        path = tmp_dir / rel_path
        if not path.is_file():
            continue

        content = _read(path)
        if not content:
            continue

        # ── URLs ──────────────────────────────────────────────────────────────
        for m in _URL_RE.finditer(content):
            url = m.group(0)
            key = url.lower()
            if key not in seen_urls:
                seen_urls.add(key)
                # Skip internal chrome-extension:// URLs — not interesting
                if not url.startswith("chrome-extension://"):
                    urls.append({"url": url, "file": rel_path})

        # ── IPv4 ──────────────────────────────────────────────────────────────
        for m in _IPV4_RE.finditer(content):
            addr = m.group(1)
            # Validate octets to avoid version strings like 1.0.0.0
            parts = addr.split(".")
            if all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                # Skip private/loopback ranges
                first = int(parts[0])
                if addr not in ("127.0.0.1", "0.0.0.0") and first not in (10, 127):  # noqa: S104
                    key = addr
                    if key not in seen_ips:
                        seen_ips.add(key)
                        ips.append({"address": addr, "file": rel_path})

        # ── Emails ────────────────────────────────────────────────────────────
        for m in _EMAIL_RE.finditer(content):
            mail = m.group(1)
            mail = mail.replace("[at]", "@").replace(" [at] ", "@")
            mail = mail.replace("[dot]", ".").replace(" [dot] ", ".")
            emails.append({"mail": mail, "file": rel_path})

        # ── Base64 ────────────────────────────────────────────────────────────
        for m in _BASE64_RE.finditer(content):
            s = m.group(0)
            base64s.append({"string": s[:80] + ("..." if len(s) > 80 else ""), "file": rel_path})

        # ── Comments ──────────────────────────────────────────────────────────
        if rel_path.endswith((".js", ".html", ".htm", ".css")):
            for m in _COMMENT_JS_INLINE_RE.finditer(content):
                text = m.group(1).strip()
                if text:
                    comments.append({"comment": text[:200], "file": rel_path})
            for m in _COMMENT_JS_BLOCK_RE.finditer(content):
                text = m.group(1).strip()
                if text:
                    comments.append({"comment": text[:200], "file": rel_path})
            for m in _COMMENT_HTML_RE.finditer(content):
                text = m.group(1).strip()
                if text:
                    comments.append({"comment": text[:200], "file": rel_path})

        # ── Bitcoin addresses ─────────────────────────────────────────────────
        for m in _BTC_RE.finditer(content):
            btc.append({"address": m.group(1), "file": rel_path})

    return {
        "urls": urls,
        "ips": ips,
        "emails": emails,
        "base64": base64s,
        "comments": comments,
        "btc": btc,
    }
