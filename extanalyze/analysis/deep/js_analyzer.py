"""
js_analyzer.py — Pattern-based JS static analysis.

All detection is regex on raw text — no AST, no execution.
Minified code is handled identically to formatted code.
Each rule returns zero or more Finding objects.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterator

from .findings import Finding
from .source_extractor import SourceUnit

# ── Helpers ──────────────────────────────────────────────────────────────────


def _line_of(source: str, match_start: int, offset: int = 1) -> int:
    """Return the line number (1-indexed) of a match position."""
    return source[:match_start].count("\n") + offset


def _snippet(text: str, start: int, length: int = 120) -> str:
    return text[start : start + length].replace("\n", " ").strip()


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())


# ── Rule definitions ──────────────────────────────────────────────────────────
# Each rule is a tuple: (rule_id, category, severity, confidence, title, description, pattern)

_RULES: list[tuple[str, str, str, str, str, str, re.Pattern]] = [
    # ── EXEC: dangerous code execution ───────────────────────────────────────
    (
        "DEEP_001",
        "EXEC",
        "CRITICAL",
        "HIGH",
        "eval() call",
        "eval() executes arbitrary strings as code. In MV2 allows remote code execution; "
        "in MV3 blocked by CSP but still dangerous if used with local data.",
        re.compile(r"\beval\s*\(", re.MULTILINE),
    ),
    (
        "DEEP_002",
        "EXEC",
        "CRITICAL",
        "HIGH",
        "new Function() constructor",
        "new Function() creates functions from strings at runtime — equivalent to eval(). "
        "Bypasses static analysis and can execute dynamically fetched payloads.",
        re.compile(r"\bnew\s+Function\s*\(", re.MULTILINE),
    ),
    (
        "DEEP_003",
        "EXEC",
        "HIGH",
        "MEDIUM",
        "setTimeout/setInterval with string argument",
        "Passing a string literal to setTimeout/setInterval evaluates it as code — "
        "behaves like eval() and can execute delayed payloads.",
        re.compile(r"\bset(?:Timeout|Interval)\s*\(\s*[\"'`]", re.MULTILINE),
    ),
    (
        "DEEP_004",
        "EXEC",
        "HIGH",
        "MEDIUM",
        "document.write() with dynamic content",
        "document.write() with concatenation or variables can inject arbitrary HTML/JS "
        "into the page, including <script> tags.",
        re.compile(r"\bdocument\.write\s*\([^)]*[\+\`]", re.MULTILINE),
    ),
    (
        "DEEP_005",
        "EXEC",
        "HIGH",
        "MEDIUM",
        "innerHTML / outerHTML assignment",
        "Assigning to innerHTML/outerHTML with unsanitized input is an XSS sink — "
        "can inject executable script content into the DOM.",
        re.compile(r"\.(?:inner|outer)HTML\s*[+]?=\s*(?![\"\']\\s*[\"\']\s*;)", re.MULTILINE),
    ),
    # ── REMOTE_LOAD: loading code from external sources ───────────────────────
    (
        "DEEP_010",
        "REMOTE_LOAD",
        "CRITICAL",
        "HIGH",
        "Dynamic script element injection",
        "Creates a <script> element and sets its src to a remote URL — "
        "loads and executes arbitrary remote code. Classic MV2 C2 technique.",
        re.compile(
            r"createElement\s*\(\s*[\"'`]script[\"'`]\s*\)",
            re.MULTILINE | re.IGNORECASE,
        ),
    ),
    (
        "DEEP_011",
        "REMOTE_LOAD",
        "CRITICAL",
        "HIGH",
        "importScripts() with remote URL",
        "importScripts() in a service worker or background script loading from http(s):// "
        "fetches and executes remote code — blocked in MV3 but critical finding in MV2.",
        re.compile(r"\bimportScripts\s*\(\s*[\"'`]https?://", re.MULTILINE),
    ),
    (
        "DEEP_012",
        "REMOTE_LOAD",
        "HIGH",
        "MEDIUM",
        "chrome.tabs.executeScript with remote code",
        "executeScript injecting code fetched or built from external sources.",
        re.compile(r"chrome\.tabs\.executeScript\s*\(", re.MULTILINE),
    ),
    # ── EXFIL: data exfiltration patterns ────────────────────────────────────
    (
        "DEEP_020",
        "EXFIL",
        "HIGH",
        "MEDIUM",
        "fetch() to external origin",
        "fetch() call targeting a non-extension URL — potential data exfiltration "
        "or C2 callback. Needs host_permissions to function.",
        re.compile(
            r"\bfetch\s*\(\s*[\"'`]https?://(?!.*chrome-extension://)",
            re.MULTILINE,
        ),
    ),
    (
        "DEEP_021",
        "EXFIL",
        "HIGH",
        "MEDIUM",
        "XMLHttpRequest to external origin",
        "XHR.open() targeting an http(s) URL — same exfiltration vector as fetch().",
        re.compile(
            r"\.open\s*\(\s*[\"'`](?:GET|POST|PUT|PATCH|DELETE)[\"'`]\s*,\s*[\"'`]https?://",
            re.MULTILINE | re.IGNORECASE,
        ),
    ),
    (
        "DEEP_022",
        "EXFIL",
        "HIGH",
        "MEDIUM",
        "navigator.sendBeacon() to external origin",
        "sendBeacon() silently posts data to a URL — designed for analytics but "
        "commonly abused for low-detectability exfiltration.",
        re.compile(r"\bnavigator\.sendBeacon\s*\(\s*[\"'`]https?://", re.MULTILINE),
    ),
    (
        "DEEP_023",
        "EXFIL",
        "MEDIUM",
        "MEDIUM",
        "WebSocket to external host",
        "WebSocket connection to a non-localhost host — can be used for real-time "
        "bidirectional C2 communication or data streaming.",
        re.compile(
            r"\bnew\s+WebSocket\s*\(\s*[\"'`]wss?://(?!localhost|127\.0\.0\.1)",
            re.MULTILINE,
        ),
    ),
    # ── C2: command and control indicators ───────────────────────────────────
    (
        "DEEP_030",
        "C2",
        "HIGH",
        "MEDIUM",
        "chrome.runtime.sendMessage to external extension",
        "sendMessage() with an explicit extension ID communicates with a different "
        "extension — potential relay or C2 proxy pattern.",
        re.compile(r"chrome\.runtime\.sendMessage\s*\(\s*[\"'`][a-p]{32}[\"'`]", re.MULTILINE),
    ),
    (
        "DEEP_031",
        "C2",
        "HIGH",
        "MEDIUM",
        "Long-polling / keep-alive fetch pattern",
        "Recursive fetch or setTimeout/setInterval loop calling an external URL — "
        "classic keep-alive C2 polling pattern.",
        re.compile(
            r"(?:setInterval|setTimeout)\s*\([^)]*(?:fetch|XMLHttpRequest|XHR)[^)]*\)",
            re.MULTILINE,
        ),
    ),
    (
        "DEEP_032",
        "C2",
        "MEDIUM",
        "LOW",
        "chrome.storage.sync access",
        "chrome.storage.sync syncs data across all browser instances — "
        "can be used to receive C2 configuration updates silently.",
        re.compile(r"chrome\.storage\.sync\.(?:get|set)\s*\(", re.MULTILINE),
    ),
    # ── OBFUSCATION: code hiding techniques ───────────────────────────────────
    (
        "DEEP_040",
        "OBFUSCATION",
        "HIGH",
        "HIGH",
        "Dean Edwards p,a,c,k,e,r packer",
        "Recognized pattern of the p,a,c,k,e,r JavaScript obfuscator — "
        "all meaningful code is hidden and unpacked at runtime.",
        re.compile(
            r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,", re.MULTILINE
        ),
    ),
    (
        "DEEP_041",
        "OBFUSCATION",
        "HIGH",
        "HIGH",
        "atob() / btoa() base64 decode in code",
        "atob() decodes base64 strings at runtime — frequently used to hide "
        "malicious payloads from static analysis.",
        re.compile(r"\batob\s*\(", re.MULTILINE),
    ),
    (
        "DEEP_042",
        "OBFUSCATION",
        "HIGH",
        "MEDIUM",
        "String.fromCharCode() with multiple arguments",
        "Converts numeric char codes to a string — classic obfuscation technique "
        "to hide URLs, keywords, or payload strings from string-based detection.",
        re.compile(r"\bString\.fromCharCode\s*\(\s*\d+(?:\s*,\s*\d+){4,}", re.MULTILINE),
    ),
    (
        "DEEP_043",
        "OBFUSCATION",
        "MEDIUM",
        "MEDIUM",
        "unescape() / decodeURIComponent() of long string",
        "Decoding percent-encoded or escape-encoded strings — used to hide URLs "
        "and code from static analysis.",
        re.compile(
            r"\b(?:unescape|decodeURIComponent)\s*\(\s*[\"'`][%A-Fa-f0-9]{20,}", re.MULTILINE
        ),
    ),
    (
        "DEEP_044",
        "OBFUSCATION",
        "MEDIUM",
        "MEDIUM",
        "Long hex string literal",
        "String literal containing 50+ hex characters — likely obfuscated payload or encoded data.",
        re.compile(r"[\"'`][0-9a-fA-F]{50,}[\"'`]"),
    ),
    # ── SECRET: hardcoded credentials ────────────────────────────────────────
    (
        "DEEP_050",
        "SECRET",
        "HIGH",
        "MEDIUM",
        "Hardcoded API key or secret",
        "String assignment that looks like a hardcoded API key, token, or password. "
        "Should be stored in server-side infrastructure, not extension code.",
        re.compile(
            r"(?:api[_\-]?key|apikey|api[_\-]?secret|secret[_\-]?key|access[_\-]?token"
            r'|auth[_\-]?token|password|passwd)\s*[:=]\s*["\'][A-Za-z0-9+/\-_]{20,}["\']',
            re.IGNORECASE | re.MULTILINE,
        ),
    ),
    (
        "DEEP_051",
        "SECRET",
        "CRITICAL",
        "HIGH",
        "AWS Access Key ID",
        "AWS access key ID pattern detected — could allow full AWS account access "
        "if the corresponding secret is also present.",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "DEEP_052",
        "SECRET",
        "CRITICAL",
        "HIGH",
        "Private key header",
        "PEM private key embedded in extension code — immediate credential exposure.",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ),
    (
        "DEEP_053",
        "SECRET",
        "HIGH",
        "MEDIUM",
        "GitHub / GitLab personal access token",
        "GitHub PAT (ghp_) or GitLab token pattern embedded in code.",
        re.compile(r"\b(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{36,}\b"),
    ),
    # ── NETWORK: suspicious network indicators ────────────────────────────────
    (
        "DEEP_060",
        "NETWORK",
        "MEDIUM",
        "MEDIUM",
        "Hardcoded IPv4 address",
        "Hardcoded IP address — direct-IP communication bypasses DNS-based "
        "blocking and reduces traceability of C2 infrastructure.",
        re.compile(
            r"[\"'`](?!127\.0\.0\.1|0\.0\.0\.0|localhost)"
            r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\"'`]"
        ),
    ),
    (
        "DEEP_061",
        "NETWORK",
        "MEDIUM",
        "MEDIUM",
        "Non-HTTPS endpoint",
        "Plaintext HTTP URL — data sent over HTTP is visible to network observers "
        "and susceptible to MITM modification.",
        re.compile(r"[\"'`]http://(?!localhost|127\.0\.0\.1)[^\s\"'`]{5,}[\"'`]"),
    ),
    # ── VULN: postMessage misconfiguration ────────────────────────────────────
    (
        "DEEP_070",
        "VULN",
        "HIGH",
        "MEDIUM",
        "postMessage with wildcard origin",
        "postMessage('*') sends data to any frame regardless of origin — "
        "can leak sensitive data to attacker-controlled iframes.",
        re.compile(r"\.postMessage\s*\([^,)]+,\s*[\"'`]\*[\"'`]", re.MULTILINE),
    ),
    (
        "DEEP_071",
        "VULN",
        "MEDIUM",
        "LOW",
        "postMessage listener without origin check",
        "addEventListener('message', ...) without apparent origin validation — "
        "the handler may accept messages from any source.",
        re.compile(
            r"addEventListener\s*\(\s*[\"'`]message[\"'`]",
            re.MULTILINE,
        ),
    ),
]


# ── Entropy-based obfuscation detection ──────────────────────────────────────

_STRING_LITERAL_RE = re.compile(r'["\']([A-Za-z0-9+/=_\-]{30,})["\']')
_ENTROPY_THRESHOLD = 4.5


def _check_entropy(unit: SourceUnit) -> Iterator[Finding]:
    """Flag high-entropy string literals that likely contain encoded payloads."""
    for match in _STRING_LITERAL_RE.finditer(unit.source):
        s = match.group(1)
        entropy = _shannon_entropy(s)
        if entropy >= _ENTROPY_THRESHOLD:
            yield Finding(
                rule_id="DEEP_045",
                category="OBFUSCATION",
                severity="MEDIUM",
                confidence="LOW",
                title=f"High-entropy string (entropy={entropy:.2f})",
                description=(
                    f"String literal with Shannon entropy {entropy:.2f} bits/char "
                    f"(threshold: {_ENTROPY_THRESHOLD}) — likely base64, encrypted, "
                    "or otherwise encoded data. May conceal URLs, payloads, or keys."
                ),
                file=unit.file,
                line=_line_of(unit.source, match.start(), unit.line_offset),
                snippet=_snippet(unit.source, match.start()),
            )


# ── Main per-unit analyzer ────────────────────────────────────────────────────


def analyze_unit(unit: SourceUnit) -> list[Finding]:
    """Run all JS rules against a single SourceUnit. Returns list of Findings."""
    findings: list[Finding] = []

    for rule_id, category, severity, confidence, title, description, pattern in _RULES:
        for match in pattern.finditer(unit.source):
            findings.append(
                Finding(
                    rule_id=rule_id,
                    category=category,
                    severity=severity,
                    confidence=confidence,
                    title=title,
                    description=description,
                    file=unit.file,
                    line=_line_of(unit.source, match.start(), unit.line_offset),
                    snippet=_snippet(unit.source, match.start()),
                )
            )

    findings.extend(_check_entropy(unit))
    return findings
