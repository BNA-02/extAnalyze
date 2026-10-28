"""
Static code review of extension JavaScript/HTML.

Heuristic, regex-based indicators for manual review: dynamic code loading,
data-exfiltration channels, sensitive-data access and obfuscation. The code is
never executed. Minified libraries and bundlers trigger some rules legitimately,
so findings are leads, not verdicts.

All patterns are kept free of nested quantifiers (linear time) because the input
is attacker-controlled, and per-file/total size is capped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

MAX_FILE_BYTES = 2 * 1024 * 1024  # skip bigger files (reported as skipped)
MAX_TOTAL_BYTES = 30 * 1024 * 1024
MAX_FILES = 2000
MAX_LOCATIONS_PER_FINDING = 3
MAX_DOMAINS = 50
_SNIPPET_LEN = 100

_SCAN_SUFFIXES = {".js", ".mjs", ".cjs", ".html", ".htm"}

# Domains that appear in code as namespaces/docs, not as contact points
_IGNORED_DOMAINS = {
    "www.w3.org",
    "w3.org",
    "www.apache.org",
    "developer.mozilla.org",
    "developer.chrome.com",
    "github.com",
    "raw.githubusercontent.com",
    "reactjs.org",
    "react.dev",
    "json-schema.org",
    "schemas.microsoft.com",
    "localhost",
    "127.0.0.1",
    "example.com",
}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    category: str  # DYNAMIC_CODE | EXFILTRATION | DATA_ACCESS | OBFUSCATION
    severity: str  # HIGH | MEDIUM | LOW
    pattern: re.Pattern[str]
    description: str
    html_only: bool = False


def _r(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


RULES: list[Rule] = [
    # ── Dynamic code loading / execution ──────────────────────────────────
    Rule(
        "CR-DYN-001",
        "eval() call",
        "DYNAMIC_CODE",
        "MEDIUM",
        _r(r"(?<![\w$.])eval\s*\("),
        "Executes strings as code; hides behaviour from static review and store review.",
    ),
    Rule(
        "CR-DYN-002",
        "Function constructor",
        "DYNAMIC_CODE",
        "MEDIUM",
        _r(r"\bnew\s+Function\s*\("),
        "Builds code from strings at runtime.",
    ),
    Rule(
        "CR-DYN-003",
        "importScripts() from remote URL",
        "DYNAMIC_CODE",
        "HIGH",
        _r(r"importScripts\s*\(\s*[\"'`]https?://"),
        "Service worker loads code from a remote server; behaviour can change after review.",
    ),
    Rule(
        "CR-DYN-004",
        "Dynamic import() of remote URL",
        "DYNAMIC_CODE",
        "HIGH",
        _r(r"\bimport\s*\(\s*[\"'`]https?://"),
        "Loads a module from a remote server at runtime.",
    ),
    Rule(
        "CR-DYN-005",
        "Script element created at runtime",
        "DYNAMIC_CODE",
        "MEDIUM",
        _r(r"createElement\s*\(\s*[\"']script[\"']\s*\)"),
        "Injects a script element, typically to pull in code (often remote).",
    ),
    Rule(
        "CR-DYN-006",
        "Remote <script src> in extension page",
        "DYNAMIC_CODE",
        "HIGH",
        _r(r"<script[^>]{0,300}\bsrc\s*=\s*[\"']?(?:https?:)?//", re.I),
        "Extension page loads remotely hosted script.",
        html_only=True,
    ),
    Rule(
        "CR-DYN-007",
        "scripting.executeScript with code string",
        "DYNAMIC_CODE",
        "MEDIUM",
        _r(r"executeScript\s*\([^)]{0,200}\bcode\s*:"),
        "Injects code supplied as a string into web pages.",
    ),
    Rule(
        "CR-DYN-008",
        "Fetched content passed to eval/Function",
        "DYNAMIC_CODE",
        "HIGH",
        _r(r"fetch\s*\([^)]{0,300}\)[^;]{0,200}?\b(?:eval|Function)\s*\("),
        "Downloads data and executes it: classic remote-code pattern.",
    ),
    Rule(
        "CR-DYN-009",
        "setTimeout/setInterval with string",
        "DYNAMIC_CODE",
        "LOW",
        _r(r"\bset(?:Timeout|Interval)\s*\(\s*[\"'`]"),
        "String argument is evaluated as code.",
    ),
    # ── Exfiltration / outbound channels ──────────────────────────────────
    Rule(
        "CR-EXF-001",
        "navigator.sendBeacon",
        "EXFILTRATION",
        "MEDIUM",
        _r(r"navigator\.sendBeacon\s*\("),
        "Fire-and-forget POST, commonly used for telemetry and exfiltration.",
    ),
    Rule(
        "CR-EXF-002",
        "POST to hard-coded external URL",
        "EXFILTRATION",
        "MEDIUM",
        _r(r"(?:method\s*:\s*[\"']POST[\"']|\.open\s*\(\s*[\"']POST[\"']\s*,\s*[\"'`]https?://)"),
        "Sends data to a remote server.",
    ),
    Rule(
        "CR-EXF-003",
        "WebSocket to external host",
        "EXFILTRATION",
        "MEDIUM",
        _r(r"new\s+WebSocket\s*\(\s*[\"'`]wss?://"),
        "Persistent channel usable for C2 or streaming stolen data.",
    ),
    Rule(
        "CR-EXF-004",
        "Image/pixel beacon",
        "EXFILTRATION",
        "LOW",
        _r(
            r"new\s+Image\s*\(\s*\)\s*\.src\s*=|\.src\s*=\s*[\"'`]https?://[^\"'`]{0,200}\?[^\"'`]{0,200}[\"'`]\s*\+"
        ),
        "Leaks data in a query string via image request.",
    ),
    Rule(
        "CR-EXF-005",
        "Encoded data in outbound request",
        "EXFILTRATION",
        "MEDIUM",
        _r(
            r"(?:fetch|\.open|sendBeacon)\s*\([^)]{0,200}(?:btoa|encodeURIComponent|JSON\.stringify)\s*\("
        ),
        "Encodes collected data into a request.",
    ),
    # ── Sensitive data access ─────────────────────────────────────────────
    Rule(
        "CR-DAT-001",
        "Cookie harvesting",
        "DATA_ACCESS",
        "HIGH",
        _r(r"cookies\.(?:getAll|get)\s*\(|document\.cookie"),
        "Reads cookies (session tokens, tracking IDs).",
    ),
    Rule(
        "CR-DAT-002",
        "Browsing history access",
        "DATA_ACCESS",
        "HIGH",
        _r(r"\bhistory\.(?:search|getVisits)\s*\("),
        "Reads the user's browsing history.",
    ),
    Rule(
        "CR-DAT-003",
        "Password / credential field access",
        "DATA_ACCESS",
        "HIGH",
        _r(
            r"type\s*=\s*[\"']?password|input\[type=[\"']?password|autocomplete\s*=\s*[\"']?(?:cc-number|current-password)",
            re.I,
        ),
        "Targets password or payment fields.",
    ),
    Rule(
        "CR-DAT-004",
        "Keystroke capture",
        "DATA_ACCESS",
        "MEDIUM",
        _r(r"addEventListener\s*\(\s*[\"'](?:keydown|keyup|keypress)[\"']"),
        "Listens to keystrokes (legitimate for shortcuts, also keylogging).",
    ),
    Rule(
        "CR-DAT-005",
        "Clipboard read",
        "DATA_ACCESS",
        "MEDIUM",
        _r(r"clipboard\.readText\s*\(|execCommand\s*\(\s*[\"']paste[\"']"),
        "Reads clipboard contents.",
    ),
    Rule(
        "CR-DAT-006",
        "Tab URL enumeration",
        "DATA_ACCESS",
        "LOW",
        _r(r"tabs\.query\s*\(\s*\{\s*\}\s*"),
        "Enumerates all tabs (URLs/titles).",
    ),
    Rule(
        "CR-DAT-007",
        "Web request / headers interception",
        "DATA_ACCESS",
        "MEDIUM",
        _r(r"webRequest\.on(?:BeforeSendHeaders|SendHeaders|BeforeRequest|Completed)\.addListener"),
        "Observes all traffic metadata.",
    ),
    # ── Obfuscation ───────────────────────────────────────────────────────
    Rule(
        "CR-OBF-001",
        "Obfuscator-style identifiers",
        "OBFUSCATION",
        "MEDIUM",
        _r(r"\b_0x[0-9a-f]{4,6}\b"),
        "Identifier style produced by javascript-obfuscator and similar tools.",
    ),
    Rule(
        "CR-OBF-002",
        "Base64 decode feeding code/URL",
        "OBFUSCATION",
        "MEDIUM",
        _r(r"\batob\s*\(\s*[\"'][A-Za-z0-9+/=]{24,}[\"']"),
        "Hard-coded base64 blob decoded at runtime.",
    ),
    Rule(
        "CR-OBF-003",
        "String.fromCharCode chain",
        "OBFUSCATION",
        "LOW",
        _r(r"String\.fromCharCode\s*\(\s*(?:\d{2,3}\s*,\s*){6,}"),
        "Builds strings from char codes to evade string search.",
    ),
    Rule(
        "CR-OBF-004",
        "Long hex/unicode escape runs",
        "OBFUSCATION",
        "LOW",
        _r(r"(?:\\x[0-9a-fA-F]{2}){12,}|(?:\\u[0-9a-fA-F]{4}){8,}"),
        "Escaped string literal hiding its content.",
    ),
]

_URL_RE = re.compile(r"""https?://[A-Za-z0-9.\-]{1,253}(?::\d{1,5})?[^\s"'`<>)\\]{0,200}""")
_INLINE_SCRIPT_RE = re.compile(
    r"<script(?![^>]{0,300}\bsrc\s*=)[^>]{0,300}>(.*?)</script>", re.S | re.I
)

_SENSITIVE_CATEGORY = "DATA_ACCESS"
_NETWORK_RULE_IDS = {"CR-EXF-001", "CR-EXF-002", "CR-EXF-003", "CR-EXF-004", "CR-EXF-005"}


@dataclass
class Location:
    file: str
    line: int
    snippet: str  # untrusted text, truncated; reporters MUST escape it


@dataclass
class CodeFinding:
    rule_id: str
    name: str
    category: str
    severity: str
    description: str
    count: int
    locations: list[Location] = field(default_factory=list)


@dataclass
class CodeReviewResult:
    findings: list[CodeFinding]
    external_domains: list[str]
    files_scanned: int
    files_skipped: list[str]  # too large / unreadable / over limits
    exfil_flows: list[str]  # files combining sensitive access + outbound channel

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH") + len(self.exfil_flows)


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _snippet(text: str, pos: int) -> str:
    start = max(text.rfind("\n", 0, pos) + 1, pos - 30)
    end = min(pos + _SNIPPET_LEN, len(text))
    nl = text.find("\n", pos, end)
    if nl != -1:
        end = nl
    # collapse control characters so snippets can't forge terminal output
    return re.sub(r"[\x00-\x1f\x7f]", " ", text[start:end]).strip()


def _normalise_domain(url: str) -> str | None:
    try:
        host = urlparse(url).hostname
    except ValueError:
        return None
    if not host or "." not in host or host in _IGNORED_DOMAINS:
        return None
    return host.lower()


def review_directory(base: Path, relative_files: list[str]) -> CodeReviewResult:
    """Scan JS/HTML files under `base` (paths relative to it, as listed by the extractor)."""
    root = base.resolve()
    findings: dict[str, CodeFinding] = {}
    domains: dict[str, int] = {}
    skipped: list[str] = []
    flows: list[str] = []
    scanned = 0
    total_bytes = 0

    candidates = [f for f in relative_files if Path(f).suffix.lower() in _SCAN_SUFFIXES]

    for rel in candidates:
        if scanned >= MAX_FILES:
            skipped.append(f"{rel} (file limit reached)")
            continue
        path = (root / rel).resolve()
        if not path.is_relative_to(root) or not path.is_file() or path.is_symlink():
            continue
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            skipped.append(f"{rel} (>{MAX_FILE_BYTES // 1024 // 1024} MB)")
            continue
        if total_bytes + size > MAX_TOTAL_BYTES:
            skipped.append(f"{rel} (total size limit reached)")
            continue
        total_bytes += size
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped.append(f"{rel} (unreadable)")
            continue
        scanned += 1

        is_html = path.suffix.lower() in {".html", ".htm"}
        # For HTML pages, scan the whole document for html_only rules and inline scripts for JS rules
        js_text = "\n".join(_INLINE_SCRIPT_RE.findall(text)) if is_html else text

        hit_ids: set[str] = set()
        hit_cats: set[str] = set()
        for rule in RULES:
            target = text if rule.html_only else js_text
            if rule.html_only and not is_html:
                continue
            matches = list(rule.pattern.finditer(target))
            if not matches:
                continue
            hit_ids.add(rule.rule_id)
            hit_cats.add(rule.category)
            finding = findings.setdefault(
                rule.rule_id,
                CodeFinding(
                    rule.rule_id, rule.name, rule.category, rule.severity, rule.description, 0
                ),
            )
            finding.count += len(matches)
            if len(finding.locations) < MAX_LOCATIONS_PER_FINDING:
                m = matches[0]
                finding.locations.append(
                    Location(rel, _line_of(target, m.start()), _snippet(target, m.start()))
                )

        if _SENSITIVE_CATEGORY in hit_cats and hit_ids & _NETWORK_RULE_IDS:
            flows.append(rel)

        for m in _URL_RE.finditer(text):
            d = _normalise_domain(m.group(0))
            if d:
                domains[d] = domains.get(d, 0) + 1

    ordered = sorted(
        findings.values(),
        key=lambda f: ({"HIGH": 0, "MEDIUM": 1, "LOW": 2}[f.severity], f.rule_id),
    )
    top_domains = sorted(domains, key=lambda d: (-domains[d], d))[:MAX_DOMAINS]
    return CodeReviewResult(ordered, top_domains, scanned, skipped, flows)
