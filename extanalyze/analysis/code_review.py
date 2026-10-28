"""
Static code review of extension JavaScript/HTML.

One engine for the default scan and for the optional --deep extras (see analysis/deep).
Heuristic, regex-based indicators for manual review: dynamic code loading, exfiltration
channels, sensitive-data access, secrets, obfuscation and CSP weaknesses. Code is never
executed. Minified libraries trigger some rules legitimately, so findings are leads, not
verdicts.

All patterns avoid unbounded nested quantifiers (linear time) because the input is
attacker-controlled, and per-file/total sizes are capped.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

MAX_FILE_BYTES = 2 * 1024 * 1024  # skip bigger files (reported as skipped)
MAX_TOTAL_BYTES = 30 * 1024 * 1024
MAX_FILES = 2000
MAX_LOCATIONS_PER_FINDING = 3
MAX_DOMAINS = 50
MAX_INTEL_ITEMS = 50
_SNIPPET_LEN = 100

_SCAN_SUFFIXES = {".js", ".mjs", ".cjs", ".html", ".htm"}

# Third-party directories: only HIGH/CRITICAL rules run there (libraries trip the noisy ones),
# but they are still scanned so payloads can't hide in a "lib" folder.
_VENDOR_DIRS = frozenset(
    {
        "node_modules",
        "npm",
        "vendor",
        "vendors",
        "lib",
        "libs",
        "dist",
        "third_party",
        "thirdparty",
        "bower_components",
        "jspm_packages",
    }
)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

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
    category: str  # DYNAMIC_CODE | EXFILTRATION | C2 | DATA_ACCESS | SECRET | OBFUSCATION | NETWORK | VULN
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    pattern: re.Pattern[str]
    description: str
    html_only: bool = False
    redact: bool = False  # never echo matched text (secrets)


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
    Rule(
        "CR-DYN-010",
        "document.write() with dynamic content",
        "DYNAMIC_CODE",
        "MEDIUM",
        _r(r"\bdocument\.write\s*\([^)]{0,200}[+`]"),
        "Concatenated document.write can inject arbitrary HTML/script into the page.",
    ),
    Rule(
        "CR-DYN-011",
        "innerHTML / outerHTML assignment",
        "DYNAMIC_CODE",
        "LOW",
        _r(r"\.(?:inner|outer)HTML\s*\+?=(?!=)"),
        "XSS sink when fed unsanitised input.",
    ),
    Rule(
        "CR-DYN-012",
        "tabs.executeScript",
        "DYNAMIC_CODE",
        "MEDIUM",
        _r(r"chrome\.tabs\.executeScript\s*\("),
        "Injects script into other pages (MV2 API).",
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
        _r(r"new\s+WebSocket\s*\(\s*[\"'`]wss?://(?!localhost|127\.0\.0\.1)"),
        "Persistent channel usable for C2 or streaming stolen data.",
    ),
    Rule(
        "CR-EXF-004",
        "Image/pixel beacon",
        "EXFILTRATION",
        "LOW",
        _r(
            r"new\s+Image\s*\(\s*\)\s*\.src\s*=|"
            r"\.src\s*=\s*[\"'`]https?://[^\"'`]{0,200}\?[^\"'`]{0,200}[\"'`]\s*\+"
        ),
        "Leaks data in a query string via image request.",
    ),
    Rule(
        "CR-EXF-005",
        "Encoded data in outbound request",
        "EXFILTRATION",
        "MEDIUM",
        _r(
            r"(?:fetch|\.open|sendBeacon)\s*\([^)]{0,200}"
            r"(?:btoa|encodeURIComponent|JSON\.stringify)\s*\("
        ),
        "Encodes collected data into a request.",
    ),
    Rule(
        "CR-EXF-006",
        "fetch() to hard-coded external origin",
        "EXFILTRATION",
        "MEDIUM",
        _r(r"\bfetch\s*\(\s*[\"'`]https?://"),
        "Contacts a fixed remote server (API, telemetry or exfiltration target).",
    ),
    Rule(
        "CR-EXF-007",
        "XMLHttpRequest to hard-coded external origin",
        "EXFILTRATION",
        "MEDIUM",
        _r(r"\.open\s*\(\s*[\"'`](?:GET|POST|PUT|PATCH|DELETE)[\"'`]\s*,\s*[\"'`]https?://", re.I),
        "Contacts a fixed remote server.",
    ),
    # ── Command and control ───────────────────────────────────────────────
    Rule(
        "CR-C2-001",
        "sendMessage to external extension",
        "C2",
        "HIGH",
        _r(r"chrome\.runtime\.sendMessage\s*\(\s*[\"'`][a-p]{32}[\"'`]"),
        "Talks to another extension by ID: possible out-of-band command channel.",
    ),
    Rule(
        "CR-C2-002",
        "Timer-driven polling of a remote endpoint",
        "C2",
        "MEDIUM",
        _r(r"(?:setInterval|setTimeout)\s*\([^)]{0,200}(?:fetch|XMLHttpRequest|XHR)"),
        "Periodic network polling, a common C2 check-in pattern.",
    ),
    Rule(
        "CR-C2-003",
        "chrome.storage.sync access",
        "C2",
        "LOW",
        _r(r"chrome\.storage\.sync\.(?:get|set)\s*\("),
        "Synced storage can be used to receive remote configuration.",
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
            r"type\s*=\s*[\"']?password|input\[type=[\"']?password|"
            r"autocomplete\s*=\s*[\"']?(?:cc-number|current-password)",
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
    # ── Secrets ───────────────────────────────────────────────────────────
    Rule(
        "CR-SEC-001",
        "Hard-coded API key or secret",
        "SECRET",
        "HIGH",
        _r(
            r"(?:api[_\-]?key|apikey|api[_\-]?secret|secret[_\-]?key|access[_\-]?token"
            r"|auth[_\-]?token|password|passwd)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9+/\-_]{20,200}[\"']",
            re.I,
        ),
        "Credential embedded in the extension: abusable by anyone who downloads it.",
        redact=True,
    ),
    Rule(
        "CR-SEC-002",
        "AWS access key ID",
        "SECRET",
        "CRITICAL",
        _r(r"\bAKIA[0-9A-Z]{16}\b"),
        "Embedded AWS credential.",
        redact=True,
    ),
    Rule(
        "CR-SEC-003",
        "Private key",
        "SECRET",
        "CRITICAL",
        _r(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "Embedded private key.",
        redact=True,
    ),
    Rule(
        "CR-SEC-004",
        "GitHub personal access token",
        "SECRET",
        "HIGH",
        _r(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        "Embedded source-control token.",
        redact=True,
    ),
    # ── Network hygiene ───────────────────────────────────────────────────
    Rule(
        "CR-NET-001",
        "Hard-coded IPv4 address",
        "NETWORK",
        "MEDIUM",
        _r(r"[\"'`](?!127\.|10\.)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\"'`]"),
        "Bypasses DNS-based blocklists; typical of throwaway C2 servers.",
    ),
    Rule(
        "CR-NET-002",
        "Non-HTTPS endpoint",
        "NETWORK",
        "MEDIUM",
        _r(r"[\"'`]http://(?!localhost|127\.0\.0\.1)[^\s\"'`]{5,200}[\"'`]"),
        "Plain-HTTP traffic can be read or modified in transit.",
    ),
    # ── Messaging ─────────────────────────────────────────────────────────
    Rule(
        "CR-VUL-001",
        "postMessage with wildcard origin",
        "VULN",
        "HIGH",
        _r(r"\.postMessage\s*\([^,)]{1,200},\s*[\"'`]\*[\"'`]"),
        "Any page can receive the message.",
    ),
    Rule(
        "CR-VUL-002",
        "window message listener",
        "VULN",
        "LOW",
        _r(r"addEventListener\s*\(\s*[\"'`]message[\"'`]"),
        "Verify the handler checks event.origin.",
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
    Rule(
        "CR-OBF-005",
        "Dean Edwards p,a,c,k,e,r packer",
        "OBFUSCATION",
        "HIGH",
        _r(r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,"),
        "Packed code: the real source is only recoverable by unpacking.",
    ),
    Rule(
        "CR-OBF-006",
        "unescape()/decodeURIComponent() of long literal",
        "OBFUSCATION",
        "MEDIUM",
        _r(r"\b(?:unescape|decodeURIComponent)\s*\(\s*[\"'`][%A-Fa-f0-9]{20,}"),
        "Percent-encoded payload decoded at runtime.",
    ),
    Rule(
        "CR-OBF-007",
        "Long hex string literal",
        "OBFUSCATION",
        "LOW",
        _r(r"[\"'`][0-9a-fA-F]{50,}[\"'`]"),
        "Opaque data blob (encoded payload, key or hash).",
    ),
]

_URL_RE = re.compile(r"""https?://[A-Za-z0-9.\-]{1,253}(?::\d{1,5})?[^\s"'`<>)\\]{0,200}""")
_IPV4_RE = re.compile(r"(?<![\w.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\w.])")
_BTC_RE = re.compile(r"(?<![A-Za-z0-9])([13][a-km-zA-HJ-NP-Z1-9]{25,33})(?![A-Za-z0-9])")
_INLINE_SCRIPT_RE = re.compile(
    r"<script(?![^>]{0,300}\bsrc\s*=)[^>]{0,300}>(.*?)</script>", re.S | re.I
)

_SENSITIVE_CATEGORY = "DATA_ACCESS"
_NETWORK_RULE_IDS = {
    "CR-EXF-001",
    "CR-EXF-002",
    "CR-EXF-003",
    "CR-EXF-004",
    "CR-EXF-005",
    "CR-EXF-006",
    "CR-EXF-007",
}


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
    ips: list[dict] = field(default_factory=list)  # {address, file}
    btc_addresses: list[dict] = field(default_factory=list)  # {address, file}
    deep: bool = False  # True when the --deep extras ran
    retire_js: list[dict] = field(default_factory=list)  # vulnerable bundled libraries
    vt_results: list[dict] = field(default_factory=list)  # VirusTotal domain lookups
    dynamic: dict | None = None  # sandbox observations (extanalyze-dynamic plugin)

    @property
    def high_count(self) -> int:
        flagged = sum(1 for f in self.findings if f.severity in ("CRITICAL", "HIGH"))
        return flagged + len(self.exfil_flows)


@dataclass
class SourceFile:
    rel: str
    text: str
    is_html: bool
    vendor: bool


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


def _is_vendor_path(rel: str) -> bool:
    parts = rel.replace("\\", "/").split("/")
    return any(p.lower() in _VENDOR_DIRS for p in parts[:-1])


def _normalise_domain(url: str) -> str | None:
    try:
        host = urlparse(url).hostname
    except ValueError:
        return None
    if not host or "." not in host or host in _IGNORED_DOMAINS:
        return None
    return host.lower()


def record(
    findings: dict[str, CodeFinding],
    key: str,
    *,
    rule_id: str,
    name: str,
    category: str,
    severity: str,
    description: str,
    count: int,
    location: Location | None,
) -> None:
    """Add an occurrence to a finding, creating it if needed (dedupes per rule)."""
    f = findings.setdefault(key, CodeFinding(rule_id, name, category, severity, description, 0))
    f.count += count
    if location and len(f.locations) < MAX_LOCATIONS_PER_FINDING:
        f.locations.append(location)


def scan_source(
    src: SourceFile, findings: dict[str, CodeFinding], label: str | None = None
) -> tuple[set[str], set[str]]:
    """Run the rules against one source file. Returns (rule ids hit, categories hit)."""
    rel = label or src.rel
    text = src.text
    # For HTML pages, JS rules run on inline scripts; html_only rules on the whole document
    js_text = "\n".join(_INLINE_SCRIPT_RE.findall(text)) if src.is_html else text

    hit_ids: set[str] = set()
    hit_cats: set[str] = set()
    for rule in RULES:
        if rule.html_only and not src.is_html:
            continue
        if src.vendor and rule.severity in ("MEDIUM", "LOW"):
            continue
        target = text if rule.html_only else js_text
        matches = list(rule.pattern.finditer(target))
        if not matches:
            continue
        hit_ids.add(rule.rule_id)
        hit_cats.add(rule.category)
        m = matches[0]
        loc = Location(
            rel,
            _line_of(target, m.start()),
            "[redacted]" if rule.redact else _snippet(target, m.start()),
        )
        record(
            findings,
            rule.rule_id,
            rule_id=rule.rule_id,
            name=rule.name,
            category=rule.category,
            severity=rule.severity,
            description=rule.description,
            count=len(matches),
            location=loc,
        )
    return hit_ids, hit_cats


def iter_sources(base: Path, relative_files: list[str]) -> Iterator[SourceFile | str]:
    """Yield SourceFile objects for JS/HTML under `base`; yield str notes for skipped files.

    Applies size/count limits, ignores symlinks and anything resolving outside `base`.
    """
    root = base.resolve()
    scanned = 0
    total_bytes = 0
    for rel in relative_files:
        if Path(rel).suffix.lower() not in _SCAN_SUFFIXES:
            continue
        if scanned >= MAX_FILES:
            yield f"{rel} (file limit reached)"
            continue
        path = (root / rel).resolve()
        if not path.is_relative_to(root) or not path.is_file() or (root / rel).is_symlink():
            continue
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            yield f"{rel} (>{MAX_FILE_BYTES // 1024 // 1024} MB)"
            continue
        if total_bytes + size > MAX_TOTAL_BYTES:
            yield f"{rel} (total size limit reached)"
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            yield f"{rel} (unreadable)"
            continue
        total_bytes += size
        scanned += 1
        yield SourceFile(rel, text, path.suffix.lower() in {".html", ".htm"}, _is_vendor_path(rel))


def _csp_findings(csp: str | None, manifest_version: int) -> list[CodeFinding]:
    """Content Security Policy weaknesses from manifest.json."""
    out: list[CodeFinding] = []

    def add(rule_id, name, category, severity, description, snippet=""):
        loc = Location("manifest.json", 0, snippet[:_SNIPPET_LEN])
        out.append(CodeFinding(rule_id, name, category, severity, description, 1, [loc]))

    if not csp:
        if manifest_version == 2:
            add(
                "CR-CSP-001",
                "Missing Content Security Policy (MV2)",
                "VULN",
                "MEDIUM",
                "No content_security_policy: MV2 extension pages allow eval() and inline scripts.",
            )
        return out  # MV3 has a restrictive default enforced by the browser

    low = csp.lower()
    if "unsafe-eval" in low:
        add(
            "CR-CSP-002",
            "CSP allows unsafe-eval",
            "DYNAMIC_CODE",
            "CRITICAL",
            "eval() and new Function() are permitted in extension pages.",
            csp,
        )
    if "unsafe-inline" in low and "script-src" in low:
        add(
            "CR-CSP-003",
            "CSP allows unsafe-inline scripts",
            "VULN",
            "HIGH",
            "Inline scripts and handlers are permitted in extension pages.",
            csp,
        )
    if re.search(r"script-src[^;]{0,500}(?:\*|http:)", low):
        add(
            "CR-CSP-004",
            "CSP script-src allows remote or wildcard scripts",
            "DYNAMIC_CODE",
            "CRITICAL",
            "Any web server can supply code to extension pages: primary MV2 C2 vector.",
            csp,
        )
    if re.search(r"connect-src[^;]{0,500}\*", low):
        add(
            "CR-CSP-005",
            "CSP connect-src allows any host",
            "EXFILTRATION",
            "HIGH",
            "No restriction on where extension pages can send data.",
            csp,
        )
    return out


def review_directory(
    base: Path, relative_files: list[str], csp: str | None = None, manifest_version: int = 3
) -> CodeReviewResult:
    """Scan JS/HTML files under `base` (paths relative to it, as listed by the extractor)."""
    findings: dict[str, CodeFinding] = {}
    domains: dict[str, int] = {}
    ips: dict[str, str] = {}
    btc: dict[str, str] = {}
    skipped: list[str] = []
    flows: list[str] = []
    scanned = 0

    for item in iter_sources(base, relative_files):
        if isinstance(item, str):
            skipped.append(item)
            continue
        scanned += 1
        hit_ids, hit_cats = scan_source(item, findings)
        if _SENSITIVE_CATEGORY in hit_cats and hit_ids & _NETWORK_RULE_IDS:
            flows.append(item.rel)

        for m in _URL_RE.finditer(item.text):
            d = _normalise_domain(m.group(0))
            if d:
                domains[d] = domains.get(d, 0) + 1
        if not item.vendor:
            for m in _IPV4_RE.finditer(item.text):
                try:
                    ip = ipaddress.ip_address(m.group(1))
                except ValueError:
                    continue
                if ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_reserved:
                    continue
                if len(ips) < MAX_INTEL_ITEMS:
                    ips.setdefault(m.group(1), item.rel)
            for m in _BTC_RE.finditer(item.text):
                if len(btc) < MAX_INTEL_ITEMS:
                    btc.setdefault(m.group(1), item.rel)

    for f in _csp_findings(csp, manifest_version):
        findings[f.rule_id] = f

    return CodeReviewResult(
        findings=sort_findings(findings),
        external_domains=sorted(domains, key=lambda d: (-domains[d], d))[:MAX_DOMAINS],
        files_scanned=scanned,
        files_skipped=skipped,
        exfil_flows=flows,
        ips=[{"address": a, "file": f} for a, f in ips.items()],
        btc_addresses=[{"address": a, "file": f} for a, f in btc.items()],
    )


def sort_findings(findings: dict[str, CodeFinding]) -> list[CodeFinding]:
    return sorted(
        findings.values(), key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.rule_id, f.name)
    )
