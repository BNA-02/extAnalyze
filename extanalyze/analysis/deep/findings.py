"""
findings.py — Finding dataclass for deep static analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Finding:
    rule_id: str  # e.g. DEEP_001
    category: str  # EXEC | EXFIL | C2 | OBFUSCATION | REMOTE_LOAD | SECRET | NETWORK | VULN
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    confidence: str  # HIGH | MEDIUM | LOW
    title: str
    description: str
    file: str  # relative path inside the extension
    line: int | None  # None when not determinable (e.g. minified single-line)
    snippet: str  # up to 120 chars of matched text


@dataclass
class DeepAnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    urls_found: list[dict] = field(default_factory=list)  # {url, file}
    ips_found: list[dict] = field(default_factory=list)  # {address, file}
    emails_found: list[dict] = field(default_factory=list)  # {mail, file}
    base64_found: list[dict] = field(default_factory=list)  # {string, file}
    comments_found: list[dict] = field(default_factory=list)  # {comment, file}
    btc_found: list[dict] = field(default_factory=list)  # {address, file}
    retire_js: list[dict] = field(default_factory=list)  # vulnerable libs
    vt_results: list[dict] = field(default_factory=list)  # VT domain lookups (optional)
    files_analyzed: int = 0
    js_files: int = 0
    html_files: int = 0

    # Convenience properties
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "LOW")

    @property
    def total_score(self) -> int:
        """Additive risk score contribution from deep analysis, capped at 100."""
        pts = (
            self.critical_count * 20
            + self.high_count * 10
            + self.medium_count * 5
            + self.low_count * 1
        )
        return min(pts, 100)
