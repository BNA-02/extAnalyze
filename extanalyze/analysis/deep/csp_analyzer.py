"""
csp_analyzer.py — Content Security Policy strength analysis.
Reads CSP from manifest.json and flags dangerous/missing directives.
"""

from __future__ import annotations

import re

from .findings import Finding


def analyze_csp(
    csp_string: str | None, manifest_version: int, file: str = "manifest.json"
) -> list[Finding]:
    """
    Analyze the extension's Content Security Policy.

    MV2: CSP is optional but recommended. Missing CSP allows eval() and inline scripts.
    MV3: CSP is enforced by Chrome — unsafe-eval and remote scripts are blocked regardless.
         We still flag misconfigurations (unsafe-inline, broad connect-src).
    """
    findings: list[Finding] = []

    if not csp_string:
        if manifest_version == 2:
            findings.append(
                Finding(
                    rule_id="DEEP_CSP_001",
                    category="VULN",
                    severity="MEDIUM",
                    confidence="HIGH",
                    title="Missing Content Security Policy (MV2)",
                    description=(
                        "No content_security_policy in manifest.json. "
                        "MV2 extensions without a CSP allow eval() and inline scripts "
                        "in extension pages — increases attack surface if any input reaches eval()."
                    ),
                    file=file,
                    line=None,
                    snippet="",
                )
            )
        # MV3 has a default restrictive CSP enforced by Chrome — not flagged
        return findings

    csp = csp_string.lower()

    # unsafe-eval — allows eval(), new Function(), etc.
    if "unsafe-eval" in csp:
        findings.append(
            Finding(
                rule_id="DEEP_CSP_002",
                category="EXEC",
                severity="CRITICAL",
                confidence="HIGH",
                title="CSP allows unsafe-eval",
                description=(
                    "content_security_policy contains 'unsafe-eval' — eval(), new Function(), "
                    "and similar APIs are permitted in extension pages. "
                    "This negates the main XSS protection of CSP. "
                    "In MV3 this is rejected by Chrome."
                ),
                file=file,
                line=None,
                snippet=csp_string[:120],
            )
        )

    # unsafe-inline scripts
    if "unsafe-inline" in csp and "script-src" in csp:
        findings.append(
            Finding(
                rule_id="DEEP_CSP_003",
                category="VULN",
                severity="HIGH",
                confidence="HIGH",
                title="CSP allows unsafe-inline scripts",
                description=(
                    "script-src contains 'unsafe-inline' — inline <script> blocks "
                    "and event handlers are permitted in extension pages. "
                    "Reduces protection against XSS in extension UI pages."
                ),
                file=file,
                line=None,
                snippet=csp_string[:120],
            )
        )

    # Wildcard or http: in script-src
    if re.search(r"script-src[^;]*(?:\*|http:)", csp):
        findings.append(
            Finding(
                rule_id="DEEP_CSP_004",
                category="REMOTE_LOAD",
                severity="CRITICAL",
                confidence="HIGH",
                title="CSP script-src allows remote or wildcard scripts",
                description=(
                    "script-src allows loading scripts from '*' or 'http:' — "
                    "any web server can inject code into extension pages. "
                    "Remote script loading is the primary C2 vector for MV2 extensions."
                ),
                file=file,
                line=None,
                snippet=csp_string[:120],
            )
        )

    # Wildcard in connect-src
    if re.search(r"connect-src[^;]*\*", csp):
        findings.append(
            Finding(
                rule_id="DEEP_CSP_005",
                category="EXFIL",
                severity="HIGH",
                confidence="HIGH",
                title="CSP connect-src allows connections to any host",
                description=(
                    "connect-src '*' allows the extension to make network requests "
                    "to any URL from extension pages — no restriction on exfiltration targets."
                ),
                file=file,
                line=None,
                snippet=csp_string[:120],
            )
        )

    return findings
