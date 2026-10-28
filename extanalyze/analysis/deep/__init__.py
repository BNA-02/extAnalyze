"""
--deep extras. Adds three things on top of the always-on code review:

1. Entropy analysis, static deobfuscation (decoded strings are re-scanned) and an AST
   data-flow check (sensitive data reaching network calls)
2. RetireJS: known-vulnerable bundled JavaScript libraries
3. VirusTotal domain reputation lookups (only when VIRUSTOTAL_API_KEY is set)

Results are merged into the same CodeReviewResult, so scoring and reporting treat them
like any other finding.
"""

from __future__ import annotations

import sys

from ..code_review import (
    CodeFinding,
    CodeReviewResult,
    Location,
    iter_sources,
    record,
    sort_findings,
)
from . import deobfuscate, flows
from .retire_js import scan_file as retire_scan
from .vt_lookup import lookup_domains

_RETIRE_MAX_BYTES = 1_000_000  # larger files are almost always app bundles
_VT_MAX_DOMAINS = 20  # free tier allows 4 lookups/min
_SEVERITY_MAP = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}


def run_deep_analysis(extract_result, review: CodeReviewResult) -> None:
    """Run the --deep extras and merge results into `review` in place."""
    tmp_dir = extract_result.tmp_dir
    findings: dict[str, CodeFinding] = {f.rule_id: f for f in review.findings}

    print(
        "[deep] Running entropy/deobfuscation, RetireJS and VirusTotal extras...", file=sys.stderr
    )

    # 1. Entropy + deobfuscation
    hidden = deobfuscate.analyze(tmp_dir, extract_result.files, findings)

    # 1b. AST data-flow check (sensitive source to network sink)
    flows.analyze(iter_sources(tmp_dir, extract_result.files), findings)

    # 2. RetireJS over all JS files (vendor directories included)
    for rel in extract_result.js_files:
        path = tmp_dir / rel
        try:
            if not path.is_file() or path.is_symlink() or path.stat().st_size > _RETIRE_MAX_BYTES:
                continue
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for hit in retire_scan(rel, content):
            review.retire_js.append(hit)
            _retire_finding(findings, hit)

    # 3. VirusTotal (domains from code plus domains found in decoded strings)
    domains = list(dict.fromkeys([*review.external_domains, *hidden]))[:_VT_MAX_DOMAINS]
    review.vt_results = lookup_domains(domains)
    for vt in review.vt_results:
        malicious, suspicious = vt.get("malicious", 0), vt.get("suspicious", 0)
        if malicious > 0 or suspicious > 0:
            record(
                findings,
                f"CR-DEEP-VT|{vt['domain']}",
                rule_id="CR-DEEP-VT",
                name=f"VirusTotal flags {vt['domain']}",
                category="NETWORK",
                severity="CRITICAL" if malicious > 2 else "HIGH",
                description=(
                    f"{malicious} engine(s) report the domain malicious, {suspicious} suspicious."
                ),
                count=1,
                location=Location("(network)", 0, vt["domain"]),
            )

    for d in hidden:
        if d not in review.external_domains and len(review.external_domains) < 50:
            review.external_domains.append(d)

    review.findings = sort_findings(findings)
    review.deep = True


def _retire_finding(findings: dict[str, CodeFinding], hit: dict) -> None:
    component = f"{hit['component']} {hit['version']}"
    for vuln in hit.get("vulnerabilities", []):
        severity = _SEVERITY_MAP.get(str(vuln.get("severity", "")).lower(), "MEDIUM")
        cves = ", ".join(vuln.get("identifiers", {}).get("CVE", [])) or "no CVE"
        record(
            findings,
            f"CR-DEEP-RETIRE|{component}|{severity}",
            rule_id="CR-DEEP-RETIRE",
            name=f"Vulnerable library: {component}",
            category="VULN",
            severity=severity,
            description=f"Known vulnerabilities ({cves}); detected via {hit['detection']}.",
            count=1,
            location=Location(hit["file"], 0, f"{hit['component']}@{hit['version']}"),
        )
