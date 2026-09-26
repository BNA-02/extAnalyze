"""
__init__.py — Deep static analysis orchestrator.

Entry point: run_deep_analysis(extract_result, manifest) → DeepAnalysisResult
"""

from __future__ import annotations

import re
import sys

from extanalyze.core.extractor import ExtractResult
from extanalyze.core.manifest_parser import ExtensionManifest

from .csp_analyzer import analyze_csp
from .findings import DeepAnalysisResult, Finding
from .intel_extractor import extract_intel
from .js_analyzer import analyze_unit
from .retire_js import scan_file as retire_scan
from .source_extractor import extract_source_units
from .vt_lookup import lookup_domains

_DOMAIN_FROM_URL_RE = re.compile(r"^(?:https?://)?(?:[^@/\n]+@)?(?:www\.)?([^:/?#\n]+)")


def run_deep_analysis(
    extract_result: ExtractResult,
    manifest: ExtensionManifest,
) -> DeepAnalysisResult:
    """
    Full deep static analysis pipeline.

    Steps:
    1. Extract all JS source units (standalone .js files + inline <script> blocks)
    2. Run JS pattern rules against each unit (eval, fetch, atob, secrets, etc.)
    3. Analyze Content Security Policy
    4. Extract intel from all files (URLs, IPs, emails, base64, comments, BTC)
    5. Run RetireJS scan on all .js files for known-vulnerable libraries
    6. Optional VirusTotal domain lookups (if VIRUSTOTAL_API_KEY is set)
    7. Assemble and return DeepAnalysisResult
    """
    result = DeepAnalysisResult()
    tmp_dir = extract_result.tmp_dir
    all_files = extract_result.files

    print("[deep] Starting static analysis...", file=sys.stderr)

    # ── Step 1+2: JS source extraction + pattern analysis ─────────────────────
    source_units = extract_source_units(tmp_dir, all_files)
    result.js_files = sum(1 for u in source_units if u.origin == "js_file")
    result.html_files = sum(1 for u in source_units if u.origin == "inline_script")
    result.files_analyzed = len(all_files)

    all_findings: list[Finding] = []
    for unit in source_units:
        all_findings.extend(analyze_unit(unit))

    # ── Step 3: CSP analysis ──────────────────────────────────────────────────
    csp = getattr(manifest, "content_security_policy", None)
    csp_findings = analyze_csp(csp, manifest.manifest_version)
    all_findings.extend(csp_findings)

    result.findings = all_findings

    # ── Step 4: Intel extraction ──────────────────────────────────────────────
    intel = extract_intel(tmp_dir, all_files)
    result.urls_found = intel["urls"]
    result.ips_found = intel["ips"]
    result.emails_found = intel["emails"]
    result.base64_found = intel["base64"]
    result.comments_found = intel["comments"]
    result.btc_found = intel["btc"]

    # ── Step 5: RetireJS ──────────────────────────────────────────────────────
    retire_hits: list[dict] = []
    _RETIRE_MAX_BYTES = 1_000_000  # 1 MB — larger files are almost always app bundles
    for rel_path in extract_result.js_files:
        path = tmp_dir / rel_path
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > _RETIRE_MAX_BYTES:
                continue
            content = path.read_text(encoding="utf-8", errors="replace")
            hits = retire_scan(rel_path, content)
            retire_hits.extend(hits)
        except OSError:
            continue

    result.retire_js = retire_hits

    # Convert RetireJS hits to Findings for scoring
    for hit in retire_hits:
        vulns = hit.get("vulnerabilities", [])
        for vuln in vulns:
            severity_map = {
                "critical": "CRITICAL",
                "high": "HIGH",
                "medium": "MEDIUM",
                "low": "LOW",
            }
            sev = severity_map.get(vuln.get("severity", "").lower(), "MEDIUM")
            cves = vuln.get("identifiers", {}).get("CVE", [])
            cve_str = ", ".join(cves) if cves else "no CVE"
            all_findings.append(
                Finding(
                    rule_id="DEEP_RETIREJS",
                    category="VULN",
                    severity=sev,
                    confidence="HIGH",
                    title=f"Vulnerable library: {hit['component']} {hit['version']}",
                    description=(
                        f"{hit['component']} v{hit['version']} has known vulnerabilities "
                        f"({cve_str}). Detected via {hit['detection']}."
                    ),
                    file=hit["file"],
                    line=None,
                    snippet=f"{hit['component']}@{hit['version']}",
                )
            )

    # ── Step 6: Optional VirusTotal lookups ───────────────────────────────────
    unique_domains: list[str] = []
    seen: set[str] = set()
    for entry in result.urls_found:
        url = entry["url"]
        m = _DOMAIN_FROM_URL_RE.match(url)
        if m:
            domain = m.group(1).lower().rstrip(".")
            if domain and domain not in seen:
                seen.add(domain)
                unique_domains.append(domain)

    vt_results = lookup_domains(unique_domains)
    result.vt_results = vt_results

    # Add findings for VT-flagged domains
    for vt in vt_results:
        if vt.get("malicious", 0) > 0 or vt.get("suspicious", 0) > 0:
            severity = "CRITICAL" if vt["malicious"] > 2 else "HIGH"
            result.findings.append(
                Finding(
                    rule_id="DEEP_VT_001",
                    category="NETWORK",
                    severity=severity,
                    confidence="HIGH",
                    title=f"VirusTotal: {vt['domain']} flagged as malicious",
                    description=(
                        f"Domain {vt['domain']} detected by {vt['malicious']} VT engines "
                        f"as malicious, {vt['suspicious']} as suspicious."
                    ),
                    file="(network)",
                    line=None,
                    snippet=vt["domain"],
                )
            )

    print(
        f"[deep] Done — {len(result.findings)} findings, {len(source_units)} source units analyzed",
        file=sys.stderr,
    )
    return result
