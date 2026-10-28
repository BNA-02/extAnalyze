"""
Risk aggregator: combine TI signals, permission scores, and combo hits into a final verdict.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..analysis.code_review import CodeReviewResult
from ..analysis.permissions import PermissionAnalysis
from ..core.store_meta import LivenessResult
from ..intel.sentry import SentryResult
from ..intel.tpci import TPCIResult
from .config import ScoringConfig, default_config
from .signals import score_signals, signals_from

# Risk levels in order
RISK_LEVELS = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
RISK_COLORS = {
    "SAFE": "green",
    "LOW": "blue",
    "MEDIUM": "yellow",
    "HIGH": "dark_orange",
    "CRITICAL": "red",
}

_CFG = default_config()

# Kept as module attributes for callers and tests; values come from data/scoring.json
COMBO_POINTS = _CFG.combo_points
PERM_POINTS = _CFG.perm_points
CODE_POINTS = _CFG.code_points
RT_POINTS = _CFG.rt_points
EXFIL_FLOW_POINTS = _CFG.exfil_flow_points
CODE_REVIEW_CAP = _CFG.code_review_cap
DYNAMIC_CAP = _CFG.dynamic_cap
THRESHOLDS = _CFG.thresholds


@dataclass
class RiskReport:
    score: int
    level: str  # SAFE / LOW / MEDIUM / HIGH / CRITICAL
    color: str
    reasons: list[str]

    # TI breakdown
    tpci_hit: bool
    sentry_hit: bool
    google_malware: bool
    google_removed: bool

    # Shortcircuit flag: TI confirmed -> skip score math
    ti_confirmed_malicious: bool


def aggregate(
    tpci: TPCIResult,
    sentry: SentryResult,
    liveness: LivenessResult,
    perm_analysis: PermissionAnalysis,
    code_review: CodeReviewResult | None = None,
    cfg: ScoringConfig | None = None,
) -> RiskReport:
    """Score via signals.score_signals and explain it. No score arithmetic lives here."""
    cfg = cfg or default_config()
    result = score_signals(signals_from(tpci, sentry, liveness, perm_analysis, code_review), cfg)
    score, ti_confirmed = result.score, result.ti_confirmed
    reasons = _reasons(tpci, sentry, liveness, perm_analysis, code_review)
    if result.raised_to_minimum:
        reasons.insert(0, "[!] TI confirmed malicious - minimum score raised to HIGH")
    level = cfg.level_for(score)
    return RiskReport(
        score=score,
        level=level,
        color=RISK_COLORS[level],
        reasons=reasons,
        tpci_hit=tpci.hit,
        sentry_hit=sentry.hit,
        google_malware=liveness.google_malware_confirmed,
        google_removed=liveness.store_likely_removed,
        ti_confirmed_malicious=ti_confirmed,
    )


def _reasons(tpci, sentry, liveness, perm_analysis, code_review) -> list[str]:
    reasons: list[str] = []
    if tpci.hit:
        confirm = tpci.confirm_mal
        if confirm == 3:
            reasons.append("TPCI: Google + researcher confirmed malicious (CONFIRM-MAL=3)")
        elif confirm == 2:
            reasons.append("TPCI: Google CWS confirmed malicious (CONFIRM-MAL=2)")
        elif confirm == 1:
            reasons.append(
                "TPCI: Researcher confirmed malicious - "
                f"{', '.join(tpci.threat_types) or 'threat type unknown'}"
            )
        else:
            reasons.append("TPCI: Listed as under investigation (CONFIRM-MAL=0)")
        if tpci.tpci_behavioral == "malicious":
            reasons.append("TPCI static analysis: MALICIOUS verdict")
        elif tpci.tpci_behavioral == "suspicious":
            reasons.append("TPCI static analysis: SUSPICIOUS verdict")
        if tpci.ownership_transfer:
            reasons.append(
                "TPCI: Extension was acquired from original developer (supply-chain risk)"
            )
    if sentry.hit:
        if sentry.blocklist:
            reasons.append(f"Sentry: Active blocklist - {sentry.reason}")
        else:
            reasons.append(f"Sentry: Flagged - {sentry.reason}")
        if sentry.sha256_match is False:
            reasons.append(
                "[!] Sentry SHA256 mismatch: analyzed build differs from reported version. "
                "Treat as informational - the version you downloaded may be clean or re-bundled."
            )
    if liveness.google_malware_confirmed:
        reasons.append("Google CRX API: _malware=true (authoritative Google malware flag)")
    if liveness.store_likely_removed:
        source = liveness.status_xml or ""
        if source == "edge-store":
            reasons.append("Edge Add-ons: extension no longer available on Edge store")
        elif source == "firefox-amo":
            reasons.append("Firefox AMO: extension no longer available (disabled or removed)")
        elif source not in ("builtin", ""):
            reasons.append(
                "Google CRX API: status=noupdate - extension likely removed from CWS "
                "(99.6% probability per TPCI research)"
            )
    for combo in perm_analysis.combo_hits:
        reasons.append(f"[{combo.combo_id}] {combo.name} ({combo.severity}): {combo.threat}")
    all_urls_in_named = any(p.name == "<all_urls>" for p in perm_analysis.permissions)
    if perm_analysis.has_all_urls and not all_urls_in_named:
        reasons.append("Host permission: <all_urls> - content access to every website")
    unexpected = [v for v in perm_analysis.necessity_verdicts if v.verdict == "UNEXPECTED"]
    if unexpected:
        perm_names = ", ".join(v.permission for v in unexpected[:5])
        reasons.append(
            f"{len(unexpected)} permission(s) not expected for category "
            f"'{perm_analysis.category}': {perm_names}"
        )
    if code_review is not None:
        for f in code_review.findings:
            if f.rule_id.startswith("CR-RT-") or f.rule_id == "CR-DEEP-VT":
                reasons.append(f"[{f.rule_id}] {f.name}: {f.description}")
            elif f.severity in ("CRITICAL", "HIGH"):
                reasons.append(f"[{f.rule_id}] {f.name}: {f.description} ({f.count} occurrence(s))")
        for flow_file in code_review.exfil_flows:
            reasons.append(
                f"Possible data exfiltration flow: {flow_file} reads sensitive data "
                "and has an outbound network channel"
            )
    return reasons
