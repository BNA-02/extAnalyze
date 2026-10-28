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

# Risk levels in order
RISK_LEVELS = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
RISK_COLORS = {
    "SAFE": "green",
    "LOW": "blue",
    "MEDIUM": "yellow",
    "HIGH": "dark_orange",
    "CRITICAL": "red",
}

# Severity -> point values for combos
COMBO_POINTS = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 5}

# Per-sensitivity point values for individual permissions
PERM_POINTS = {"CRITICAL": 8, "HIGH": 5, "MEDIUM": 2, "LOW": 0}

# Code review scoring (per distinct rule hit; total capped, VirusTotal findings excluded from the cap)
CODE_POINTS = {"CRITICAL": 15, "HIGH": 6, "MEDIUM": 2, "LOW": 0}
EXFIL_FLOW_POINTS = 10
CODE_REVIEW_CAP = 40

# Thresholds
THRESHOLDS = [
    (71, "CRITICAL"),
    (41, "HIGH"),
    (21, "MEDIUM"),
    (1, "LOW"),
    (0, "SAFE"),
]


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
) -> RiskReport:
    score = 0
    reasons: list[str] = []

    # ── Threat Intelligence ───────────────────────────────────────────────
    ti_confirmed = False

    if tpci.hit:
        confirm = tpci.confirm_mal
        if confirm == 3:
            score += 80
            reasons.append("TPCI: Google + researcher confirmed malicious (CONFIRM-MAL=3)")
            ti_confirmed = True
        elif confirm == 2:
            score += 70
            reasons.append("TPCI: Google CWS confirmed malicious (CONFIRM-MAL=2)")
            ti_confirmed = True
        elif confirm == 1:
            score += 50
            reasons.append(
                f"TPCI: Researcher confirmed malicious — {', '.join(tpci.threat_types) or 'threat type unknown'}"
            )
            ti_confirmed = True
        else:
            score += 25
            reasons.append("TPCI: Listed as under investigation (CONFIRM-MAL=0)")

        if tpci.tpci_behavioral == "malicious":
            score += 20
            reasons.append("TPCI static analysis: MALICIOUS verdict")
        elif tpci.tpci_behavioral == "suspicious":
            score += 10
            reasons.append("TPCI static analysis: SUSPICIOUS verdict")

        if tpci.ownership_transfer:
            score += 15
            reasons.append(
                "TPCI: Extension was acquired from original developer (supply-chain risk)"
            )

    if sentry.hit:
        if sentry.blocklist:
            score += 60
            reasons.append(f"Sentry: Active blocklist — {sentry.reason}")
            ti_confirmed = True
        else:
            score += 30
            reasons.append(f"Sentry: Flagged — {sentry.reason}")

        if sentry.sha256_match is False:
            reasons.append(
                "[!] Sentry SHA256 mismatch: analyzed build differs from reported version. "
                "Treat as informational — the version you downloaded may be clean or re-bundled."
            )

    if liveness.google_malware_confirmed:
        score += 70
        reasons.append("Google CRX API: _malware=true (authoritative Google malware flag)")
        ti_confirmed = True

    if liveness.store_likely_removed:
        score += 5
        source = liveness.status_xml or ""
        if source == "edge-store":
            reasons.append("Edge Add-ons: extension no longer available on Edge store")
        elif source == "firefox-amo":
            reasons.append("Firefox AMO: extension no longer available (disabled or removed)")
        elif source in ("builtin", ""):
            pass  # builtin or unknown — no meaningful removal signal
        else:
            reasons.append(
                "Google CRX API: status=noupdate — extension likely removed from CWS "
                "(99.6% probability per TPCI research)"
            )

    # ── Permission Combos ────────────────────────────────────────────────
    for combo in perm_analysis.combo_hits:
        pts = COMBO_POINTS.get(combo.severity, 0)
        score += pts
        reasons.append(f"[{combo.combo_id}] {combo.name} ({combo.severity}): {combo.threat}")

    # ── Individual permission risk ───────────────────────────────────────
    for perm_entry in perm_analysis.permissions:
        pts = PERM_POINTS.get(perm_entry.sensitivity, 0)
        score += pts

    # <all_urls> host permission — only add points if NOT already scored as a named permission
    # (avoids double-counting when <all_urls> is both normalized into host_permissions
    # and scored as a PermissionEntry)
    all_urls_in_named = any(p.name == "<all_urls>" for p in perm_analysis.permissions)
    if perm_analysis.has_all_urls and not all_urls_in_named:
        score += 8
        reasons.append("Host permission: <all_urls> — content access to every website")

    # ── Manifest signals ─────────────────────────────────────────────────
    # These are already caught by combos but add reasons if not already there
    # (combo COMBO_012 handles update_url signal)

    # ── Necessity (unexpected permissions) ───────────────────────────────
    unexpected = [v for v in perm_analysis.necessity_verdicts if v.verdict == "UNEXPECTED"]
    if unexpected:
        score += len(unexpected) * 5
        perm_names = ", ".join(v.permission for v in unexpected[:5])
        reasons.append(
            f"{len(unexpected)} permission(s) not expected for category "
            f"'{perm_analysis.category}': {perm_names}"
        )

    # ── Code review (heuristic: capped so minified libraries can't dominate) ─
    if code_review is not None:
        cr_points = 0
        for f in code_review.findings:
            if f.rule_id == "CR-DEEP-VT":
                # External reputation signal: scored outside the code-review cap
                score += CODE_POINTS.get(f.severity, 0)
                reasons.append(f"[{f.rule_id}] {f.name}: {f.description}")
                continue
            cr_points += CODE_POINTS.get(f.severity, 0)
            if f.severity in ("CRITICAL", "HIGH"):
                reasons.append(f"[{f.rule_id}] {f.name}: {f.description} ({f.count} occurrence(s))")
        for flow_file in code_review.exfil_flows:
            cr_points += EXFIL_FLOW_POINTS
            reasons.append(
                f"Possible data exfiltration flow: {flow_file} reads sensitive data "
                "and has an outbound network channel"
            )
        score += min(cr_points, CODE_REVIEW_CAP)

    # ── Shortcircuit: TI confirmed -> minimum HIGH ───────────────────────
    if ti_confirmed and score < 41:
        score = 41
        reasons.insert(0, "[!] TI confirmed malicious — minimum score raised to HIGH")

    # ── Determine level ──────────────────────────────────────────────────
    level = "SAFE"
    for threshold, lvl in THRESHOLDS:
        if score >= threshold:
            level = lvl
            break

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
