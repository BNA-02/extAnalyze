"""
Pure scoring: a flat `Signals` record in, a score out.

`aggregate()` builds Signals from live analysis objects; the crx-census project stores the
same Signals per extension so scores can be recomputed offline with different weights
without downloading anything again. This module is the only place score arithmetic lives.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .config import ScoringConfig, default_config


@dataclass
class Signals:
    # Threat intelligence
    tpci_hit: bool = False
    tpci_confirm: int = 0
    tpci_behavioral: str = ""
    tpci_ownership_transfer: bool = False
    sentry_hit: bool = False
    sentry_blocklist: bool = False
    google_malware: bool = False
    store_removed: bool = False
    # Manifest / permissions
    combos: list[list[str]] = field(default_factory=list)  # [[combo_id, severity], ...]
    perm_sensitivities: list[str] = field(default_factory=list)
    all_urls_unscored: bool = False  # <all_urls> present but not already a scored permission
    unexpected_permissions: int = 0
    # Code review: [[rule_id, severity, count], ...] (includes CR-DEEP-* and CR-RT-*)
    findings: list[list] = field(default_factory=list)
    exfil_flows: int = 0

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> Signals:
        known = cls.__dataclass_fields__
        return cls(**{k: v for k, v in d.items() if k in known})


def _finding_points(rule_id: str, severity: str, cfg: ScoringConfig, table: dict[str, int]) -> int:
    if rule_id in cfg.rule_points:
        return cfg.rule_points[rule_id]
    return table.get(severity, 0)


@dataclass(frozen=True)
class ScoreResult:
    score: int
    ti_confirmed: bool
    raised_to_minimum: bool  # a TI-confirmed extension would have scored below the minimum


def score_signals(sig: Signals, cfg: ScoringConfig | None = None) -> ScoreResult:
    """Score a Signals record with the given (or default) weights."""
    cfg = cfg or default_config()
    ti = cfg.ti
    score = 0
    confirmed = False

    if sig.tpci_hit:
        score += ti["tpci_confirm"].get(str(sig.tpci_confirm), 0)
        confirmed |= sig.tpci_confirm >= 1
        score += ti["tpci_behavioral"].get(sig.tpci_behavioral, 0)
        if sig.tpci_ownership_transfer:
            score += ti["tpci_ownership_transfer"]
    if sig.sentry_hit:
        if sig.sentry_blocklist:
            score += ti["sentry_blocklist"]
            confirmed = True
        else:
            score += ti["sentry_flagged"]
    if sig.google_malware:
        score += ti["google_malware"]
        confirmed = True
    if sig.store_removed:
        score += ti["store_removed"]

    for _combo_id, severity in sig.combos:
        score += cfg.combo_points.get(severity, 0)
    score += sum(cfg.perm_points.get(s, 0) for s in sig.perm_sensitivities)
    if sig.all_urls_unscored:
        score += cfg.all_urls_points
    score += sig.unexpected_permissions * cfg.unexpected_permission_points

    static_points = 0
    runtime_points = 0
    for rule_id, severity, _count in sig.findings:
        if rule_id.startswith("CR-RT-"):
            runtime_points += _finding_points(rule_id, severity, cfg, cfg.rt_points)
        elif rule_id == "CR-DEEP-VT":
            score += _finding_points(rule_id, severity, cfg, cfg.code_points)  # outside the cap
        else:
            static_points += _finding_points(rule_id, severity, cfg, cfg.code_points)
    static_points += sig.exfil_flows * cfg.exfil_flow_points
    score += min(static_points, cfg.code_review_cap) + min(runtime_points, cfg.dynamic_cap)

    raised = confirmed and score < ti["confirmed_minimum_score"]
    if raised:
        score = ti["confirmed_minimum_score"]
    return ScoreResult(score, confirmed, raised)


def signals_from(tpci, sentry, liveness, perm_analysis, code_review=None) -> Signals:
    """Build Signals from live analysis objects."""
    all_urls_in_named = any(p.name == "<all_urls>" for p in perm_analysis.permissions)
    sig = Signals(
        tpci_hit=bool(tpci.hit),
        tpci_confirm=int(tpci.confirm_mal or 0) if tpci.hit else 0,
        tpci_behavioral=tpci.tpci_behavioral if tpci.hit else "",
        tpci_ownership_transfer=bool(tpci.hit and tpci.ownership_transfer),
        sentry_hit=bool(sentry.hit),
        sentry_blocklist=bool(sentry.hit and sentry.blocklist),
        google_malware=bool(liveness.google_malware_confirmed),
        store_removed=bool(liveness.store_likely_removed),
        combos=[[c.combo_id, c.severity] for c in perm_analysis.combo_hits],
        perm_sensitivities=[p.sensitivity for p in perm_analysis.permissions],
        all_urls_unscored=bool(perm_analysis.has_all_urls and not all_urls_in_named),
        unexpected_permissions=sum(
            1 for v in perm_analysis.necessity_verdicts if v.verdict == "UNEXPECTED"
        ),
    )
    if code_review is not None:
        sig.findings = [[f.rule_id, f.severity, f.count] for f in code_review.findings]
        sig.exfil_flows = len(code_review.exfil_flows)
    return sig
