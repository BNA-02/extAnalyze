"""
Permission analysis: score each permission against the taxonomy,
detect dangerous combos, check necessity vs category baseline.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ..core.manifest_parser import ExtensionManifest, get_all_permissions

_DATA_DIR = Path(__file__).parent.parent / "data"

# Loaded once at module import
with open(_DATA_DIR / "permissions_taxonomy.json", encoding="utf-8") as _f:
    TAXONOMY: dict[str, dict] = json.load(_f)

with open(_DATA_DIR / "danger_combos.json", encoding="utf-8") as _f:
    COMBOS: list[dict] = json.load(_f)

with open(_DATA_DIR / "category_baselines.json", encoding="utf-8") as _f:
    BASELINES: dict[str, dict] = json.load(_f)


@dataclass
class PermissionEntry:
    name: str
    risk_score: int  # 1-10
    sensitivity: str  # LOW / MEDIUM / HIGH / CRITICAL
    description: str
    mv2_abuse: str
    mv3_abuse: str
    mv2_only: bool
    mv3_blocked: bool  # True = doesn't exist in MV3
    data_exfil_vector: bool
    c2_vector: bool
    present_in_manifest: bool
    is_host_permission: bool  # True if it's a URL pattern
    known: bool  # False = not in taxonomy (new/unknown permission)


@dataclass
class ComboHit:
    combo_id: str
    name: str
    severity: str
    threat: str
    matched_permissions: list[str]
    mv_note: str
    mv2_only: bool
    mv3_only: bool


@dataclass
class NecessityVerdict:
    permission: str
    expected: bool
    borderline: bool
    verdict: str  # "NEEDED", "BORDERLINE", "UNEXPECTED"
    explanation: str


@dataclass
class HostScopeAssessment:
    """Evaluates whether host_permissions are scoped or broad."""

    is_broad: bool  # True if <all_urls> or functionally equivalent
    domain_count: int  # number of distinct domains
    domains: list[str]  # list of host permission patterns
    scope_label: str  # "BROAD", "SCOPED", "MINIMAL"
    risk_note: str  # human-readable explanation


@dataclass
class PermissionAnalysis:
    permissions: list[PermissionEntry]
    host_permissions: list[str]  # raw URL patterns (not in taxonomy)
    has_all_urls: bool
    host_scope: HostScopeAssessment  # scope assessment for host permissions
    total_risk_score: int
    has_critical: bool
    has_high: bool
    combo_hits: list[ComboHit]
    necessity_verdicts: list[NecessityVerdict]
    category: str
    category_confidence: str  # HIGH / MEDIUM / LOW / UNKNOWN


def analyze(
    manifest: ExtensionManifest, category: str = "UNKNOWN", category_confidence: str = "UNKNOWN"
) -> PermissionAnalysis:
    """Full permission analysis for a parsed manifest."""

    all_perms = set(get_all_permissions(manifest))
    named_perms = set(manifest.permissions + manifest.optional_permissions)
    host_perms = set(manifest.host_permissions + manifest.optional_host_permissions)

    has_all_urls = "<all_urls>" in host_perms or "<all_urls>" in all_perms

    # Score each NAMED permission only — no URL patterns here
    perm_entries: list[PermissionEntry] = []
    for perm in sorted(named_perms):
        entry = _score_permission(perm, manifest.manifest_version, is_host=False)
        perm_entries.append(entry)

    # Host permissions are stored separately — NOT added to perm_entries
    # They appear in pa.host_permissions and are rendered in their own section
    # by the reporter, with host scope assessment logic

    total_score = sum(e.risk_score for e in perm_entries)
    has_critical = any(e.sensitivity == "CRITICAL" for e in perm_entries)
    has_high = any(e.sensitivity in ("CRITICAL", "HIGH") for e in perm_entries)

    # Detect manifest signals for combo matching
    manifest_signals = _collect_signals(manifest)

    # Combo detection — pass manifest so signals can include contextual values
    combo_hits = _detect_combos(all_perms, manifest.manifest_version, manifest_signals, manifest)

    # Host scope assessment
    host_scope = _assess_host_scope(list(host_perms), has_all_urls)

    # Necessity mapping
    necessity_verdicts = []
    if category != "UNKNOWN":
        necessity_verdicts = _map_necessity(perm_entries, category)

    return PermissionAnalysis(
        permissions=perm_entries,
        host_permissions=sorted(host_perms),
        has_all_urls=has_all_urls,
        host_scope=host_scope,
        total_risk_score=total_score,
        has_critical=has_critical,
        has_high=has_high,
        combo_hits=combo_hits,
        necessity_verdicts=necessity_verdicts,
        category=category,
        category_confidence=category_confidence,
    )


def _score_permission(perm: str, mv: int, is_host: bool = False) -> PermissionEntry:
    info = TAXONOMY.get(perm)
    if info is None:
        # Unknown permission - assign minimal score but flag it
        return PermissionEntry(
            name=perm,
            risk_score=1,
            sensitivity="LOW",
            description="Unknown/undocumented permission",
            mv2_abuse="Unknown",
            mv3_abuse="Unknown",
            mv2_only=False,
            mv3_blocked=False,
            data_exfil_vector=False,
            c2_vector=False,
            present_in_manifest=True,
            is_host_permission=is_host,
            known=False,
        )

    # Adjust risk score for manifest version context
    risk = info["risk_score"]
    if info.get("mv2_only") and mv == 3:
        # Permission shouldn't exist in MV3 - flag anomaly
        risk = min(risk + 2, 10)
    if info.get("mv3_blocked") and mv == 2:
        risk = info["risk_score"]  # full risk in MV2

    return PermissionEntry(
        name=perm,
        risk_score=risk,
        sensitivity=info["sensitivity"],
        description=info["description"],
        mv2_abuse=info["mv2_abuse"],
        mv3_abuse=info["mv3_abuse"],
        mv2_only=info.get("mv2_only", False),
        mv3_blocked=info.get("mv3_blocked", False),
        data_exfil_vector=info.get("data_exfil_vector", False),
        c2_vector=info.get("c2_vector", False),
        present_in_manifest=True,
        is_host_permission=is_host,
        known=True,
    )


def _collect_signals(manifest: ExtensionManifest) -> set[str]:
    """Collect manifest-level signals for combo matching (non-permission based)."""
    signals = set()
    if manifest.update_url_non_google:
        signals.add("update_url_non_google")
    if manifest.content_scripts_all_urls:
        signals.add("content_scripts_all_urls")
    if manifest.has_unsafe_eval:
        signals.add("unsafe_eval_in_csp")
    if manifest.oauth2:
        signals.add("oauth2_present")
    if manifest.externally_connectable:
        signals.add("externally_connectable")
    return signals


def _detect_combos(
    all_perms: set[str],
    mv: int,
    signals: set[str],
    manifest: ExtensionManifest | None = None,
) -> list[ComboHit]:
    hits: list[ComboHit] = []

    for combo in COMBOS:
        # Version gating
        if combo.get("mv2_only") and mv == 3:
            continue
        if combo.get("mv3_only") and mv == 2:
            continue

        match_mode = combo.get("match_mode", "all")
        required_perms = combo.get("permissions", [])
        required_signals = combo.get("manifest_signals", [])

        # Signal-based combo
        if match_mode == "signals":
            matched = [s for s in required_signals if s in signals]
            if not matched:
                continue

            # For update_url_non_google, show the actual URL so the report is actionable
            matched_display = list(matched)
            if "update_url_non_google" in matched and manifest and manifest.update_url:
                matched_display = [f"update_url → {manifest.update_url}"]

            hits.append(
                ComboHit(
                    combo_id=combo["id"],
                    name=combo["name"],
                    severity=combo["severity"],
                    threat=combo["threat"],
                    matched_permissions=matched_display,
                    mv_note=combo.get("mv3_note" if mv == 3 else "mv2_note", ""),
                    mv2_only=combo.get("mv2_only", False),
                    mv3_only=combo.get("mv3_only", False),
                )
            )
            continue

        # Permission-based combo
        matched_perms = [p for p in required_perms if p in all_perms]

        if match_mode == "all" and len(matched_perms) == len(required_perms):
            hit = True
        elif match_mode == "any" and len(matched_perms) > 0:
            hit = True
        else:
            hit = False

        if hit:
            mv_note_key = "mv3_note" if mv == 3 else "mv2_note"
            hits.append(
                ComboHit(
                    combo_id=combo["id"],
                    name=combo["name"],
                    severity=combo["severity"],
                    threat=combo["threat"],
                    matched_permissions=matched_perms or required_perms,
                    mv_note=combo.get(mv_note_key, ""),
                    mv2_only=combo.get("mv2_only", False),
                    mv3_only=combo.get("mv3_only", False),
                )
            )

    # Sort: CRITICAL first
    _severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    hits.sort(key=lambda h: _severity_order.get(h.severity, 9))
    return hits


def _map_necessity(perm_entries: list[PermissionEntry], category: str) -> list[NecessityVerdict]:
    baseline = BASELINES.get(category, {})
    expected = set(baseline.get("expected_permissions", []))
    borderline = set(baseline.get("borderline_permissions", []))
    verdicts = []

    for entry in perm_entries:
        perm = entry.name
        if perm in expected:
            verdict = "NEEDED"
            explanation = f"Expected for {category} extensions"
        elif perm in borderline:
            verdict = "BORDERLINE"
            explanation = f"Sometimes used by {category} extensions but not always necessary"
        else:
            verdict = "UNEXPECTED"
            explanation = f"Not typically required for {category} extensions"

        verdicts.append(
            NecessityVerdict(
                permission=perm,
                expected=perm in expected,
                borderline=perm in borderline,
                verdict=verdict,
                explanation=explanation,
            )
        )

    return verdicts


def _assess_host_scope(host_perms: list[str], has_all_urls: bool) -> HostScopeAssessment:
    """
    Classify host permission scope and produce a risk note.
    BROAD:   <all_urls> or wildcard patterns covering any site
    SCOPED:  A defined list of specific domains (positive signal)
    MINIMAL: 0-2 domains (very limited surface)
    NONE:    No host permissions
    """
    if not host_perms:
        return HostScopeAssessment(
            is_broad=False,
            domain_count=0,
            domains=[],
            scope_label="NONE",
            risk_note="No host permissions declared",
        )

    if has_all_urls:
        return HostScopeAssessment(
            is_broad=True,
            domain_count=len(host_perms),
            domains=host_perms,
            scope_label="BROAD",
            risk_note=(
                "<all_urls> grants access to every website the user visits — "
                "broadest possible host permission scope"
            ),
        )

    broad_patterns = {"*://*/*", "http://*/*", "https://*/*", "file://*/*"}
    if any(p in broad_patterns for p in host_perms):
        return HostScopeAssessment(
            is_broad=True,
            domain_count=len(host_perms),
            domains=host_perms,
            scope_label="BROAD",
            risk_note="Wildcard host permission is functionally equivalent to <all_urls>",
        )

    n = len(host_perms)
    if n <= 2:
        note = f"Host access limited to {n} domain(s) — very narrow scope: " + ", ".join(host_perms)
        label = "MINIMAL"
    else:
        preview = ", ".join(host_perms[:5])
        more = f" and {n - 5} more" if n > 5 else ""
        note = (
            f"Host access scoped to {n} specific domain(s) — better than <all_urls>. "
            f"Verify domains match the extension's stated purpose. "
            f"Domains: {preview}{more}"
        )
        label = "SCOPED"

    return HostScopeAssessment(
        is_broad=False, domain_count=n, domains=host_perms, scope_label=label, risk_note=note
    )
