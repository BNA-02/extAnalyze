"""
CSV reporter: write summary rows for bulk analysis.
One row per extension, no nested structures.
"""

from __future__ import annotations

import csv
from pathlib import Path

from ..scoring.result import AnalysisResult

_FIELDS = [
    "ext_id",
    "name",
    "browser",
    "manifest_version",
    "version",
    "risk_level",
    "risk_score",
    "category",
    "category_confidence",
    "tpci_hit",
    "tpci_confirm_mal",
    "tpci_threat_types",
    "tpci_behavioral",
    "sentry_hit",
    "sentry_reason",
    "sentry_blocklist",
    "google_malware",
    "google_removed",
    "store_available",
    "developer",
    "install_count",
    "crx_format",
    "sha256",
    "total_permissions",
    "host_permissions",
    "has_all_urls",
    "has_critical_permission",
    "has_high_permission",
    "combo_count",
    "critical_combos",
    "high_combos",
    "code_review_high",
    "code_review_findings",
    "unexpected_permissions",
    "update_url_non_google",
    "has_unsafe_eval",
    "content_scripts_all_urls",
    "ownership_transfer",
    "catalog_source",
    "analyzed_at",
    "download_error",
    "manifest_error",
]


def write_bulk(results: list[AnalysisResult], path: Path) -> None:
    """Write all results as CSV rows."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_FIELDS)
        writer.writeheader()
        for r in results:
            writer.writerow(_flatten(r))


def write_single(result: AnalysisResult, path: Path) -> None:
    """Write a single result as a one-row CSV."""
    write_bulk([result], path)


def _flatten(r: AnalysisResult) -> dict:
    pa = r.perm_analysis
    m = r.manifest

    combo_hits = pa.combo_hits if pa else []
    critical_combos = sum(1 for c in combo_hits if c.severity == "CRITICAL")
    high_combos = sum(1 for c in combo_hits if c.severity == "HIGH")

    unexpected = []
    if pa:
        unexpected = [v.permission for v in pa.necessity_verdicts if v.verdict == "UNEXPECTED"]

    return {
        "ext_id": r.ext_id,
        "name": r.enrichment.name or "",
        "browser": r.browser,
        "manifest_version": m.manifest_version if m else "",
        "version": m.version if m else "",
        "risk_level": r.risk.level,
        "risk_score": r.risk.score,
        "category": pa.category if pa else "UNKNOWN",
        "category_confidence": pa.category_confidence if pa else "UNKNOWN",
        "tpci_hit": int(r.tpci.hit),
        "tpci_confirm_mal": r.tpci.confirm_mal if r.tpci.hit else "",
        "tpci_threat_types": "|".join(r.tpci.threat_types) if r.tpci.hit else "",
        "tpci_behavioral": r.tpci.tpci_behavioral if r.tpci.hit else "",
        "sentry_hit": int(r.sentry.hit),
        "sentry_reason": r.sentry.reason if r.sentry.hit else "",
        "sentry_blocklist": int(r.sentry.blocklist) if r.sentry.hit else "",
        "google_malware": int(r.liveness.google_malware_confirmed),
        "google_removed": int(r.liveness.store_likely_removed),
        "store_available": int(r.store.available),
        "developer": r.store.developer or "",
        "install_count": r.store.install_count or "",
        "crx_format": r.crx_format or "",
        "sha256": r.download_sha256 or "",
        "total_permissions": len(pa.permissions) if pa else "",
        "host_permissions": "|".join(pa.host_permissions) if pa else "",
        "has_all_urls": int(pa.has_all_urls) if pa else "",
        "has_critical_permission": int(pa.has_critical) if pa else "",
        "has_high_permission": int(pa.has_high) if pa else "",
        "combo_count": len(combo_hits),
        "critical_combos": critical_combos,
        "high_combos": high_combos,
        "code_review_high": r.code_review.high_count if r.code_review else "",
        "code_review_findings": len(r.code_review.findings) if r.code_review else "",
        "unexpected_permissions": "|".join(unexpected),
        "update_url_non_google": int(m.update_url_non_google) if m else "",
        "has_unsafe_eval": int(m.has_unsafe_eval) if m else "",
        "content_scripts_all_urls": int(m.content_scripts_all_urls) if m else "",
        "ownership_transfer": int(r.tpci.ownership_transfer) if r.tpci.hit else 0,
        "catalog_source": r.enrichment.source,
        "analyzed_at": r.analyzed_at.isoformat(),
        "download_error": r.download_error,
        "manifest_error": r.manifest_error,
    }
