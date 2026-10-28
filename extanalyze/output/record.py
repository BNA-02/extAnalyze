"""
Flat, versioned feature record per analysed extension.

Built for bulk studies (the crx-census project): compact, free of code snippets and personal
data, and complete enough to recompute the score offline with different weights
(`rescore`). Contains no extension source and no secrets.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from .. import __version__
from ..analysis import code_review
from ..scoring.config import ScoringConfig, default_config
from ..scoring.result import AnalysisResult  # noqa: F401  (re-exported for type hints)
from ..scoring.signals import Signals, score_signals, signals_from

RECORD_SCHEMA = 1
_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def ruleset_hash() -> str:
    """Hash of everything that can change a finding: code-review rules and the data files."""
    h = hashlib.sha256()
    for r in code_review.RULES:
        h.update(f"{r.rule_id}|{r.severity}|{r.pattern.pattern}|{r.html_only}\n".encode())
    for name in ("permissions_taxonomy.json", "danger_combos.json", "category_baselines.json"):
        h.update((_DATA_DIR / name).read_bytes())
    return h.hexdigest()[:16]


def scoring_hash(cfg: ScoringConfig | None = None) -> str:
    cfg = cfg or default_config()
    return hashlib.sha256(json.dumps(cfg.raw, sort_keys=True).encode()).hexdigest()[:16]


def to_record(result, *, now: datetime | None = None) -> dict:
    """Convert an AnalysisResult into a flat, JSON-safe record."""
    m = result.manifest
    pa = result.perm_analysis
    cr = result.code_review
    store = result.store
    signals = signals_from(result.tpci, result.sentry, result.liveness, pa, cr) if pa else Signals()
    return {
        "schema": RECORD_SCHEMA,
        "ext_id": result.ext_id,
        "browser": result.browser,
        "analyzed_at": (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "extanalyze_version": __version__,
        "ruleset_hash": ruleset_hash(),
        "scoring_hash": scoring_hash(),
        "name": result.enrichment.name or store.name,
        "category": pa.category if pa else "",
        "store": {
            "source": store.source,
            "version": store.version,
            "install_count": store.install_count,
            "available": store.available,
            "verified": store.verified,
            "established": store.established,
        },
        "package": {
            "sha256": result.download_sha256,
            "size_bytes": result.download_size_bytes,
            "format": result.crx_format,
        },
        "errors": {"download": result.download_error, "manifest": result.manifest_error},
        "manifest": (
            {
                "manifest_version": m.manifest_version,
                "version": m.version,
                "permissions": sorted(m.permissions),
                "optional_permissions": sorted(m.optional_permissions),
                "host_permission_count": len(m.host_permissions),
                "has_all_urls": bool(pa and pa.has_all_urls),
                "content_scripts_all_urls": m.content_scripts_all_urls,
                "has_unsafe_eval": m.has_unsafe_eval,
                "update_url_non_google": m.update_url_non_google,
                "has_oauth2": bool(m.oauth2),
                "externally_connectable": bool(m.externally_connectable),
            }
            if m
            else None
        ),
        "code": (
            {
                "files_scanned": cr.files_scanned,
                "files_skipped": len(cr.files_skipped),
                "rule_hits": {f.rule_id: f.count for f in cr.findings},
                "exfil_flows": len(cr.exfil_flows),
                "external_domain_count": len(cr.external_domains),
                "public_ip_count": len(cr.ips),
                "deep": cr.deep,
            }
            if cr
            else None
        ),
        "ti": {
            "tpci_hit": result.tpci.hit,
            "tpci_confirm_mal": result.tpci.confirm_mal if result.tpci.hit else None,
            "sentry_hit": result.sentry.hit,
            "sentry_blocklist": bool(result.sentry.hit and result.sentry.blocklist),
            "google_malware": result.liveness.google_malware_confirmed,
            "store_removed": result.liveness.store_likely_removed,
        },
        "signals": signals.to_dict(),
        "score": result.risk.score,
        "level": result.risk.level,
    }


def rescore(record: dict, cfg: ScoringConfig | None = None) -> tuple[int, str]:
    """Recompute (score, level) from a stored record with the given or default weights."""
    cfg = cfg or default_config()
    score = score_signals(Signals.from_dict(record["signals"]), cfg).score
    return score, cfg.level_for(score)
