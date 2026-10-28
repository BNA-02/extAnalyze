"""
Full analysis result dataclass - passed between all layers and reporters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from extanalyze.analysis.code_review import CodeReviewResult
from extanalyze.analysis.permissions import PermissionAnalysis
from extanalyze.core.enrichment import EnrichmentResult
from extanalyze.core.manifest_parser import ExtensionManifest
from extanalyze.core.store_meta import LivenessResult, StoreMeta
from extanalyze.intel.sentry import SentryResult
from extanalyze.intel.tpci import TPCIResult
from extanalyze.scoring.aggregator import RiskReport


@dataclass
class AnalysisResult:
    # Input
    ext_id: str
    browser: str

    # Identity
    enrichment: EnrichmentResult
    store: StoreMeta
    liveness: LivenessResult

    # Threat Intelligence
    tpci: TPCIResult
    sentry: SentryResult

    # Static Analysis
    manifest: ExtensionManifest | None
    perm_analysis: PermissionAnalysis | None
    download_sha256: str
    download_size_bytes: int
    crx_format: str

    # Risk
    risk: RiskReport = field(default_factory=lambda: RiskReport(0, "SAFE", [], False, False))

    # Metadata
    analyzed_at: datetime = field(default_factory=datetime.utcnow)
    download_error: str = ""  # non-empty if download failed
    manifest_error: str = ""  # non-empty if manifest parse failed
    is_builtin: bool = False  # True for extensions baked into the browser
    code_review: CodeReviewResult | None = None  # None if extraction/review did not run
    code_review_error: str = ""  # non-empty if the code review step failed
    dynamic_error: str = ""  # non-empty if the dynamic (sandbox) step failed
