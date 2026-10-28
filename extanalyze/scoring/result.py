"""
Full analysis result dataclass - the container passed between all layers and reporters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from ..analysis.code_review import CodeReviewResult
from ..analysis.permissions import PermissionAnalysis
from ..core.enrichment import EnrichmentResult
from ..core.manifest_parser import ExtensionManifest
from ..core.store_meta import LivenessResult, StoreMeta
from ..intel.sentry import SentryResult
from ..intel.tpci import TPCIResult
from ..scoring.aggregator import RiskReport


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
    risk: RiskReport

    # Metadata
    analyzed_at: datetime = field(default_factory=datetime.utcnow)
    download_error: str = ""  # non-empty if download failed
    manifest_error: str = ""  # non-empty if manifest parse failed
    is_builtin: bool = False  # True for extensions baked into the browser
    code_review: CodeReviewResult | None = None  # None if extraction/review did not run
    code_review_error: str = ""  # non-empty if the code review step failed
