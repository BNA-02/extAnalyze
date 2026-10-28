"""
Library entry point for programmatic use (bulk studies, other tools).

    from extanalyze.api import analyze_extension, to_record
    result = analyze_extension("gighmmpiobklfepjocnamgkkbiglidom")
    record = to_record(result)          # flat, versioned, snippet-free
"""

from __future__ import annotations

from .core.ingestion import ExtensionInput, detect_browser
from .output.record import rescore, to_record
from .scoring.result import AnalysisResult
from .worker import analyze_single, preload_intel

__all__ = ["analyze_extension", "preload_intel", "rescore", "to_record"]


def analyze_extension(
    ext_id: str, browser: str | None = None, *, deep: bool = False
) -> AnalysisResult:
    """Analyse one extension. Never raises for network or parsing problems: errors are fields
    on the returned result. Call `preload_intel()` once before many calls."""
    return analyze_single(ExtensionInput(ext_id, detect_browser(ext_id, browser)), deep=deep)
