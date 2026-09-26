"""
Worker: orchestrates the full analysis pipeline for one extension.
Bulk dispatcher uses ThreadPoolExecutor with this as the unit of work.
"""

from __future__ import annotations

import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

from .analysis.categorizer import categorize
from .analysis.permissions import analyze as analyze_permissions
from .core.downloader import ExtensionNotDownloadableError, download
from .core.enrichment import enrich
from .core.extractor import ExtractionError, extract
from .core.ingestion import ExtensionInput
from .core.manifest_parser import parse_manifest
from .core.store_meta import (
    LivenessResult,
    StoreMeta,
    check_crx_liveness,
    fetch_amo_meta,
    fetch_cws_meta,
    fetch_edge_meta,
    probe_stores,
)
from .intel import sentry as sentry_mod
from .intel import tpci as tpci_mod
from .intel.sentry import SentryResult
from .intel.tpci import TPCIResult
from .scoring.aggregator import aggregate
from .scoring.result import AnalysisResult

# Rate limiter for live Google API calls (avoid hammering)
_google_semaphore = threading.Semaphore(2)
_store_semaphore = threading.Semaphore(3)


def _empty_store(source: str) -> StoreMeta:
    return StoreMeta(
        name="",
        description="",
        category="",
        developer="",
        version="",
        install_count="",
        available=False,
        source=source,
        verified=False,
        established=False,
    )


def preload_intel() -> None:
    """
    Pre-load threat intel caches BEFORE spawning thread pool.
    Both datasets are read-only after loading — safe for concurrent reads.
    """
    print("[worker] Pre-loading threat intelligence caches...", file=sys.stderr)
    tpci_mod._ensure_loaded()
    sentry_mod._ensure_loaded()
    print("[worker] TI caches ready.", file=sys.stderr)


def analyze_single(inp: ExtensionInput) -> AnalysisResult:
    """
    Full pipeline for one extension. Designed to run inside a thread.
    Never raises: errors are captured in AnalysisResult fields.
    """
    ext_id = inp.ext_id
    browser = inp.browser

    # ── Step 1: Store metadata (parallel-safe, rate limited) ──────────────
    with _store_semaphore:
        try:
            if browser == "firefox":
                store = fetch_amo_meta(ext_id)
            elif browser == "edge":
                # Edge has its own product API — never use CWS for Edge IDs.
                store = fetch_edge_meta(ext_id)
            elif browser == "auto":
                # Check builtin list first — Chrome/Edge builtins are not on CWS
                # and would waste a probe_stores round-trip returning nothing useful.
                from .core.enrichment import _BUILTIN_EXTENSIONS

                if ext_id in _BUILTIN_EXTENSIONS:
                    b = _BUILTIN_EXTENSIONS[ext_id]
                    browser = b.get("browser", "chrome")
                    store = StoreMeta(
                        name=b.get("name", ""),
                        description=b.get("description", ""),
                        category=b.get("category", ""),
                        developer="Google LLC",
                        version="",
                        install_count="",
                        available=True,
                        source="builtin",
                        verified=True,
                        established=True,
                    )
                else:
                    # No browser specified for a 32-char CRX ID — probe both stores
                    # to determine where the extension actually lives.
                    found_on = probe_stores(ext_id)
                    if "chrome" in found_on and "edge" in found_on:
                        # Cross-listed: use CWS as primary (richer metadata)
                        browser = "chrome"
                        store = fetch_cws_meta(ext_id)
                        # Annotate so the report shows both stores
                        store = StoreMeta(
                            name=store.name,
                            description=store.description,
                            category=store.category,
                            developer=store.developer,
                            version=store.version,
                            install_count=store.install_count,
                            available=store.available,
                            source="chrome+edge",
                            verified=store.verified,
                            established=store.established,
                        )
                    elif "edge" in found_on:
                        browser = "edge"
                        store = fetch_edge_meta(ext_id)
                    elif "chrome" in found_on:
                        browser = "chrome"
                        store = fetch_cws_meta(ext_id)
                    else:
                        # Not found on either store — still run TI checks
                        browser = "chrome"  # default for download attempt
                        store = _empty_store("unknown")
            else:
                store = fetch_cws_meta(ext_id)
        except Exception:
            store = StoreMeta(
                name="",
                description="",
                category="",
                developer="",
                version="",
                install_count="",
                available=False,
                source="error",
                verified=False,
                established=False,
            )

    # ── Step 2: Google CRX liveness (rate limited) ────────────────────────
    # Skip for: Edge-only IDs (returns error-unknownApplication from Google),
    # Firefox (not on CWS at all), and builtins (not in CWS).
    is_builtin = store.source == "builtin"
    with _google_semaphore:
        try:
            if browser == "edge":
                liveness = LivenessResult(
                    google_malware_confirmed=False,
                    store_likely_removed=not store.available,
                    status_xml="edge-store",
                    raw_response="",
                )
            elif browser == "firefox":
                liveness = LivenessResult(
                    google_malware_confirmed=False,
                    store_likely_removed=not store.available,
                    status_xml="firefox-amo",
                    raw_response="",
                )
            elif is_builtin:
                liveness = LivenessResult(
                    google_malware_confirmed=False,
                    store_likely_removed=False,
                    status_xml="builtin",
                    raw_response="",
                )
            else:
                liveness = check_crx_liveness(ext_id)
        except Exception:
            liveness = LivenessResult(
                google_malware_confirmed=False,
                store_likely_removed=False,
                status_xml="error",
                raw_response="",
            )

    # ── Step 3: Enrichment (local lookup, fast) ───────────────────────────
    enrichment = enrich(ext_id, store.name, store.description)

    # ── Step 4: TI lookups (in-memory, no network) ───────────────────────
    tpci_result: TPCIResult = tpci_mod.lookup(ext_id)
    sentry_result: SentryResult = sentry_mod.lookup(ext_id)

    # ── Step 5: Download ──────────────────────────────────────────────────
    download_error = ""
    manifest_error = ""
    manifest = None
    perm_analysis = None
    download_sha256 = ""
    download_size = 0
    crx_format = ""

    if is_builtin:
        # Builtin extensions are baked into the browser binary — no CRX to download.
        # We know what they are from the registry; skip download entirely.
        crx_format = "builtin"
    else:
        try:
            dl = download(ext_id, browser)
            download_sha256 = dl.sha256
            download_size = dl.size_bytes
            crx_format = dl.crx_format

            # Cross-check SHA256 with sentry after download
            sentry_result = sentry_mod.lookup(ext_id, downloaded_sha256=download_sha256)

            # ── Step 6: Extract ───────────────────────────────────────────────
            try:
                extract_result = extract(dl)

                # ── Step 7: Parse manifest ────────────────────────────────────
                try:
                    manifest = parse_manifest(extract_result.manifest_path)

                    # ── Step 8: Categorize and analyze permissions ────────────
                    text_for_cat = (
                        (enrichment.name or "")
                        + " "
                        + (enrichment.description or store.description or manifest.description or "")
                    )
                    category, confidence = categorize(enrichment.name or "", text_for_cat)

                    perm_analysis = analyze_permissions(manifest, category, confidence)

                except Exception as e:
                    manifest_error = str(e)

            except ExtractionError as e:
                download_error = f"Extraction failed: {e}"

        except ExtensionNotDownloadableError as e:
            download_error = str(e)
        except Exception as e:
            download_error = f"Unexpected download error: {e}"

    # ── Step 9: Risk scoring ──────────────────────────────────────────────
    # Create minimal objects for scoring if analysis failed
    if perm_analysis is None:
        from .analysis.permissions import HostScopeAssessment, PermissionAnalysis

        perm_analysis = PermissionAnalysis(
            permissions=[],
            host_permissions=[],
            has_all_urls=False,
            host_scope=HostScopeAssessment(False, 0, [], "NONE", ""),
            total_risk_score=0,
            has_critical=False,
            has_high=False,
            combo_hits=[],
            necessity_verdicts=[],
            category="UNKNOWN",
            category_confidence="UNKNOWN",
        )

    risk = aggregate(tpci_result, sentry_result, liveness, perm_analysis)

    return AnalysisResult(
        ext_id=ext_id,
        browser=browser,
        enrichment=enrichment,
        store=store,
        liveness=liveness,
        tpci=tpci_result,
        sentry=sentry_result,
        manifest=manifest,
        perm_analysis=perm_analysis,
        download_sha256=download_sha256,
        download_size_bytes=download_size,
        crx_format=crx_format,
        risk=risk,
        analyzed_at=datetime.utcnow(),
        download_error=download_error,
        manifest_error=manifest_error,
        is_builtin=is_builtin,
    )


def analyze_bulk(
    inputs: list[ExtensionInput],
    max_workers: int = 8,
    console: Console | None = None,
) -> list[AnalysisResult]:
    """
    Dispatch analysis for multiple extensions using a thread pool.
    TI caches are pre-loaded before pool starts.
    Returns results in completion order (not input order).
    """
    if console is None:
        console = Console(stderr=True)

    preload_intel()

    results: list[AnalysisResult] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(f"Analyzing {len(inputs)} extensions...", total=len(inputs))

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(analyze_single, inp): inp for inp in inputs}

            for future in as_completed(futures):
                inp = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    # analyze_single shouldn't raise, but be safe
                    console.print(f"[red]Unexpected error for {inp.ext_id}: {e}[/red]")
                finally:
                    progress.advance(task)

    return results
