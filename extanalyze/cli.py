"""
extanalyze CLI entry point.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from .core.enrichment import load_catalog
from .core.ingestion import InvalidExtensionID, iter_single, load_ids_from_file
from .output import csv_reporter, html_reporter, json_reporter, text_reporter
from .worker import analyze_bulk, analyze_single

console = Console()
err_console = Console(stderr=True)


@click.group()
@click.version_option()
def main():
    """extanalyze - Browser extension security analysis CLI."""
    pass


# ─────────────────────────────────────────────────────────────────────────────
# analyze command
# ─────────────────────────────────────────────────────────────────────────────


@main.command()
@click.argument("ext_id", required=False)
@click.option(
    "--file",
    "-f",
    "input_file",
    type=click.Path(exists=True, path_type=Path),
    help="Text file with one extension ID per line.",
)
@click.option(
    "--browser",
    "-b",
    type=click.Choice(["chrome", "edge", "firefox"]),
    default=None,
    help="Force browser type (auto-detected from ID format if omitted).",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["text", "json", "csv", "html", "all"]),
    default="text",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--out-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Directory to write output files (required for csv/html/all).",
)
@click.option(
    "--workers",
    "-w",
    type=int,
    default=8,
    show_default=True,
    help="Thread pool size for bulk analysis.",
)
@click.option(
    "--catalog",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to CRX catalog CSV (2023-10-18_list_of_all_crx.csv) for name enrichment.",
)
@click.option(
    "--rebuild-catalog",
    is_flag=True,
    default=False,
    help="Force rebuild of the msgpack catalog index from --catalog CSV.",
)
@click.option(
    "--deep",
    is_flag=True,
    default=False,
    help=(
        "Add deep extras to the always-on code review: entropy analysis and static "
        "deobfuscation, RetireJS vulnerable-library detection, and VirusTotal domain "
        "lookups (needs VIRUSTOTAL_API_KEY; sends domains found in the extension to VirusTotal). "
        "Slower."
    ),
)
def analyze(ext_id, input_file, browser, output, out_dir, workers, catalog, rebuild_catalog, deep):
    """
    Analyze one extension ID or a batch from a file.

    Examples:

    \b
      extanalyze analyze ublock-origin --browser firefox
      extanalyze analyze gbchcmhmhahfdphkhkmpfmihenigjmpp
      extanalyze analyze --file ids.txt --output html --out-dir ./reports
      extanalyze analyze --file ids.txt --output all --out-dir ./reports --workers 12
    """
    # ── Load catalog if provided ──────────────────────────────────────────
    if catalog:
        load_catalog(catalog, force_rebuild=rebuild_catalog)
    elif rebuild_catalog:
        err_console.print("[yellow]--rebuild-catalog requires --catalog path[/yellow]")

    # ── Validate input ────────────────────────────────────────────────────
    if not ext_id and not input_file:
        raise click.UsageError("Provide an extension ID or --file <path>")

    if ext_id and input_file:
        raise click.UsageError("Provide either an ID or --file, not both")

    # Output directory check
    if output in ("csv", "html", "all") and not out_dir:
        raise click.UsageError(f"--out-dir is required when --output is {output}")

    # ── Build input list ──────────────────────────────────────────────────
    try:
        if ext_id:
            inputs = iter_single(ext_id, browser)
        else:
            inputs = load_ids_from_file(input_file, browser)
    except InvalidExtensionID as e:
        err_console.print(f"[red]Invalid extension ID:[/red] {e}")
        sys.exit(1)

    if not inputs:
        err_console.print("[yellow]No valid extension IDs found.[/yellow]")
        sys.exit(0)

    # ── Run analysis ──────────────────────────────────────────────────────
    if len(inputs) == 1:
        result = analyze_single(inputs[0], deep=deep)
        results = [result]
    else:
        results = analyze_bulk(inputs, max_workers=workers, console=err_console, deep=deep)
        # Sort by risk score descending for output
        results.sort(key=lambda r: -r.risk.score)

    # ── Output ────────────────────────────────────────────────────────────
    _emit_output(results, output, out_dir)


def _emit_output(results, output: str, out_dir: Path | None) -> None:
    is_bulk = len(results) > 1

    if output in ("text", "all"):
        for r in results:
            text_reporter.print_report(r, console=console)
            if is_bulk:
                console.print()

    if output in ("json", "all"):
        if is_bulk:
            if out_dir:
                p = out_dir / "extanalyze_report.json"
                json_reporter.write_bulk(results, p)
                err_console.print(f"[green]JSON written:[/green] {p}")
            else:
                # Single extension: print to stdout
                click.echo(json_reporter.write(results[0]))
        else:
            if out_dir:
                p = out_dir / f"{results[0].ext_id}.json"
                json_reporter.write(results[0], p)
                err_console.print(f"[green]JSON written:[/green] {p}")
            else:
                click.echo(json_reporter.write(results[0]))

    if output in ("csv", "all"):
        p = out_dir / "extanalyze_report.csv"
        csv_reporter.write_bulk(results, p)
        err_console.print(f"[green]CSV written:[/green] {p}")

    if output in ("html", "all"):
        if is_bulk:
            p = out_dir / "extanalyze_report.html"
            html_reporter.write_bulk(results, p)
        else:
            p = out_dir / f"{results[0].ext_id}.html"
            html_reporter.write_single(results[0], p)
        err_console.print(f"[green]HTML written:[/green] {p}")


# ─────────────────────────────────────────────────────────────────────────────
# cache command
# ─────────────────────────────────────────────────────────────────────────────


@main.command()
@click.argument("action", type=click.Choice(["status", "clear"]))
def cache(action):
    """Manage the local TI and catalog cache."""
    cache_dir = Path.home() / ".extanalyze" / "cache"

    if action == "status":
        if not cache_dir.exists():
            console.print("[yellow]Cache directory does not exist.[/yellow]")
            return
        files = list(cache_dir.iterdir())
        if not files:
            console.print("[yellow]Cache is empty.[/yellow]")
            return
        import time

        from rich.table import Table

        t = Table(title="Cache Status")
        t.add_column("File")
        t.add_column("Size")
        t.add_column("Age")
        for f in sorted(files):
            stat = f.stat()
            age_h = (time.time() - stat.st_mtime) / 3600
            t.add_row(f.name, f"{stat.st_size // 1024}KB", f"{age_h:.1f}h")
        console.print(t)

    elif action == "clear":
        import shutil

        if cache_dir.exists():
            shutil.rmtree(cache_dir)
            console.print(f"[green]Cache cleared:[/green] {cache_dir}")
        else:
            console.print("[yellow]Nothing to clear.[/yellow]")


if __name__ == "__main__":
    main()
