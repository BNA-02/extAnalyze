"""
Rich terminal reporter: prints a structured, colored report to stdout.
"""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..scoring.aggregator import RISK_COLORS
from ..scoring.result import AnalysisResult

_SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "dark_orange",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "SAFE": "green",
}


def print_report(result: AnalysisResult, console: Console | None = None) -> None:
    if console is None:
        console = Console()

    mv = result.manifest.manifest_version if result.manifest else "?"
    name = result.enrichment.name or result.ext_id
    risk_color = RISK_COLORS.get(result.risk.level, "white")

    # ── Header ────────────────────────────────────────────────────────────
    console.print()
    console.rule(f"[bold]extanalyze  |  {name}[/bold]", style="white")

    meta_table = Table(box=None, show_header=False, padding=(0, 2))
    meta_table.add_column(style="bold cyan", no_wrap=True)
    meta_table.add_column()

    meta_table.add_row("Extension ID", result.ext_id)
    meta_table.add_row("Name", name or "[dim]UNKNOWN[/dim]")
    # Show which store(s) the extension was found on
    browser_display = result.browser.capitalize()
    if result.store.source == "chrome+edge":
        browser_display = "Chrome [dim]+ Edge[/dim]"
    meta_table.add_row("Browser / Store", browser_display)
    meta_table.add_row("Manifest", f"MV{mv}")
    meta_table.add_row("Version", result.manifest.version if result.manifest else "?")
    meta_table.add_row("Developer", result.store.developer or "[dim]unknown[/dim]")
    # Publisher trust signals
    trust_parts = []
    if result.store.verified:
        trust_parts.append("[green]Verified[/green]")
    if result.store.established:
        trust_parts.append("[cyan]Established[/cyan]")
    if not result.store.verified and not result.store.established:
        trust_parts.append("[dim]Not verified[/dim]")
    meta_table.add_row("Publisher Trust", " · ".join(trust_parts))
    meta_table.add_row("Install Count", result.store.install_count or "[dim]unknown[/dim]")
    meta_table.add_row("Store Status", _store_status(result))
    meta_table.add_row("CRX Format", result.crx_format or "[dim]not downloaded[/dim]")
    meta_table.add_row(
        "SHA256", result.download_sha256[:16] + "..." if result.download_sha256 else "[dim]-[/dim]"
    )
    if result.enrichment.source == "catalog":
        meta_table.add_row(
            "[yellow]Catalog Note[/yellow]", f"[yellow]{result.enrichment.catalog_warning}[/yellow]"
        )

    console.print(meta_table)

    # ── Risk Banner ───────────────────────────────────────────────────────
    risk_text = Text(
        f"  {result.risk.level}  [Score: {result.risk.score}]  ", style=f"bold {risk_color}"
    )
    console.print(Panel(risk_text, title="RISK VERDICT", border_style=risk_color, expand=False))

    # ── Threat Intelligence ───────────────────────────────────────────────
    console.print("\n[bold underline]Threat Intelligence[/bold underline]")
    ti_table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    ti_table.add_column("Source", style="cyan", width=20)
    ti_table.add_column("Status", width=12)
    ti_table.add_column("Detail")

    _add_ti_row(ti_table, "TPCI", result.tpci.hit, _tpci_detail(result.tpci))
    _add_ti_row(ti_table, "Sentry", result.sentry.hit, _sentry_detail(result.sentry))
    _add_ti_row(
        ti_table,
        "Google CRX API",
        result.liveness.google_malware_confirmed,
        _liveness_detail(result.liveness),
    )

    console.print(ti_table)

    # ── Permissions Table ─────────────────────────────────────────────────
    # ── Static Analysis ────────────────────────────────────────────────────
    if result.manifest and result.perm_analysis:
        _print_permissions(console, result)
        _print_combos(console, result)
        _print_necessity(console, result)
    elif result.download_error or result.manifest_error:
        reason = result.download_error or result.manifest_error
        console.print(f"\n[dim]Static analysis skipped — {reason}[/dim]")

    if result.download_error:
        console.print(f"\n[red][!] Download failed:[/red] {result.download_error}")
    if result.manifest_error:
        console.print(f"\n[red][!] Manifest parse error:[/red] {result.manifest_error}")

    # ── Risk Factors ───────────────────────────────────────────────────────
    # Only show risk factors when there is something meaningful to show.
    # If there is no manifest (download failed) and no TI hits, suppress the
    # section entirely — an empty reasons list from a failed download is noise.
    has_ti_hit = result.tpci.hit or result.sentry.hit or result.liveness.google_malware_confirmed
    if result.risk.reasons and (result.manifest is not None or has_ti_hit):
        console.print("\n[bold underline]Risk Factors[/bold underline]")
        for reason in result.risk.reasons:
            color = _reason_color(reason)
            console.print(f"  [{color}]•[/{color}] {reason}")

    console.print()


def _reason_color(reason: str) -> str:
    """
    Map a risk reason string to a Rich color based on its severity signals.
    Mirrors the same CRITICAL/HIGH/MEDIUM/LOW/SAFE hierarchy used in combo
    and permission tables so the Risk Factors list is visually consistent.
    """
    r = reason.upper()
    # Shortcircuit markers and confirmed TI
    if "[!]" in reason or "_MALWARE=TRUE" in r or "GOOGLE CONFIRMED" in r:
        return "bold red"
    # Severity keywords embedded in the reason string
    if "(CRITICAL)" in r or "CONFIRM-MAL=3" in r or "CONFIRM-MAL=2" in r:
        return "bold red"
    if "(HIGH)" in r or "BLOCKLIST" in r or "NON-CWS UPDATE" in r:
        return "dark_orange"
    if "(MEDIUM)" in r or "UNEXPECTED PERMISSION" in r or "UNEXPECTED" in r.split(":")[0]:
        return "yellow"
    # TI hits without explicit severity tag
    if any(src in r for src in ("TPCI:", "SENTRY:", "GOOGLE CRX")):
        return "dark_orange"
    # Generic informational
    return "dim yellow"


def _is_generic_mv3_note(text: str) -> bool:
    """
    Return True when mv3_abuse is just a short fallback note rather than a
    meaningful description of the attack surface. In these cases we display the
    richer mv2_abuse text (the real attack detail) with a short MV3 annotation.
    """
    t = text.lower().strip()
    return (
        t.startswith("identical in mv3")
        or t.startswith("same in mv3")
        or t.startswith("same —")
        or t == "identical."
        or t.startswith("same risk in mv3")
    )


def _print_permissions(console: Console, result: AnalysisResult) -> None:
    mv = result.manifest.manifest_version
    pa = result.perm_analysis

    console.print(
        f"\n[bold underline]Permissions[/bold underline]  "
        f"(MV{mv}  |  {len(pa.permissions)} named  |  "
        f"{len(pa.host_permissions)} host)"
    )

    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold white")
    table.add_column("Permission", style="cyan", no_wrap=True, width=28)
    table.add_column("Risk", width=8, justify="center")
    table.add_column("Score", width=5, justify="right")
    table.add_column(f"Abuse (MV{mv})", width=55)

    # Track which host-permission names were already rendered in the named section
    # so we don't duplicate them below (e.g. <all_urls> can appear in both lists)
    rendered_as_named: set[str] = set()

    for perm in sorted(pa.permissions, key=lambda p: -p.risk_score):
        risk_style = _SEVERITY_COLORS.get(perm.sensitivity, "white")

        flags = []
        if perm.data_exfil_vector:
            flags.append("[red]EXFIL[/red]")
        if perm.c2_vector:
            flags.append("[magenta]C2[/magenta]")

        perm_display = perm.name
        if flags:
            perm_display += "  " + " ".join(flags)

        # Single abuse column: for MV3, use mv3_abuse when it's substantive.
        # When mv3_abuse is just a short "Identical/Same in MV3" fallback,
        # show mv2_abuse (the detailed attack description) with a short MV3 note appended.
        if mv == 3:
            mv3 = perm.mv3_abuse.strip()
            mv2 = perm.mv2_abuse.strip()
            if perm.mv2_only:
                abuse_text = "[yellow]⚠ MV2-only permission declared in MV3 manifest[/yellow]"
            elif _is_generic_mv3_note(mv3):
                # mv3_abuse is just "Same/Identical in MV3" — show the real detail from MV2
                mv3_suffix = "" if "unchanged" in mv3.lower() else f" ({mv3})"
                abuse_text = mv2 + (" — unchanged in MV3" if not mv3_suffix else mv3_suffix)
            else:
                abuse_text = mv3
        else:
            abuse_text = perm.mv2_abuse
            if perm.mv3_blocked:
                abuse_text += " [dim](removed in MV3)[/dim]"

        table.add_row(
            perm_display,
            f"[{risk_style}]{perm.sensitivity}[/{risk_style}]",
            str(perm.risk_score),
            abuse_text,
        )
        rendered_as_named.add(perm.name)

    # Host permissions section — separate from named permissions
    # Skip any that were already rendered in the named loop (e.g. <all_urls>
    # normalised into both sets in edge cases)
    remaining_hosts = [h for h in sorted(pa.host_permissions) if h not in rendered_as_named]

    console.print(table)

    # ── Host Scope section ────────────────────────────────────────────────────
    scope = pa.host_scope
    if scope.scope_label != "NONE":
        if scope.is_broad:
            scope_icon = "[bold red]⚠ BROAD[/bold red]"
        elif scope.scope_label == "MINIMAL":
            scope_icon = "[green]✓ MINIMAL[/green]"
        else:
            scope_icon = "[cyan]SCOPED[/cyan]"

        console.print(
            f"\n[bold underline]Host Permission Scope[/bold underline]  "
            f"{scope_icon}  ({scope.domain_count} domain(s))"
        )
        console.print(f"  {scope.risk_note}")

        if remaining_hosts and not scope.is_broad:
            # Show scoped domains in a compact table
            host_table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
            host_table.add_column("Domain Pattern", style="dim cyan")
            host_table.add_column("Type", width=10)
            for hp in remaining_hosts:
                kind = (
                    "ws wildcard"
                    if hp.startswith("ws") and "*" in hp
                    else (
                        "websocket"
                        if hp.startswith("ws")
                        else ("wildcard" if "*" in hp else "exact")
                    )
                )
                host_table.add_row(hp, kind)
            console.print(host_table)
        elif scope.is_broad:
            console.print("  [red]No domain restriction — the extension can access any site[/red]")


def _print_combos(console: Console, result: AnalysisResult) -> None:
    combos = result.perm_analysis.combo_hits
    if not combos:
        console.print("\n[green]No dangerous permission combos detected.[/green]")
        return

    console.print(
        f"\n[bold underline]Dangerous Permission Combos[/bold underline]  ({len(combos)} detected)"
    )

    for combo in combos:
        sev_color = _SEVERITY_COLORS.get(combo.severity, "white")
        console.print(
            f"\n  [{sev_color}][{combo.combo_id}] {combo.name}  [{combo.severity}][/{sev_color}]"
        )
        console.print(f"    Threat: {combo.threat}")
        console.print(f"    Matched: {', '.join(combo.matched_permissions)}")
        if combo.mv_note:
            console.print(f"    MV Note: [dim]{combo.mv_note}[/dim]")


def _print_necessity(console: Console, result: AnalysisResult) -> None:
    verdicts = result.perm_analysis.necessity_verdicts
    if not verdicts:
        return

    cat = result.perm_analysis.category
    conf = result.perm_analysis.category_confidence
    console.print(
        f"\n[bold underline]Permission Necessity[/bold underline]  "
        f"(Category: [cyan]{cat}[/cyan]  Confidence: [dim]{conf}[/dim])"
    )

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("Permission", style="cyan", width=28)
    table.add_column("Verdict", width=12)
    table.add_column("Note")

    for v in verdicts:
        if v.verdict == "NEEDED":
            style = "green"
        elif v.verdict == "BORDERLINE":
            style = "yellow"
        else:
            style = "bold red"

        table.add_row(v.permission, f"[{style}]{v.verdict}[/{style}]", v.explanation)

    console.print(table)


# ── Helper formatters ─────────────────────────────────────────────────────────


def _store_status(result: AnalysisResult) -> str:
    if result.store.available:
        return "[green]Active[/green]"
    if result.liveness.store_likely_removed:
        return "[yellow]Likely Removed[/yellow]"
    return "[dim]Unknown[/dim]"


def _add_ti_row(table: Table, source: str, hit: bool, detail: str) -> None:
    if hit:
        table.add_row(source, "[bold red]HIT[/bold red]", detail)
    else:
        table.add_row(source, "[green]Clean[/green]", detail or "Not found in database")


def _tpci_detail(tpci) -> str:
    if not tpci.hit:
        return ""
    parts = []
    confirm_labels = {
        0: "Under investigation",
        1: "Researcher confirmed",
        2: "Google confirmed",
        3: "Google + researcher confirmed",
    }
    parts.append(confirm_labels.get(tpci.confirm_mal, "Unknown"))
    if tpci.threat_types:
        parts.append(f"Types: {', '.join(tpci.threat_types)}")
    if tpci.tpci_behavioral not in ("unknown", ""):
        parts.append(f"Behavioral: {tpci.tpci_behavioral}")
    return " | ".join(parts)


def _sentry_detail(sentry) -> str:
    if not sentry.hit:
        return ""
    parts = [sentry.reason or "Flagged"]
    if sentry.blocklist:
        parts.append("BLOCKLISTED")
    if sentry.sha256_match is False:
        parts.append("[yellow]SHA256 mismatch[/yellow]")
    return " | ".join(parts)


def _liveness_detail(liveness) -> str:
    if liveness.google_malware_confirmed:
        return "[bold red]_malware=true (authoritative)[/bold red]"
    if liveness.store_likely_removed:
        return f"[yellow]Likely removed (status={liveness.status_xml})[/yellow]"
    return f"status={liveness.status_xml}"
