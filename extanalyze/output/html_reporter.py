"""
HTML reporter: self-contained single-file HTML report.
No external dependencies - all CSS and JS inlined.
Supports sorting, filtering by risk level, and collapsible detail panels.
"""

from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

from ..scoring.result import AnalysisResult

_RISK_BADGE = {
    "CRITICAL": ("background:#dc2626;color:#fff", "CRITICAL"),
    "HIGH": ("background:#ea580c;color:#fff", "HIGH"),
    "MEDIUM": ("background:#ca8a04;color:#fff", "MEDIUM"),
    "LOW": ("background:#2563eb;color:#fff", "LOW"),
    "SAFE": ("background:#16a34a;color:#fff", "SAFE"),
}


def write_single(result: AnalysisResult, path: Path) -> None:
    """Write a self-contained HTML report for a single extension."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_render_single(result), encoding="utf-8")


def write_bulk(results: list[AnalysisResult], path: Path) -> None:
    """Write a combined HTML report with all extensions, sortable table + detail panels."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_render_bulk(results), encoding="utf-8")


# ── Renderers ─────────────────────────────────────────────────────────────────


def _render_single(r: AnalysisResult) -> str:
    name = html.escape(r.enrichment.name or r.ext_id)
    risk_style, risk_label = _RISK_BADGE.get(
        r.risk.level, ("background:#6b7280;color:#fff", r.risk.level)
    )
    m = r.manifest
    pa = r.perm_analysis

    perms_html = ""
    if pa:
        rows = []
        for p in sorted(pa.permissions, key=lambda x: -x.risk_score):
            ps, _ = _RISK_BADGE.get(p.sensitivity, ("", ""))
            badge = f'<span style="padding:2px 6px;border-radius:3px;font-size:11px;{ps}">{html.escape(p.sensitivity)}</span>'
            mv2 = html.escape(p.mv2_abuse)
            mv3 = html.escape(p.mv3_abuse)
            if p.mv2_only:
                mv3 = '<em style="color:#9ca3af">N/A – MV3 removed</em>'
            rows.append(f"""
                <tr>
                  <td style="font-family:monospace">{html.escape(p.name)}</td>
                  <td>{badge}</td>
                  <td style="text-align:center">{p.risk_score}</td>
                  <td style="font-size:12px;color:#d1d5db">{mv2}</td>
                  <td style="font-size:12px;color:#d1d5db">{mv3}</td>
                </tr>""")

        perms_html = f"""
        <h2 style="color:#f3f4f6;border-bottom:1px solid #374151;padding-bottom:8px">Permissions</h2>
        <table style="width:100%;border-collapse:collapse;font-size:13px">
          <thead>
            <tr style="background:#1f2937;color:#9ca3af;text-align:left">
              <th style="padding:8px">Permission</th><th>Risk</th><th>Score</th>
              <th>MV2 Abuse</th><th>MV3 Abuse</th>
            </tr>
          </thead>
          <tbody>{"".join(rows)}</tbody>
        </table>"""

    combos_html = ""
    if pa and pa.combo_hits:
        items = []
        for c in pa.combo_hits:
            cs, _ = _RISK_BADGE.get(c.severity, ("background:#6b7280;color:#fff", c.severity))
            badge = f'<span style="padding:2px 8px;border-radius:3px;{cs}">{html.escape(c.severity)}</span>'
            note = (
                f'<div style="font-size:11px;color:#9ca3af;margin-top:4px">{html.escape(c.mv_note)}</div>'
                if c.mv_note
                else ""
            )
            items.append(f"""
            <div style="background:#1f2937;border-left:3px solid #dc2626;margin:8px 0;padding:10px 14px;border-radius:0 6px 6px 0">
              <div style="display:flex;align-items:center;gap:10px">
                {badge}
                <strong style="color:#f3f4f6">[{html.escape(c.combo_id)}] {html.escape(c.name)}</strong>
              </div>
              <div style="margin-top:4px;color:#d1d5db;font-size:13px">{html.escape(c.threat)}</div>
              <div style="font-size:12px;color:#6b7280;margin-top:2px">Matched: {html.escape(", ".join(c.matched_permissions))}</div>
              {note}
            </div>""")
        combos_html = f'<h2 style="color:#f3f4f6;border-bottom:1px solid #374151;padding-bottom:8px">Dangerous Combos</h2>{"".join(items)}'

    reasons_html = ""
    if r.risk.reasons:
        items = [
            f'<li style="margin:4px 0;color:#d1d5db">{html.escape(reason)}</li>'
            for reason in r.risk.reasons
        ]
        reasons_html = f'<h2 style="color:#f3f4f6;border-bottom:1px solid #374151;padding-bottom:8px">Risk Factors</h2><ul style="padding-left:20px">{"".join(items)}</ul>'

    ti_rows = [
        ("TPCI", r.tpci.hit, _tpci_detail_html(r.tpci)),
        ("Sentry", r.sentry.hit, _sentry_detail_html(r.sentry)),
        ("Google CRX API", r.liveness.google_malware_confirmed, _liveness_detail_html(r.liveness)),
    ]
    ti_html_rows = ""
    for src, hit, detail in ti_rows:
        status = (
            '<span style="color:#dc2626;font-weight:bold">HIT</span>'
            if hit
            else '<span style="color:#16a34a">Clean</span>'
        )
        ti_html_rows += f'<tr><td style="padding:6px 12px;font-weight:bold;color:#93c5fd">{src}</td><td style="padding:6px 12px">{status}</td><td style="padding:6px 12px;color:#d1d5db;font-size:12px">{detail}</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>extanalyze | {name}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0 }}
    body {{ background: #111827; color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; padding: 24px }}
    table td, table th {{ padding: 7px 10px; border-bottom: 1px solid #374151 }}
    table tr:hover td {{ background: #1f2937 }}
    h2 {{ margin: 24px 0 12px }}
    .card {{ background: #1f2937; border-radius: 8px; padding: 20px; margin: 16px 0 }}
  </style>
</head>
<body>
  <div style="max-width:1100px;margin:0 auto">
    <div style="display:flex;align-items:center;gap:16px;margin-bottom:24px">
      <h1 style="font-size:22px">{name}</h1>
      <span style="padding:4px 14px;border-radius:6px;font-weight:bold;{risk_style}">{risk_label} [{r.risk.score}]</span>
    </div>

    <div class="card">
      <table style="width:100%;border-collapse:collapse">
        <tr><td style="color:#9ca3af;width:160px">Extension ID</td><td style="font-family:monospace">{html.escape(r.ext_id)}</td></tr>
        <tr><td style="color:#9ca3af">Browser</td><td>{html.escape(r.browser.capitalize())}</td></tr>
        <tr><td style="color:#9ca3af">Manifest</td><td>MV{m.manifest_version if m else "?"}</td></tr>
        <tr><td style="color:#9ca3af">Developer</td><td>{html.escape(r.store.developer or "Unknown")}</td></tr>
        <tr><td style="color:#9ca3af">Publisher Trust</td><td>{_trust_html(r.store)}</td></tr>
        <tr><td style="color:#9ca3af">Installs</td><td>{html.escape(r.store.install_count or "Unknown")}</td></tr>
        <tr><td style="color:#9ca3af">Store Status</td><td>{"Active" if r.store.available else "Removed/Unknown"}</td></tr>
        <tr><td style="color:#9ca3af">SHA256</td><td style="font-family:monospace;font-size:12px">{html.escape(r.download_sha256 or "-")}</td></tr>
        <tr><td style="color:#9ca3af">Analyzed</td><td>{html.escape(r.analyzed_at.strftime("%Y-%m-%d %H:%M UTC"))}</td></tr>
      </table>
    </div>

    <div class="card">
      <h2 style="color:#f3f4f6;border-bottom:1px solid #374151;padding-bottom:8px">Threat Intelligence</h2>
      <table style="width:100%;border-collapse:collapse">{ti_html_rows}</table>
    </div>

    <div class="card">{perms_html}</div>
    <div class="card">{combos_html}</div>
    <div class="card">{_code_review_html(r)}</div>
    <div class="card">{reasons_html}</div>

    <div style="color:#6b7280;font-size:12px;margin-top:24px;text-align:center">
      Generated by extanalyze · {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}
    </div>
  </div>
</body>
</html>"""


def _render_bulk(results: list[AnalysisResult]) -> str:
    """Summary table with collapsible rows linking to per-ext detail sections."""
    summary_rows = ""
    detail_sections = ""

    for r in sorted(results, key=lambda x: -x.risk.score):
        name = html.escape(r.enrichment.name or r.ext_id)
        rs, rl = _RISK_BADGE.get(r.risk.level, ("", r.risk.level))
        badge = f'<span style="padding:2px 8px;border-radius:3px;font-size:11px;{rs}">{rl}</span>'
        ti_hits = []
        if r.tpci.hit:
            ti_hits.append("TPCI")
        if r.sentry.hit:
            ti_hits.append("Sentry")
        if r.liveness.google_malware_confirmed:
            ti_hits.append("Google")
        ti_str = ", ".join(ti_hits) if ti_hits else "—"

        combos = r.perm_analysis.combo_hits if r.perm_analysis else []
        combo_str = str(len(combos)) if combos else "0"

        summary_rows += f"""
        <tr onclick="document.getElementById('ext-{r.ext_id}').scrollIntoView()" style="cursor:pointer">
          <td style="font-family:monospace;font-size:12px">{html.escape(r.ext_id)}</td>
          <td>{name}</td>
          <td>{r.browser}</td>
          <td>{badge}</td>
          <td>{r.risk.score}</td>
          <td style="color:#ef4444">{ti_str}</td>
          <td>{combo_str}</td>
        </tr>"""

        # Embed per-extension detail as section
        detail_sections += f'<div id="ext-{r.ext_id}">{_render_single(r)}</div><hr style="border:1px solid #374151;margin:32px 0">'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>extanalyze — Bulk Report ({len(results)} extensions)</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0 }}
    body {{ background: #111827; color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; padding: 24px }}
    table td, table th {{ padding: 8px 12px; border-bottom: 1px solid #374151 }}
    table tr:hover td {{ background: #1f2937 }}
    h1, h2 {{ margin-bottom: 12px }}
    input {{ background:#1f2937;border:1px solid #374151;color:#f3f4f6;padding:8px 12px;border-radius:6px;width:320px }}
  </style>
</head>
<body>
  <div style="max-width:1200px;margin:0 auto">
    <h1 style="margin-bottom:8px">extanalyze — Bulk Report</h1>
    <div style="color:#9ca3af;margin-bottom:20px">{len(results)} extensions · Generated {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}</div>

    <input type="text" id="filterInput" placeholder="Filter by ID or name..." oninput="filterTable()" style="margin-bottom:16px">

    <table id="summaryTable" style="width:100%;border-collapse:collapse;margin-bottom:40px">
      <thead>
        <tr style="background:#1f2937;color:#9ca3af">
          <th style="text-align:left">Extension ID</th>
          <th style="text-align:left">Name</th>
          <th style="text-align:left">Browser</th>
          <th style="text-align:left">Risk</th>
          <th style="text-align:left">Score</th>
          <th style="text-align:left">TI Hits</th>
          <th style="text-align:left">Combos</th>
        </tr>
      </thead>
      <tbody>{summary_rows}</tbody>
    </table>

    <h2>Extension Details</h2>
    {detail_sections}
  </div>
  <script>
    function filterTable() {{
      const q = document.getElementById('filterInput').value.toLowerCase();
      document.querySelectorAll('#summaryTable tbody tr').forEach(row => {{
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
      }});
    }}
  </script>
</body>
</html>"""


def _code_review_html(r: AnalysisResult) -> str:
    cr = r.code_review
    if cr is None:
        return ""
    h2 = '<h2 style="color:#f3f4f6;border-bottom:1px solid #374151;padding-bottom:8px">Code Review</h2>'
    note = (
        f'<div style="font-size:12px;color:#9ca3af">{cr.files_scanned} files scanned · '
        "heuristic leads, not verdicts</div>"
    )
    items = []
    for f in cr.findings:
        cs, _ = _RISK_BADGE.get(f.severity, ("background:#6b7280;color:#fff", f.severity))
        locs = "".join(
            f'<div style="font-family:monospace;font-size:11px;color:#9ca3af">'
            f"{html.escape(loc.file)}:{loc.line}  {html.escape(loc.snippet)}</div>"
            for loc in f.locations
        )
        items.append(
            f'<div style="background:#1f2937;margin:8px 0;padding:10px 14px;border-radius:6px">'
            f'<span style="padding:2px 8px;border-radius:3px;{cs}">{html.escape(f.severity)}</span> '
            f"<strong>[{html.escape(f.rule_id)}] {html.escape(f.name)}</strong> ×{f.count}"
            f'<div style="font-size:13px;color:#d1d5db;margin-top:4px">{html.escape(f.description)}</div>'
            f"{locs}</div>"
        )
    flows = "".join(
        f'<div style="color:#f87171;margin:6px 0">Possible exfiltration flow: {html.escape(x)} '
        "reads sensitive data and has an outbound channel</div>"
        for x in cr.exfil_flows
    )
    domains = ""
    if cr.external_domains:
        domains = (
            '<div style="font-size:12px;color:#9ca3af;margin-top:8px">External domains: '
            + html.escape(", ".join(cr.external_domains[:30]))
            + "</div>"
        )
    empty = (
        "" if items else '<div style="color:#34d399">No suspicious code patterns detected.</div>'
    )
    return h2 + note + empty + "".join(items) + flows + domains


def _trust_html(store) -> str:
    parts = []
    if store.verified:
        parts.append('<span style="color:#4ade80">✓ Verified</span>')
    if store.established:
        parts.append('<span style="color:#67e8f9">Established</span>')
    if not parts:
        parts.append('<span style="color:#6b7280">Not verified</span>')
    return " · ".join(parts)


def _tpci_detail_html(tpci) -> str:
    if not tpci.hit:
        return ""
    labels = {
        0: "Under investigation",
        1: "Researcher confirmed",
        2: "Google confirmed",
        3: "Google + researcher confirmed",
    }
    parts = [labels.get(tpci.confirm_mal, "Unknown")]
    if tpci.threat_types:
        parts.append(f"Types: {html.escape(', '.join(tpci.threat_types))}")
    if tpci.tpci_behavioral not in ("unknown", ""):
        parts.append(f"Behavioral: {html.escape(tpci.tpci_behavioral)}")
    return " | ".join(parts)


def _sentry_detail_html(sentry) -> str:
    if not sentry.hit:
        return ""
    parts = [html.escape(sentry.reason or "Flagged")]
    if sentry.blocklist:
        parts.append('<span style="color:#dc2626">BLOCKLISTED</span>')
    return " | ".join(parts)


def _liveness_detail_html(liveness) -> str:
    if liveness.google_malware_confirmed:
        return '<span style="color:#dc2626">_malware=true (authoritative)</span>'
    if liveness.store_likely_removed:
        return f'<span style="color:#ca8a04">Likely removed (status={html.escape(liveness.status_xml)})</span>'
    return html.escape(f"status={liveness.status_xml}")
