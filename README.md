# extanalyze

Static security analysis and threat intelligence CLI for browser extensions.

Supports Chrome, Edge (Chromium), and Firefox. Analyzes extensions without
executing them — downloads the CRX/XPI, parses the manifest, scores every
permission, detects dangerous combinations, and cross-references three threat
intelligence databases.

---

## Features

**Threat Intelligence**
- [TPCI](https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids) — researcher-confirmed malicious extensions
- [Malext/Sentry](https://github.com/malvuln/malext) — community malware database with SHA256 cross-check post-download
- Store liveness — Chrome CRX API, Edge Add-ons API, Firefox AMO availability check

**Static Permission Analysis**
- 58-entry permission taxonomy with MV2 and MV3 specific abuse descriptions
- 11 CRITICAL and 16 HIGH risk permissions fully documented
- 28 dangerous permission combination rules (COMBO_001 through COMBO_027)
- Host permission scope classification: BROAD / SCOPED / MINIMAL
- WebSocket (`ws://`, `wss://`) patterns correctly separated from named permissions
- Permission necessity mapping against 15 extension categories

**Multi-Browser**
- Chrome: Chrome Web Store JSON API (no HTML scraping)
- Edge: Microsoft Edge Add-ons product API
- Firefox: Firefox AMO public REST API
- Auto-detection: probes Chrome CRX API + Edge product API when no `--browser` flag given
- Cross-listed extensions detected and annotated (Chrome + Edge)
- Built-in browser extensions (PDF Viewer, Media Router) recognized and skipped

**MV2 vs MV3 awareness**
- Manifest version detected and displayed on every analysis
- Permission abuse descriptions are version-aware
- Combos gate on MV2-only / MV3-only where relevant
- `webRequestBlocking` (MV2-only MITM) distinguished from read-only MV3 webRequest

**Output**
- Rich terminal report (color-coded risk, tables, combo details)
- JSON (`--output json`) for CI/pipeline integration
- Bulk mode: `--file ids.txt` with multithreaded analysis

---

## Installation

```bash
git clone <repo-url>
cd extanalyze
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

Python 3.10+ required.

---

## Usage

```bash
# Single extension — auto-detect browser
extanalyze analyze cjpalhdlnbpafiamejdnhcphjbkeiagm

# Force browser
extanalyze analyze cjpalhdlnbpafiamejdnhcphjbkeiagm --browser chrome
extanalyze analyze amnbcmdbanbkjhnfoeceemmmdiepnbpp --browser edge
extanalyze analyze uBlock0@raymondhill.net --browser firefox

# Bulk analysis from file
extanalyze analyze --file ids.txt
extanalyze analyze --file ids.txt --browser edge

# JSON output
extanalyze analyze <id> --output json
extanalyze analyze --file ids.txt --output json > results.json

# Cache management
extanalyze cache status
extanalyze cache clear
```

**ids.txt format** — one extension ID per line, blank lines and `#` comments ignored:

```
# Chrome extensions
cjpalhdlnbpafiamejdnhcphjbkeiagm
bmnlcjabgnpnenekpadlanbbkooimhnj

# Firefox
uBlock0@raymondhill.net
```

---

## Risk Scoring

| Verdict  | Score  |
|----------|--------|
| SAFE     | 0      |
| LOW      | 1–15   |
| MEDIUM   | 16–35  |
| HIGH     | 36–70  |
| CRITICAL | 71+    |

Score sources: TI database hits (short-circuit to minimum HIGH on confirmed malicious),
permission risk scores, dangerous combo points, unexpected permissions for category.

---

## Permission Taxonomy

58 permissions documented with:
- Risk score (1–10)
- Sensitivity (LOW / MEDIUM / HIGH / CRITICAL)
- MV2 abuse scenario
- MV3 abuse scenario (or delta from MV2)
- Data exfil / C2 / privilege escalation flags

Selected CRITICAL entries:

| Permission | Score | Why |
|---|---|---|
| `webRequestFilterResponse.serviceWorkerScript` | 10 | Inject code into target site's service worker — runs at site origin, persists after extension removal |
| `debugger` | 10 | Full tab control: intercept network at protocol level, read JS vars, capture screenshots |
| `webAuthenticationProxy` | 9 | MITM on FIDO2/passkey authentication |
| `userScripts` | 9 | Arbitrary JS injection bypassing MV3 CSP restrictions |
| `webRequestFilterResponse` | 9 | Response body MITM — read and modify page content as it streams |
| `nativeMessaging` | 9 | Full browser sandbox escape to host OS |
| `vpnProvider` | 9 | Route all device traffic through attacker infrastructure (ChromeOS) |

---

## Dangerous Combo Detection

28 rules fire when specific permission combinations appear together.
Examples:

| ID | Name | Severity |
|---|---|---|
| COMBO_002 | Cookie Theft Pipeline | CRITICAL |
| COMBO_006 | Universal Code Injection | CRITICAL |
| COMBO_025 | Service Worker Script Injection | CRITICAL |
| COMBO_024 | Response Body MITM (filterResponseData) | CRITICAL |
| COMBO_001 | Full MITM Stack (MV2) | CRITICAL |
| COMBO_016 | Sandbox Evasion Suite (cpu+memory) | HIGH |
| COMBO_027 | DNS Tunnel Exfiltration | HIGH |
| COMBO_019 | Evidence Destruction (browsingData) | HIGH |

---

## Threat Intelligence Sources

| Source | Type | Update |
|---|---|---|
| TPCI | Researcher-confirmed malicious extension IDs | On first run, cached 24h |
| Malext/Sentry | Community malware DB + SHA256 post-download | On first run, cached 24h |
| Chrome CRX API | Liveness + Google malware flag | Live per analysis |
| Edge Add-ons API | Liveness + metadata | Live per analysis |
| Firefox AMO | Liveness + metadata | Live per analysis |

Cache lives at `~/.extanalyze/cache/`.

---

## Development

```bash
pip install -e '.[dev]'

# Lint
ruff check extanalyze/
ruff format extanalyze/

# Tests (72 unit tests, no network)
pytest tests/ -v

# SAST
bandit -r extanalyze/ -c pyproject.toml

# SCA
pip-audit
```

CI runs on push/PR via `.github/workflows/ci.yml`:
lint → format check → unit tests → bandit → pip-audit.

---

## Project Layout

```
extanalyze/
  cli.py                  Click CLI entrypoint
  worker.py               Single + bulk analysis pipeline
  core/
    ingestion.py          ID parsing, browser detection, bulk file loading
    downloader.py         CRX/XPI download (Chrome, Edge, Firefox endpoints)
    extractor.py          CRX/XPI unpack to temp dir
    manifest_parser.py    manifest.json parsing, MV2/MV3, permission extraction
    store_meta.py         CWS JSON API, Edge product API, AMO API, probe_stores()
    enrichment.py         Catalog lookup, builtin registry, categorization
  analysis/
    permissions.py        Permission scoring, host scope, combo detection
    categorizer.py        Extension category inference from name/description
  intel/
    tpci.py               TPCI dataset loader and ID lookup
    sentry.py             Malext/Sentry dataset loader, ID + SHA256 lookup
  scoring/
    aggregator.py         Risk score + reason assembly
    result.py             AnalysisResult dataclass
  output/
    text_reporter.py      Rich terminal output
    html_reporter.py      HTML report
  data/
    permissions_taxonomy.json    58 permissions with abuse descriptions
    danger_combos.json           28 combination rules
    category_baselines.json      15 extension categories with expected permissions
    crx_catalog.csv              Chrome extension catalog snapshot (2023-10-18)
tests/
  test_ingestion.py
  test_manifest_parser.py
  test_permissions.py
  test_aggregator.py
  test_intel.py
.github/workflows/ci.yml
```

---

## Limitations

- **Static analysis only** — no dynamic execution, no runtime network capture
- **CRX catalog snapshot** — Chrome catalog dated 2023-10-18; newer extensions fall back to live store metadata
- **CWS JSON API** — undocumented internal endpoint (`xY2Ddd` RPC); may break if Google changes the frontend
- **Permission necessity mapping** — rule-based heuristics per category, not semantic reasoning
- **No Firefox built-in registry** — Firefox built-in extensions not enumerated

---

## License

Private. All rights reserved.
