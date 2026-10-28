# extanalyze

Static security analysis and threat intelligence CLI for browser extensions.

Supports Chrome, Edge (Chromium), and Firefox. Analyzes extensions without
executing them. It downloads the CRX/XPI, parses the manifest, scores every
permission, detects dangerous combinations, and cross-references three threat
intelligence databases.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Risk Scoring](#risk-scoring)
- [Permission Taxonomy](#permission-taxonomy)
- [Dangerous Combo Detection](#dangerous-combo-detection)
- [Threat Intelligence Sources](#threat-intelligence-sources)
- [Contributing](#contributing)
- [Project Layout](#project-layout)
- [Code review](#code-review)
- [Limitations](#limitations)
- [Acknowledgements](#acknowledgements)
- [License](#license)

## Features

**Threat Intelligence**
- [TPCI](https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids): researcher-confirmed malicious extensions
- [Malext/Sentry](https://github.com/malvuln/malext): community malware database with SHA256 cross-check post-download
- Store liveness: Chrome CRX API, Edge Add-ons API, Firefox AMO availability check

**Static Permission Analysis**
- 58-entry permission taxonomy with MV2 and MV3 specific abuse descriptions
- 11 CRITICAL and 16 HIGH risk permissions fully documented
- 28 dangerous permission combination rules (COMBO_001 through COMBO_027)
- Host permission scope classification: BROAD / SCOPED / MINIMAL
- Permission necessity mapping against 15 extension categories

**Multi-Browser**
- Chrome: Chrome Web Store JSON API
- Edge: Microsoft Edge Add-ons product API
- Firefox: Firefox AMO public REST API
- Auto-detection: probes Chrome CRX API + Edge product API when no `--browser` flag given
- Built-in browser extensions (PDF Viewer, Media Router) recognized and skipped

**MV2 vs MV3 awareness**
- Manifest version detected and displayed on every analysis
- Permission abuse descriptions are version-aware example: `webRequestBlocking` (MV2-only MITM) distinguished from read-only MV3 webRequest

**Output**
- JSON (`--output json`) for CI/pipeline integration
- Bulk mode: `--file ids.txt` with multithreaded analysis

## Installation

Debian, Ubuntu, Kali (self-contained `.deb`, bundles its own Python under `/opt/extanalyze`):

```bash
# Download the .deb and SHA256SUMS from the latest GitHub Release, then:
sha256sum -c --ignore-missing SHA256SUMS
sudo apt install ./extanalyze_*_amd64.deb
extanalyze --version
```

Build it yourself with `packaging/build-deb.sh` (needs `uv` and `dpkg-deb`). A signed apt repository is planned.

From a clone (pip):

```bash
git clone https://github.com/BNA-02/extAnalyze.git
cd extAnalyze
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

With [uv](https://docs.astral.sh/uv/):

```bash
# Install as an isolated tool, straight from GitHub
uv tool install git+https://github.com/BNA-02/extAnalyze.git
# or run once without installing
uvx --from git+https://github.com/BNA-02/extAnalyze.git extanalyze --help

# From a clone, into the current environment
uv pip install .
```

Python 3.10+ required.

## Usage

```bash
# Single extension - auto-detect browser
extanalyze cjpalhdlnbpafiamejdnhcphjbkeiagm

# Force browser
extanalyze cjpalhdlnbpafiamejdnhcphjbkeiagm --browser chrome
extanalyze amnbcmdbanbkjhnfoeceemmmdiepnbpp --browser edge
extanalyze uBlock0@raymondhill.net --browser firefox

# Bulk analysis from file
extanalyze --file ids.txt
extanalyze --file ids.txt --browser edge

# JSON output
extanalyze <id> --output json
extanalyze --file ids.txt --output json > results.json

# Cache management
extanalyze cache status
extanalyze cache clear
```

**ids.txt format** - one extension ID per line, blank lines and `#` comments ignored:

```
# Chrome extensions
cjpalhdlnbpafiamejdnhcphjbkeiagm
bmnlcjabgnpnenekpadlanbbkooimhnj

# Firefox
uBlock0@raymondhill.net
```

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
| `webRequestFilterResponse.serviceWorkerScript` | 10 | Inject code into target site's service worker - runs at site origin, persists after extension removal |
| `debugger` | 10 | Full tab control: intercept network at protocol level, read JS vars, capture screenshots |
| `webAuthenticationProxy` | 9 | MITM on FIDO2/passkey authentication |
| `userScripts` | 9 | Arbitrary JS injection bypassing MV3 CSP restrictions |
| `webRequestFilterResponse` | 9 | Response body MITM - read and modify page content as it streams |
| `nativeMessaging` | 5 | Bridge to a native host app already installed on the endpoint (password managers, security agents); risk depends on that app |
| `vpnProvider` | 9 | Route all device traffic through attacker infrastructure (ChromeOS) |

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

## Threat Intelligence Sources

| Source | Type | Update |
|---|---|---|
| TPCI | Researcher-confirmed malicious extension IDs | On first run, cached 24h |
| Malext/Sentry | Community malware DB + SHA256 post-download | On first run, cached 24h |
| Chrome CRX API | Liveness + Google malware flag | Live per analysis |
| Edge Add-ons API | Liveness + metadata | Live per analysis |
| Firefox AMO | Liveness + metadata | Live per analysis |

Cache lives at `~/.extanalyze/cache/`.

## Dynamic analysis (`--dynamic`)

Static analysis never runs the extension. `--dynamic` additionally **executes it inside a disposable Docker sandbox** and observes what it does. It ships as an optional plugin so the core CLI stays light:

```bash
pip install "git+https://github.com/BNA-02/extAnalyze.git#subdirectory=plugins/dynamic"   # included in the .deb
extanalyze dynamic pull            # download the sandbox images (or: extanalyze dynamic build)
extanalyze <id> --dynamic          # add --dynamic-seconds N, --dynamic-workers N, --dynamic-network
```

- **What it does:** loads the extension in headless Chromium or Firefox, browses local test pages that impersonate popular sites (login and card forms, cookies and localStorage seeded with unique canary values), and records every external request. If a canary value shows up in an outbound request (raw, URL-encoded, base64, hex), that is confirmed exfiltration (`CR-RT-001`, CRITICAL).
- **Images:** `chromium-mv3` (current Chrome for Testing), `chromium-mv2` (Chrome for Testing 126, the last line that loads Manifest V2 extensions) and `firefox` (current Firefox driven through geckodriver, since Playwright cannot load Firefox extensions). The right image is picked per extension from its browser and manifest version, so mixed batches work; the dynamic step runs one container at a time by default (`--dynamic-workers N` runs up to N in parallel). Built on Red Hat Hardened Images (`registry.access.redhat.com/hi/nodejs`, non-root, no package manager), browsers and geckodriver pinned by version and SHA-256.
- **Isolation:** no network by default (attempts are still observed, nothing leaves), read-only filesystem, all capabilities dropped, no-new-privileges, pid/memory/cpu limits, extension mounted read-only, host-side timeout. `--dynamic-network` lets it reach the real internet; use it only on a machine you are willing to expose.
- **Scoring:** runtime-confirmed findings (`CR-RT-*`) are scored outside the static cap, with their own cap.
- **Firefox specifics:** traffic goes through a recording proxy inside the container that answers every external request locally, so `--dynamic-network` has no effect on Firefox. Firefox's own housekeeping hosts are ignored, and attributing a request to the background page versus a content script is best effort.
- **Limits:** evasive extensions (sleep timers, geo or user-agent checks, delayed activation) may not trigger; not exhaustive. A container is a strong boundary, not a perfect one: keep Docker up to date.

## Contributing

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for setup, tests, linting, security scans and CI.

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

## Code review

After extraction, `extanalyze/analysis/code_review.py` statically scans the extension's JS and HTML (never executing it) with about 45 rules:

- **Dynamic code loading**: `eval`, `new Function`, `importScripts`/`import()` of remote URLs, runtime script injection, remote `<script src>`
- **Exfiltration and C2**: `sendBeacon`, POSTs and fetches to hard-coded URLs, WebSockets, pixel beacons, polling, messaging other extensions
- **Sensitive data access**: cookies, history, password fields, keystrokes, clipboard, request interception
- **Secrets**: hard-coded API keys, AWS keys, private keys, tokens (matched text is redacted in reports)
- **Obfuscation**: packers, `_0x` identifiers, base64 blobs, `fromCharCode` chains, escape runs
- **CSP weaknesses** in `manifest.json`
- **Exfiltration flows**: a file that both reads sensitive data and has an outbound channel
- **Intel**: external domains, public IP addresses and Bitcoin addresses found in the code

Third-party directories (`lib/`, `vendor/`, `node_modules/`...) run only the HIGH and CRITICAL rules. Findings are heuristic leads for manual review, not verdicts. Score contribution is capped at 40 points. VirusTotal findings are scored outside that cap.

### `--deep`

`--deep` adds three extras to the same result (same findings list, same scoring):

- **AST data-flow check** (tree-sitter): flags sensitive data (cookies, history, storage, clipboard, password fields) that reaches `fetch`, `sendBeacon`, `.send` or an image beacon within the same file. Name-based taint, so it is stronger evidence than the regex "same file" heuristic but not a full analysis
- **Entropy analysis and static deobfuscation**: decodes base64 literals, hex/unicode escapes and `fromCharCode` lists, then re-runs the rules on the decoded text
- **RetireJS**: known-vulnerable bundled JavaScript libraries
- **VirusTotal**: domain reputation lookups when `VIRUSTOTAL_API_KEY` is set. Domains found in the extension are sent to VirusTotal.

## Limitations

- **Mostly regex-based code review**: the default scan has no AST (only `--deep` does, within a single file); obfuscated or split-up code can evade it
- **Static analysis only**: no dynamic execution, no runtime network capture
- **CRX catalog snapshot**: Chrome catalog dated 2023-10-18; newer extensions fall back to live store metadata
- **CWS JSON API**: undocumented internal endpoint (`xY2Ddd` RPC); may break if Google changes the frontend
- **Permission necessity mapping**: rule-based heuristics per category, not semantic reasoning
- **No Firefox built-in registry**: Firefox built-in extensions not enumerated

## Library use and scoring weights

```python
from extanalyze.api import analyze_extension, preload_intel, rescore, to_record

preload_intel()
record = to_record(analyze_extension("gighmmpiobklfepjocnamgkkbiglidom"))  # flat, snippet-free JSON
score, level = rescore(record)       # recompute offline, optionally with other weights
```

All scoring weights live in `extanalyze/data/scoring.json` (per-rule overrides in `rule_points`), and the score arithmetic in `extanalyze/scoring/signals.py`, so large-scale studies can re-score stored records without downloading anything again.

---

## Acknowledgements

- The Chrome extension ID to name catalog (`crx_catalog.csv`, snapshot of 2023-10-18) comes from [Mapping Chrome extension IDs to their names, part 2](https://www.hexacorn.com/blog/2023/10/20/mapping-chrome-extension-ids-to-their-names-part-2/) by Hexacorn. Thank you for publishing it.
- Threat intelligence: [TPCI](https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids) and [Malext/Sentry](https://github.com/malvuln/malext).

## License

Released under the [MIT License](LICENSE). You are free to use, modify and build on this tool, including in your own security research and tooling.

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities.
