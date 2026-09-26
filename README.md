# extanalyze

Browser extension static analysis and threat intelligence CLI.

Analyzes Chrome, Edge, and Firefox extensions against multiple threat intelligence
databases and performs permission risk analysis with MV2/MV3 awareness.

## Features

- **Threat Intelligence**: TPCI (7,400+ known malicious extensions), malicious_extension_sentry, Google CRX API malware flag
- **Manifest Analysis**: Full MV2/MV3 permission parsing with per-permission abuse description
- **Permission Risk Scoring**: Taxonomy of 30+ permissions with CRITICAL/HIGH/MEDIUM/LOW ratings
- **Dangerous Combo Detection**: 15 combo rules (Universal Code Injection, Cookie Theft Pipeline, C2 + Persistence, etc.)
- **Host Scope Assessment**: BROAD / SCOPED / MINIMAL classification — flags `<all_urls>` vs scoped domain lists
- **Permission Necessity**: Category-based analysis of whether permissions match the extension's stated purpose
- **Publisher Trust**: Verified/Established publisher status from Chrome Web Store
- **Bulk analysis**: ThreadPoolExecutor with progress bar, TI caches pre-loaded once
- **Output formats**: Rich terminal, JSON, CSV, HTML (single + bulk aggregated reports)

## Install

```bash
# Development (editable)
git clone https://github.com/YOUR_USERNAME/extanalyze
cd extanalyze
python -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
# Single extension (auto-detects browser from ID format)
extanalyze analyze cjpalhdlnbpafiamejdnhcphjbkeiagm

# Force browser
extanalyze analyze ublock-origin --browser firefox

# All output formats
extanalyze analyze bmnlcjabgnpnenekpadlanbbkooimhnj \
  --output all --out-dir ./reports

# Bulk analysis from file
extanalyze analyze --file ids.txt --output csv --out-dir ./reports --workers 12

# With local CRX catalog for name enrichment (386k extensions)
extanalyze analyze --file ids.txt \
  --catalog /path/to/2023-10-18_list_of_all_crx.csv \
  --output all --out-dir ./reports

# Cache management
extanalyze cache status
extanalyze cache clear
```

## Threat Intelligence Sources

| Source | Coverage | Auth |
|--------|----------|------|
| [TPCI](https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids) | 7,484 Chrome/Edge extensions | Free |
| [malicious_extension_sentry](https://github.com/toborrm9/malicious_extension_sentry) | 6,794 extensions with SHA256 | Free |
| Google CRX API | `_malware=true` flag (authoritative) | Free |
| VirusTotal | File hash reputation | API key (optional) |

TI datasets are cached locally for 24 hours (`~/.extanalyze/cache/`).

## Pipeline

CI runs on every push and PR:

- **Lint** — ruff check + format
- **SAST** — bandit (medium+ severity/confidence), results uploaded as SARIF to GitHub Security tab
- **SCA** — pip-audit against OSV + PyPI advisory database
- **Tests** — pytest on Python 3.10–3.13 with coverage
- **Build** — wheel + sdist, twine check

```bash
# Run all checks locally before pushing
ruff check extanalyze/ && ruff format --check extanalyze/
bandit -r extanalyze/ -ll -ii
pytest tests/ --cov=extanalyze --cov-fail-under=60
```

## Risk Levels

| Level | Score | Meaning |
|-------|-------|---------|
| SAFE | 0 | No signals |
| LOW | 1–20 | Informational |
| MEDIUM | 21–40 | Warrants review |
| HIGH | 41–70 | Confirmed TI hit or critical combo |
| CRITICAL | 71+ | Confirmed malicious — Google/researcher confirmed |

Any confirmed TI hit (TPCI, Sentry blocklist, Google malware flag) forces minimum HIGH regardless of score.

## License

MIT
