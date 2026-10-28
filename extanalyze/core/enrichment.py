"""
Enrichment: resolve extension name and category from:
1. Store metadata (most authoritative)
2. 2023 CRX catalog (~386k extensions): Chrome extension ID to name inventory published by
   Hexacorn (https://www.hexacorn.com/blog/2023/10/20/mapping-chrome-extension-ids-to-their-names-part-2/)
3. Built-in extension hardcoded list
Falls back to UNKNOWN.
"""

from __future__ import annotations

import csv
import sys
from dataclasses import dataclass
from pathlib import Path

import msgpack

# Cache location
_CACHE_DIR = Path.home() / ".extanalyze" / "cache"
_CATALOG_INDEX_PATH = _CACHE_DIR / "crx_catalog_index.msgpack"

# The in-memory index: {ext_id: {"name": str, "description": str}}
_CATALOG: dict[str, dict] | None = None

# Small hardcoded list of Chrome/Edge/Firefox built-in extensions
# These won't be in the CWS or AMO public APIs
_BUILTIN_EXTENSIONS: dict[str, dict] = {
    # Chrome built-ins
    "nmmhkkegccagdldgiimedpiccmgmieda": {
        "name": "Google Wallet",
        "category": "productivity",
        "browser": "chrome",
    },
    "mhjfbmdgcfjbbpaeojofohoefgiehjai": {
        "name": "Chrome PDF Viewer",
        "category": "productivity",
        "browser": "chrome",
    },
    "neajdppkdcdipfabeoofebfddakdcjhd": {
        "name": "Google Network Speech",
        "category": "accessibility",
        "browser": "chrome",
    },
    "pkedcjkdefgpdelpbcmbmeomcjbeemfm": {
        "name": "Chrome Media Router",
        "category": "productivity",
        "browser": "chrome",
    },
    "apdfllckaahabafndbhieahigkjlhalf": {
        "name": "Google Drive",
        "category": "productivity",
        "browser": "chrome",
    },
    "aohghmighlieiainnegkcijnfilokake": {
        "name": "Google Docs",
        "category": "productivity",
        "browser": "chrome",
    },
    "felcaaldnbdncclmgdcncolpebgiejap": {
        "name": "Google Sheets",
        "category": "productivity",
        "browser": "chrome",
    },
    "aapocclcgogkmnckokdopfmhonfmgoek": {
        "name": "Google Slides",
        "category": "productivity",
        "browser": "chrome",
    },
    "coobgpohoikkiipiblmjeljniedjpjpf": {
        "name": "Google Search",
        "category": "search",
        "browser": "chrome",
    },
    "mfehgcgbbipciphmccgaenjidiccnmng": {
        "name": "Cloud Print",
        "category": "productivity",
        "browser": "chrome",
    },
    "gbchcmhmhahfdphkhkmpfmihenigjmpp": {
        "name": "Google Wallet (Pay)",
        "category": "productivity",
        "browser": "chrome",
    },
    "emahakmocgideepebncgnmlmliepgpgb": {
        "name": "Google Feedback",
        "category": "productivity",
        "browser": "chrome",
    },
    "hfnkpimlhhgieaddgfemjhofmfblmnib": {
        "name": "Chrome Accessibility Helper",
        "category": "accessibility",
        "browser": "chrome",
    },
    # Edge built-ins
    "jmjflgjpcpepeafmmgdpfkogkghcpiha": {
        "name": "Microsoft Edge PDF Viewer",
        "category": "productivity",
        "browser": "edge",
    },
    "dpbkbhflmcgmlahifnlekgaocmgoidem": {
        "name": "Microsoft Shopping",
        "category": "shopping",
        "browser": "edge",
    },
}


@dataclass
class EnrichmentResult:
    name: str  # best available name
    description: str
    source: str  # "store", "catalog", "builtin", "unknown"
    is_builtin: bool
    catalog_warning: str  # non-empty if catalog data may be stale


# The catalog is a 2023 snapshot. Extensions added after Oct 2023 won't be in it.
_CATALOG_VINTAGE = "2023-10-18"
_CATALOG_WARNING = (
    f"CRX catalog is a {_CATALOG_VINTAGE} snapshot — extensions published after this date "
    "will not be found here. Store metadata is the authoritative fallback."
)


def enrich(ext_id: str, store_name: str = "", store_description: str = "") -> EnrichmentResult:
    """
    Resolve name and description for an extension.
    Priority: store metadata > catalog lookup > builtin list > UNKNOWN
    """
    # 1. Store metadata (most authoritative - live data)
    if store_name and store_name.strip():
        return EnrichmentResult(
            name=store_name.strip(),
            description=store_description,
            source="store",
            is_builtin=False,
            catalog_warning="",
        )

    # 2. Built-in list (hardcoded, no staleness issue)
    if ext_id in _BUILTIN_EXTENSIONS:
        b = _BUILTIN_EXTENSIONS[ext_id]
        return EnrichmentResult(
            name=b["name"],
            description="",
            source="builtin",
            is_builtin=True,
            catalog_warning="",
        )

    # 3. CRX catalog (Oct 2023 snapshot - NOT authoritative for post-2023 extensions)
    catalog = _get_catalog()
    if catalog and ext_id in catalog:
        entry = catalog[ext_id]
        return EnrichmentResult(
            name=entry.get("name", ""),
            description=entry.get("description", ""),
            source="catalog",
            is_builtin=False,
            catalog_warning=_CATALOG_WARNING,
        )

    return EnrichmentResult(
        name="",
        description="",
        source="unknown",
        is_builtin=False,
        catalog_warning=_CATALOG_WARNING,
    )


def load_catalog(csv_path: Path, force_rebuild: bool = False) -> None:
    """
    Build and cache the msgpack index from the CRX catalog CSV.
    Call this once at startup if the user has provided the catalog path.
    Subsequent runs load the msgpack cache (fast).
    """
    global _CATALOG
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)

    if not force_rebuild and _CATALOG_INDEX_PATH.exists():
        _CATALOG = _load_msgpack_index()
        print(f"[catalog] Loaded {len(_CATALOG):,} extensions from cache", file=sys.stderr)
        return

    print(f"[catalog] Building index from {csv_path} ...", file=sys.stderr)
    index: dict[str, dict] = {}

    with open(csv_path, encoding="utf-8-sig", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ext_id = row.get("crx_id", "").strip().lower()
            if not ext_id:
                continue
            index[ext_id] = {
                "name": row.get("crx_name", "").strip(),
                "description": row.get("crx_description", "").strip(),
            }

    _save_msgpack_index(index)
    _CATALOG = index
    print(
        f"[catalog] Indexed {len(index):,} extensions, saved to {_CATALOG_INDEX_PATH}",
        file=sys.stderr,
    )


def _get_catalog() -> dict[str, dict] | None:
    global _CATALOG
    if _CATALOG is not None:
        return _CATALOG

    # Try loading from cache without requiring the original CSV
    if _CATALOG_INDEX_PATH.exists():
        try:
            _CATALOG = _load_msgpack_index()
        except Exception:
            _CATALOG = None
    return _CATALOG


def _save_msgpack_index(index: dict[str, dict]) -> None:
    with open(_CATALOG_INDEX_PATH, "wb") as f:
        msgpack.pack(index, f, use_bin_type=True)


def _load_msgpack_index() -> dict[str, dict]:
    with open(_CATALOG_INDEX_PATH, "rb") as f:
        return msgpack.unpack(f, raw=False)
