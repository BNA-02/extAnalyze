"""
extractor.py — Extract JS source units from .js files and inline <script> blocks in HTML.

Limits applied to keep deep analysis fast:
- Skips known vendor/npm/lib/dist directories (third-party code)
- Skips files larger than MAX_FILE_BYTES (minified bundles add noise, not signal)
- Caps total units at MAX_UNITS per extension with a stderr warning
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

# Third-party directory names — skip their JS files for pattern analysis.
# RetireJS still scans ALL JS files (including these) for vulnerable library detection.
_VENDOR_DIRS = frozenset(
    {
        "node_modules",
        "npm",
        "vendor",
        "vendors",
        "lib",
        "libs",
        "dist",
        "third_party",
        "thirdparty",
        "bower_components",
        "jspm_packages",
    }
)

_MAX_FILE_BYTES = 300_000  # 300 KB — larger files are almost always bundles
_MAX_UNITS = 200  # cap total source units per extension


@dataclass
class SourceUnit:
    """One unit of JavaScript source to analyze."""

    file: str  # relative path
    source: str  # raw JS text
    line_offset: int  # line number where this unit starts (1 for whole files, N for inline)
    origin: str  # "js_file" | "inline_script"


_SCRIPT_TAG_RE = re.compile(
    r"<script(?:[^>]*)>(.+?)</script>",
    re.DOTALL | re.IGNORECASE,
)
_SCRIPT_SRC_RE = re.compile(r"<script[^>]+src\s*=", re.IGNORECASE)


def _is_vendor_path(rel_path: str) -> bool:
    """Return True if the path lives inside a known vendor/third-party directory."""
    parts = rel_path.replace("\\", "/").split("/")
    return any(p.lower() in _VENDOR_DIRS for p in parts[:-1])


def extract_source_units(tmp_dir: Path, all_files: list[str]) -> list[SourceUnit]:
    """
    Return SourceUnit objects for:
    - .js files outside vendor/lib/dist dirs and under _MAX_FILE_BYTES
    - Inline <script> blocks in .html/.htm files

    Stops after _MAX_UNITS total.
    """
    units: list[SourceUnit] = []

    for rel_path in all_files:
        if len(units) >= _MAX_UNITS:
            print(
                f"[deep] Warning: capped at {_MAX_UNITS} source units "
                "(extension has many files — vendor dirs excluded automatically)",
                file=sys.stderr,
            )
            break

        path = tmp_dir / rel_path

        if not path.is_file():
            continue

        if rel_path.endswith(".js"):
            if _is_vendor_path(rel_path):
                continue
            try:
                if path.stat().st_size > _MAX_FILE_BYTES:
                    continue  # skip large bundles
                source = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            units.append(
                SourceUnit(
                    file=rel_path,
                    source=source,
                    line_offset=1,
                    origin="js_file",
                )
            )

        elif rel_path.endswith((".html", ".htm")):
            try:
                html = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for match in _SCRIPT_TAG_RE.finditer(html):
                tag_start = match.start()
                line_no = html[:tag_start].count("\n") + 1
                tag_text = html[tag_start : match.start(1)]
                if _SCRIPT_SRC_RE.search(tag_text):
                    continue
                inline_js = match.group(1)
                if inline_js.strip():
                    units.append(
                        SourceUnit(
                            file=rel_path,
                            source=inline_js,
                            line_offset=line_no,
                            origin="inline_script",
                        )
                    )

    return units
