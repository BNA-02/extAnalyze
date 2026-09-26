"""
Ingestion layer: parse input (single ID or bulk .txt file) and detect browser type.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

# Chrome/Edge extension IDs: exactly 32 lowercase chars a-p
_CHROME_ID_RE = re.compile(r"^[a-p]{32}$")
# Firefox AMO IDs: UUID or slug (letters, digits, hyphens, @)
_FIREFOX_ID_RE = re.compile(r"^[a-zA-Z0-9_\-@\.]{2,80}$")


@dataclass
class ExtensionInput:
    ext_id: str
    browser: str  # "chrome", "edge", "firefox"
    line_number: int = 0  # for bulk: original line number (error reporting)


class InvalidExtensionID(ValueError):
    pass


def detect_browser(ext_id: str, hint: str | None = None) -> str:
    """
    Determine browser from ID format and optional hint flag.

    Chrome/Edge IDs: 32 lowercase chars, only a-p (base26 encoding of CRX ID bytes)
    Firefox IDs: UUID format OR short slug from AMO

    Returns one of: "chrome", "edge", "firefox", "auto"
    "auto" means the caller should probe both Chrome and Edge stores to determine
    which store(s) list the extension.
    """
    if hint in ("chrome", "edge", "firefox"):
        return hint

    if _CHROME_ID_RE.match(ext_id):
        # 32-char a-p ID could be Chrome, Edge, or both.
        # Return "auto" so the worker can probe both stores.
        return "auto"

    # Firefox UUID format: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
    if re.match(r"^\{[0-9a-f-]{36}\}$", ext_id, re.IGNORECASE):
        return "firefox"

    # Firefox slug (e.g. ublock-origin, adguardadblocker@adguard.com)
    if re.match(r"^[a-z0-9][a-z0-9\-_@\.]+$", ext_id) and len(ext_id) < 80:
        return "firefox"

    raise InvalidExtensionID(
        f"Cannot determine browser for ID '{ext_id}'. Use --browser chrome|edge|firefox to specify."
    )


def parse_id(raw: str) -> str:
    """Strip whitespace and normalize to lowercase."""
    return raw.strip().lower()


def validate_chrome_id(ext_id: str) -> bool:
    return bool(_CHROME_ID_RE.match(ext_id))


def load_ids_from_file(path: Path, browser_hint: str | None = None) -> list[ExtensionInput]:
    """
    Read a .txt file with one extension ID per line.
    - Ignores blank lines and lines starting with #
    - Supports optional 'id,browser' CSV format per line
    - Reports invalid IDs as warnings, continues processing rest
    """
    results: list[ExtensionInput] = []
    errors: list[str] = []

    with open(path, encoding="utf-8-sig") as f:
        for lineno, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            # Support optional "id,browser" format
            parts = line.split(",")
            ext_id = parse_id(parts[0])
            line_browser = parts[1].strip().lower() if len(parts) > 1 else None
            effective_browser = line_browser or browser_hint

            try:
                browser = detect_browser(ext_id, effective_browser)
                results.append(ExtensionInput(ext_id=ext_id, browser=browser, line_number=lineno))
            except InvalidExtensionID as e:
                errors.append(f"  Line {lineno}: {e}")

    if errors:
        print(f"[!] {len(errors)} invalid IDs skipped:", file=sys.stderr)
        for err in errors[:10]:
            print(err, file=sys.stderr)
        if len(errors) > 10:
            print(f"  ... and {len(errors) - 10} more", file=sys.stderr)

    return results


def iter_single(ext_id: str, browser_hint: str | None = None) -> list[ExtensionInput]:
    """Wrap a single CLI-provided ID into a list for uniform handling."""
    ext_id = parse_id(ext_id)
    browser = detect_browser(ext_id, browser_hint)
    return [ExtensionInput(ext_id=ext_id, browser=browser)]
