"""
Extractor: unzip .crx/.xpi to a temp directory.
Registers atexit cleanup so temp dirs are always removed.
"""

from __future__ import annotations

import atexit
import io
import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .downloader import DownloadResult

# Global registry of temp dirs to clean up on exit
_TEMP_DIRS: list[Path] = []


def _cleanup_temp_dirs() -> None:
    for d in _TEMP_DIRS:
        try:
            shutil.rmtree(d, ignore_errors=True)
        except Exception:  # noqa: S110 — cleanup, log suppressed intentionally
            pass


atexit.register(_cleanup_temp_dirs)


class ExtractionError(Exception):
    pass


@dataclass
class ExtractResult:
    tmp_dir: Path
    manifest_path: Path
    files: list[str]  # relative paths of all extracted files
    js_files: list[str]  # relative paths of .js files only


def extract(download: DownloadResult) -> ExtractResult:
    """
    Extract the ZIP portion of a CRX/XPI into a fresh temp directory.
    Returns ExtractResult with paths to all extracted files.
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="extanalyze_extract_"))
    _TEMP_DIRS.append(tmp_dir)

    # Read raw bytes and slice to ZIP portion
    with open(download.path, "rb") as f:
        raw = f.read()

    zip_data = raw[download.zip_offset :]

    try:
        with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
            # Security: prevent zip-slip path traversal
            for member in zf.namelist():
                dest = (tmp_dir / member).resolve()
                if not str(dest).startswith(str(tmp_dir)):
                    raise ExtractionError(f"Zip-slip attempt detected: {member}")

            zf.extractall(tmp_dir)
            all_files = zf.namelist()

    except zipfile.BadZipFile as e:
        raise ExtractionError(
            f"Failed to open ZIP content (offset {download.zip_offset}): {e}"
        ) from e

    # Locate manifest.json - should be at root or one level deep
    manifest_path = _find_manifest(tmp_dir)
    if manifest_path is None:
        raise ExtractionError("manifest.json not found in extracted extension")

    js_files = [f for f in all_files if f.endswith(".js")]

    return ExtractResult(
        tmp_dir=tmp_dir,
        manifest_path=manifest_path,
        files=all_files,
        js_files=js_files,
    )


def _find_manifest(base: Path) -> Path | None:
    """
    Find manifest.json. Check root first, then one directory deep.
    Some extensions wrap their content in a subdirectory.
    """
    root_manifest = base / "manifest.json"
    if root_manifest.exists():
        return root_manifest

    # One level deep (some edge cases)
    for child in base.iterdir():
        if child.is_dir():
            candidate = child / "manifest.json"
            if candidate.exists():
                return candidate

    return None
