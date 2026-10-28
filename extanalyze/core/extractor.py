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


# Zip-bomb guards (compressed input is already capped at 50 MB by the downloader)
MAX_ENTRIES = 10_000
MAX_TOTAL_UNCOMPRESSED = 500 * 1024 * 1024  # 500 MB
MAX_MEMBER_UNCOMPRESSED = 100 * 1024 * 1024  # 100 MB
MAX_COMPRESSION_RATIO = 200  # per member, applied above _RATIO_MIN_SIZE
_RATIO_MIN_SIZE = 1024 * 1024
_CHUNK = 64 * 1024


class ExtractionError(Exception):
    pass


def cleanup_extraction(tmp_dir: Path) -> None:
    """Remove an extraction directory now rather than waiting for atexit."""
    shutil.rmtree(tmp_dir, ignore_errors=True)
    try:
        _TEMP_DIRS.remove(tmp_dir)
    except ValueError:
        pass


def _safe_extract(zf: zipfile.ZipFile, tmp_dir: Path) -> list[str]:
    """Validate limits and path containment, then extract with byte counting."""
    infos = zf.infolist()
    if len(infos) > MAX_ENTRIES:
        raise ExtractionError(f"Archive has too many entries ({len(infos)} > {MAX_ENTRIES})")

    root = tmp_dir.resolve()
    declared_total = 0
    for info in infos:
        dest = (root / info.filename).resolve()
        if not dest.is_relative_to(root):
            raise ExtractionError(f"Zip-slip attempt detected: {info.filename}")
        if info.file_size > MAX_MEMBER_UNCOMPRESSED:
            raise ExtractionError(f"Archive member too large: {info.filename}")
        if (
            info.file_size > _RATIO_MIN_SIZE
            and info.file_size / max(info.compress_size, 1) > MAX_COMPRESSION_RATIO
        ):
            raise ExtractionError(f"Suspicious compression ratio: {info.filename}")
        declared_total += info.file_size
        if declared_total > MAX_TOTAL_UNCOMPRESSED:
            raise ExtractionError("Archive uncompressed size exceeds limit")

    # Headers can lie, so also count the bytes actually written.
    written_total = 0
    for info in infos:
        dest = (root / info.filename).resolve()
        if info.is_dir():
            dest.mkdir(parents=True, exist_ok=True)
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        member_written = 0
        with zf.open(info) as src, open(dest, "wb") as out:
            while chunk := src.read(_CHUNK):
                member_written += len(chunk)
                written_total += len(chunk)
                if (
                    member_written > MAX_MEMBER_UNCOMPRESSED
                    or written_total > MAX_TOTAL_UNCOMPRESSED
                ):
                    raise ExtractionError("Archive exceeded size limit during extraction")
                out.write(chunk)
    return [i.filename for i in infos]


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
            all_files = _safe_extract(zf, tmp_dir)

    except zipfile.BadZipFile as e:
        cleanup_extraction(tmp_dir)
        raise ExtractionError(
            f"Failed to open ZIP content (offset {download.zip_offset}): {e}"
        ) from e

    except ExtractionError:
        cleanup_extraction(tmp_dir)
        raise

    # Locate manifest.json - should be at root or one level deep
    manifest_path = _find_manifest(tmp_dir)
    if manifest_path is None:
        cleanup_extraction(tmp_dir)
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
