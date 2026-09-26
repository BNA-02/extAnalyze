"""
Downloader: fetch .crx (Chrome/Edge) or .xpi (Firefox) to a temp file.
Returns path + SHA256 hash. Does NOT execute anything.
"""

from __future__ import annotations

import hashlib
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path

import requests

# Chrome/Edge CWS download endpoint
_CWS_DOWNLOAD_URL = (
    "https://clients2.google.com/service/update2/crx"
    "?response=redirect"
    "&acceptformat=crx2,crx3"
    "&prodversion=120.0.0.0"
    "&x=id%3D{ext_id}%26installsource%3Dondemand%26uc"
)

# Edge Add-ons uses same Chromium infrastructure - same endpoint works
_EDGE_DOWNLOAD_URL = _CWS_DOWNLOAD_URL

# Firefox AMO metadata endpoint (to get the actual download URL)
_AMO_ADDON_URL = "https://addons.mozilla.org/api/v5/addons/addon/{ext_id}/"

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

MAX_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB hard cap


class ExtensionNotDownloadableError(Exception):
    pass


@dataclass
class DownloadResult:
    path: Path  # temp file path (caller must clean up or use extractor)
    sha256: str  # hex digest of raw file bytes
    size_bytes: int
    crx_format: str  # "crx2", "crx3", "xpi", "zip"
    zip_offset: int  # byte offset where ZIP content starts inside the file


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _detect_crx_format(data: bytes) -> tuple[str, int]:
    """
    Detect CRX format and return (format_name, zip_start_offset).

    CRX3: magic "Cr24" + 4 bytes version (==3) + 4 bytes header_size
          ZIP starts at offset: 12 + header_size

    CRX2: magic "Cr24" + 4 bytes version (==2) + 4 bytes pubkey_len + 4 bytes sig_len
          ZIP starts at offset: 16 + pubkey_len + sig_len

    Plain ZIP / XPI: magic PK\x03\x04 at offset 0
    """
    if len(data) < 4:
        raise ExtensionNotDownloadableError("File too small to be a valid extension")

    magic = data[:4]

    if magic == b"Cr24":
        if len(data) < 12:
            raise ExtensionNotDownloadableError("Truncated CRX header")
        version = struct.unpack_from("<I", data, 4)[0]

        if version == 3:
            header_size = struct.unpack_from("<I", data, 8)[0]
            zip_offset = 12 + header_size
            return "crx3", zip_offset

        elif version == 2:
            pubkey_len = struct.unpack_from("<I", data, 8)[0]
            sig_len = struct.unpack_from("<I", data, 12)[0]
            zip_offset = 16 + pubkey_len + sig_len
            return "crx2", zip_offset

        else:
            raise ExtensionNotDownloadableError(f"Unknown CRX version: {version}")

    elif magic[:2] == b"PK":
        return "zip", 0

    else:
        raise ExtensionNotDownloadableError(
            f"Unrecognised file format (magic bytes: {magic.hex()})"
        )


def _download_bytes(url: str, timeout: int = 30) -> bytes:
    """Download URL, follow redirects, return raw bytes. Enforces MAX_SIZE_BYTES."""
    try:
        resp = requests.get(url, headers=_HEADERS, timeout=timeout, stream=True)
    except requests.RequestException as e:
        raise ExtensionNotDownloadableError(f"Network error: {e}") from e

    if resp.status_code == 404:
        raise ExtensionNotDownloadableError("Extension not found (404) - may have been removed")
    if resp.status_code == 204:
        raise ExtensionNotDownloadableError(
            "Extension not downloadable (204 No Content) - may be restricted or region-locked"
        )
    if resp.status_code != 200:
        raise ExtensionNotDownloadableError(f"Unexpected HTTP {resp.status_code} from {url}")

    chunks = []
    total = 0
    for chunk in resp.iter_content(chunk_size=65536):
        total += len(chunk)
        if total > MAX_SIZE_BYTES:
            raise ExtensionNotDownloadableError(
                f"Extension exceeds {MAX_SIZE_BYTES // 1024 // 1024}MB size cap"
            )
        chunks.append(chunk)

    return b"".join(chunks)


def _get_firefox_download_url(ext_id: str, timeout: int = 10) -> str:
    """Resolve Firefox extension ID to actual .xpi download URL via AMO API."""
    url = _AMO_ADDON_URL.format(ext_id=ext_id)
    try:
        resp = requests.get(url, headers=_HEADERS, timeout=timeout)
    except requests.RequestException as e:
        raise ExtensionNotDownloadableError(f"AMO API error: {e}") from e

    if resp.status_code == 404:
        raise ExtensionNotDownloadableError(f"Firefox addon '{ext_id}' not found on AMO")
    if resp.status_code != 200:
        raise ExtensionNotDownloadableError(f"AMO API HTTP {resp.status_code}")

    data = resp.json()
    try:
        xpi_url = data["current_version"]["file"]["url"]
        return xpi_url
    except (KeyError, TypeError) as e:
        raise ExtensionNotDownloadableError(f"AMO response missing download URL: {e}") from e


def download(ext_id: str, browser: str, timeout: int = 30) -> DownloadResult:
    """
    Download an extension and return DownloadResult with temp file path and metadata.
    Caller is responsible for cleanup (extractor handles this via atexit).
    """
    if browser in ("chrome", "edge"):
        url = _CWS_DOWNLOAD_URL.format(ext_id=ext_id)
        data = _download_bytes(url, timeout=timeout)
        sha = _sha256(data)
        crx_format, zip_offset = _detect_crx_format(data)

    elif browser == "firefox":
        xpi_url = _get_firefox_download_url(ext_id, timeout=timeout)
        data = _download_bytes(xpi_url, timeout=timeout)
        sha = _sha256(data)
        crx_format, zip_offset = "xpi", 0  # XPI is plain zip

    else:
        raise ValueError(f"Unsupported browser: {browser}")

    # Write to named temp file (suffix helps with debugging)
    suffix = ".xpi" if browser == "firefox" else ".crx"
    tmp = tempfile.NamedTemporaryFile(
        prefix=f"extanalyze_{ext_id}_",
        suffix=suffix,
        delete=False,
    )
    tmp.write(data)
    tmp.close()

    return DownloadResult(
        path=Path(tmp.name),
        sha256=sha,
        size_bytes=len(data),
        crx_format=crx_format,
        zip_offset=zip_offset,
    )
