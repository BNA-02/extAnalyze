import zipfile
from pathlib import Path

import pytest

from extanalyze.core import extractor
from extanalyze.core.downloader import DownloadResult
from extanalyze.core.extractor import ExtractionError, extract


def _dl(tmp_path: Path, members: dict[str, bytes]) -> DownloadResult:
    p = tmp_path / "ext.xpi"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return DownloadResult(
        path=p, sha256="", size_bytes=p.stat().st_size, crx_format="xpi", zip_offset=0
    )


def test_valid_archive(tmp_path):
    res = extract(_dl(tmp_path, {"manifest.json": b"{}", "a.js": b"x"}))
    assert res.manifest_path.exists()
    assert res.js_files == ["a.js"]
    extractor.cleanup_extraction(res.tmp_dir)
    assert not res.tmp_dir.exists()


def test_zip_slip_rejected(tmp_path):
    with pytest.raises(ExtractionError, match="Zip-slip"):
        extract(_dl(tmp_path, {"../evil.txt": b"x", "manifest.json": b"{}"}))


def test_sibling_prefix_path_rejected(tmp_path):
    # "<tmp>_evil" shares a string prefix with "<tmp>" but is outside it
    with pytest.raises(ExtractionError, match="Zip-slip"):
        extract(_dl(tmp_path, {"../../" + "x" * 3: b"x"}))


def test_zip_bomb_ratio_rejected(tmp_path):
    with pytest.raises(ExtractionError):
        extract(_dl(tmp_path, {"manifest.json": b"{}", "bomb.bin": b"\0" * (50 * 1024 * 1024)}))


def test_total_size_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(extractor, "MAX_TOTAL_UNCOMPRESSED", 1000)
    with pytest.raises(ExtractionError, match="exceeds limit"):
        extract(_dl(tmp_path, {"manifest.json": b"{}", "a": b"abc" * 400, "b": b"xyz" * 400}))


def test_entry_count_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(extractor, "MAX_ENTRIES", 2)
    with pytest.raises(ExtractionError, match="too many"):
        extract(_dl(tmp_path, {f"f{i}": b"x" for i in range(5)}))
