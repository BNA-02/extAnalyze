"""
Unit tests: core/ingestion.py
"""
import pytest
from extanalyze.core.ingestion import (
    detect_browser,
    iter_single,
    load_ids_from_file,
    parse_id,
    InvalidExtensionID,
)


class TestDetectBrowser:
    def test_chrome_id_detected(self):
        # 32 chars, a-p only
        assert detect_browser("cjpalhdlnbpafiamejdnhcphjbkeiagm") == "chrome"

    def test_hint_overrides_detection(self):
        assert detect_browser("cjpalhdlnbpafiamejdnhcphjbkeiagm", hint="edge") == "edge"

    def test_firefox_uuid_detected(self):
        assert detect_browser("{91f05833-bab1-4fb1-b9e4-187091a4d75d}") == "firefox"

    def test_firefox_slug_detected(self):
        assert detect_browser("ublock-origin") == "firefox"

    def test_invalid_id_raises(self):
        with pytest.raises(InvalidExtensionID):
            detect_browser("not-a-valid-id!!!")

    def test_hint_firefox_overrides(self):
        assert detect_browser("cjpalhdlnbpafiamejdnhcphjbkeiagm", hint="firefox") == "firefox"


class TestParseId:
    def test_strips_whitespace(self):
        assert parse_id("  abc  ") == "abc"

    def test_lowercases(self):
        assert parse_id("ABCDEF") == "abcdef"


class TestIterSingle:
    def test_returns_one_input(self):
        inputs = iter_single("cjpalhdlnbpafiamejdnhcphjbkeiagm")
        assert len(inputs) == 1
        assert inputs[0].ext_id == "cjpalhdlnbpafiamejdnhcphjbkeiagm"
        assert inputs[0].browser == "chrome"


class TestLoadIdsFromFile:
    def test_loads_valid_ids(self, tmp_path):
        f = tmp_path / "ids.txt"
        f.write_text(
            "cjpalhdlnbpafiamejdnhcphjbkeiagm\n"
            "# comment line\n"
            "\n"
            "bmnlcjabgnpnenekpadlanbbkooimhnj\n"
        )
        results = load_ids_from_file(f)
        assert len(results) == 2

    def test_skips_blank_and_comments(self, tmp_path):
        f = tmp_path / "ids.txt"
        f.write_text("# comment\n\n  \ncjpalhdlnbpafiamejdnhcphjbkeiagm\n")
        results = load_ids_from_file(f)
        assert len(results) == 1

    def test_csv_format_with_browser_column(self, tmp_path):
        f = tmp_path / "ids.txt"
        f.write_text("cjpalhdlnbpafiamejdnhcphjbkeiagm,edge\n")
        results = load_ids_from_file(f)
        assert results[0].browser == "edge"

    def test_skips_invalid_ids_without_crashing(self, tmp_path, capsys):
        f = tmp_path / "ids.txt"
        f.write_text(
            "cjpalhdlnbpafiamejdnhcphjbkeiagm\n"
            "not-valid-!!!\n"
        )
        results = load_ids_from_file(f)
        # valid ID still returned
        assert len(results) == 1

    def test_browser_hint_applied(self, tmp_path):
        f = tmp_path / "ids.txt"
        f.write_text("cjpalhdlnbpafiamejdnhcphjbkeiagm\n")
        results = load_ids_from_file(f, browser_hint="edge")
        assert results[0].browser == "edge"
