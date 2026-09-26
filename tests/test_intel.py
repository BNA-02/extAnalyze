"""
Unit tests: intel/tpci.py and intel/sentry.py
Uses responses library to mock HTTP calls — no real network I/O.
"""
import json
import csv
import io
import pytest
import responses as resp_lib

from extanalyze.intel import tpci as tpci_mod
from extanalyze.intel import sentry as sentry_mod


TPCI_SAMPLE = {
    "meta": {"name": "test", "total": 2},
    "extensions": [
        {
            "ext_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
            "name": "Malware Extension",
            "browser": "chrome",
            "threat_types": ["spyware", "data-theft"],
            "still_active": True,
            "ownership_transfer": False,
            "notes": "Test malware entry",
            "source": "https://example.com/research",
            "article": "https://example.com/article",
            "tpci_behavioral": "malicious",
            "date_added": "2026-01-01",
        },
        {
            "ext_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2",
            "name": "Suspicious Extension",
            "browser": "edge",
            "threat_types": ["adware"],
            "still_active": False,
            "confirm_mal": 2,
            "ownership_transfer": True,
            "notes": "Google confirmed",
            "source": "https://example.com",
            "article": "https://example.com",
            "tpci_behavioral": "suspicious",
            "date_added": "2026-02-01",
        },
    ],
}

SENTRY_CSV_ROWS = (
    "extension_id,name,reason,source,insert_date_fmt,blocklist,store,version,sha256\n"
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01,Bad Extension,Malware,"
    "Store Monitoring,2026-01-01,true,Google Chrome,1.0,"
    "deadbeef00000000000000000000000000000000000000000000000000000001\n"
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb02,Policy Viol,Policy Violation,"
    "Store Monitoring,2026-01-02,false,Google Chrome,2.0,"
    "cafecafe00000000000000000000000000000000000000000000000000000002\n"
)


@pytest.fixture(autouse=True)
def reset_intel_caches(tmp_path, monkeypatch):
    """
    Force each test to use a fresh tmp cache dir and reset module-level indices.
    Without this, a cached index from a previous test bleeds through.
    """
    monkeypatch.setattr(tpci_mod, "_INDEX", None)
    monkeypatch.setattr(sentry_mod, "_INDEX", None)
    monkeypatch.setattr(tpci_mod, "_CACHE_DIR", tmp_path)
    monkeypatch.setattr(sentry_mod, "_CACHE_DIR", tmp_path)


class TestTPCILookup:
    @resp_lib.activate
    def test_hit_returns_result(self):
        resp_lib.add(
            resp_lib.GET,
            tpci_mod._RAW_URL,
            json=TPCI_SAMPLE,
            status=200,
        )
        result = tpci_mod.lookup("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
        assert result.hit is True
        assert result.name == "Malware Extension"
        assert "spyware" in result.threat_types
        assert result.tpci_behavioral == "malicious"
        assert result.ownership_transfer is False

    @resp_lib.activate
    def test_miss_returns_no_hit(self):
        resp_lib.add(
            resp_lib.GET,
            tpci_mod._RAW_URL,
            json=TPCI_SAMPLE,
            status=200,
        )
        result = tpci_mod.lookup("ffffffffffffffffffffffffffffffff")
        assert result.hit is False
        assert result.name == ""
        assert result.threat_types == []

    @resp_lib.activate
    def test_confirm_mal_explicit_field(self):
        resp_lib.add(
            resp_lib.GET,
            tpci_mod._RAW_URL,
            json=TPCI_SAMPLE,
            status=200,
        )
        result = tpci_mod.lookup("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2")
        assert result.hit is True
        assert result.confirm_mal == 2
        assert result.ownership_transfer is True

    @resp_lib.activate
    def test_confirm_mal_inferred_from_threat_types(self):
        """When confirm_mal not in JSON, infer from threat_types presence."""
        resp_lib.add(
            resp_lib.GET,
            tpci_mod._RAW_URL,
            json=TPCI_SAMPLE,
            status=200,
        )
        result = tpci_mod.lookup("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
        # entry has threat_types but no explicit confirm_mal -> inferred as 1
        assert result.confirm_mal == 1

    @resp_lib.activate
    def test_network_error_returns_no_hit(self):
        resp_lib.add(
            resp_lib.GET,
            tpci_mod._RAW_URL,
            body=Exception("network failure"),
        )
        # Should not raise; returns empty cache
        result = tpci_mod.lookup("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
        assert result.hit is False


class TestSentryLookup:
    @resp_lib.activate
    def test_blocklist_hit(self):
        resp_lib.add(
            resp_lib.GET,
            sentry_mod._RAW_URL,
            body=SENTRY_CSV_ROWS,
            status=200,
            content_type="text/csv",
        )
        result = sentry_mod.lookup("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01")
        assert result.hit is True
        assert result.blocklist is True
        assert result.reason == "Malware"
        assert result.store == "Google Chrome"

    @resp_lib.activate
    def test_non_blocklist_hit(self):
        resp_lib.add(
            resp_lib.GET,
            sentry_mod._RAW_URL,
            body=SENTRY_CSV_ROWS,
            status=200,
            content_type="text/csv",
        )
        result = sentry_mod.lookup("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb02")
        assert result.hit is True
        assert result.blocklist is False
        assert result.reason == "Policy Violation"

    @resp_lib.activate
    def test_miss(self):
        resp_lib.add(
            resp_lib.GET,
            sentry_mod._RAW_URL,
            body=SENTRY_CSV_ROWS,
            status=200,
            content_type="text/csv",
        )
        result = sentry_mod.lookup("ffffffffffffffffffffffffffffffff")
        assert result.hit is False

    @resp_lib.activate
    def test_sha256_match_true(self):
        resp_lib.add(
            resp_lib.GET,
            sentry_mod._RAW_URL,
            body=SENTRY_CSV_ROWS,
            status=200,
            content_type="text/csv",
        )
        known_sha = "deadbeef00000000000000000000000000000000000000000000000000000001"
        result = sentry_mod.lookup(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01",
            downloaded_sha256=known_sha,
        )
        assert result.sha256_match is True

    @resp_lib.activate
    def test_sha256_mismatch(self):
        resp_lib.add(
            resp_lib.GET,
            sentry_mod._RAW_URL,
            body=SENTRY_CSV_ROWS,
            status=200,
            content_type="text/csv",
        )
        result = sentry_mod.lookup(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01",
            downloaded_sha256="0000000000000000000000000000000000000000000000000000000000000000",
        )
        assert result.sha256_match is False
