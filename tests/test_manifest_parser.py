"""
Unit tests: core/manifest_parser.py
"""
import json
import pytest
from pathlib import Path
from extanalyze.core.manifest_parser import (
    parse_manifest,
    get_all_permissions,
    has_permission,
    _split_permissions,
    _is_non_google_update_url,
    _content_scripts_match_all,
)


def _write_manifest(tmp_path: Path, data: dict) -> Path:
    p = tmp_path / "manifest.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


class TestSplitPermissions:
    def test_separates_url_patterns(self):
        named, urls = _split_permissions([
            "tabs", "storage", "https://*/*", "<all_urls>", "scripting"
        ])
        assert set(named) == {"tabs", "storage", "scripting"}
        assert "<all_urls>" in urls
        assert "https://*/*" in urls

    def test_empty_list(self):
        named, urls = _split_permissions([])
        assert named == []
        assert urls == []


class TestIsNonGoogleUpdateUrl:
    def test_google_url_returns_false(self):
        assert not _is_non_google_update_url(
            "https://clients2.google.com/service/update2/crx"
        )

    def test_empty_returns_false(self):
        assert not _is_non_google_update_url("")

    def test_attacker_url_returns_true(self):
        assert _is_non_google_update_url("https://evil.com/update")


class TestContentScriptsMatchAll:
    def test_detects_all_urls(self):
        cs = [{"matches": ["<all_urls>"]}]
        assert _content_scripts_match_all(cs) is True

    def test_detects_wildcard(self):
        cs = [{"matches": ["https://*/*"]}]
        assert _content_scripts_match_all(cs) is True

    def test_specific_url_not_all(self):
        cs = [{"matches": ["https://example.com/*"]}]
        assert _content_scripts_match_all(cs) is False

    def test_empty(self):
        assert _content_scripts_match_all([]) is False


class TestParseManifest:
    def test_mv3_named_permissions(self, tmp_path):
        p = _write_manifest(tmp_path, {
            "manifest_version": 3,
            "name": "Test Extension",
            "version": "1.0",
            "permissions": ["tabs", "storage", "scripting"],
            "host_permissions": ["<all_urls>"],
        })
        m = parse_manifest(p)
        assert m.manifest_version == 3
        assert "tabs" in m.permissions
        assert "storage" in m.permissions
        # host_permissions must be separate from named
        assert "<all_urls>" not in m.permissions
        assert "<all_urls>" in m.host_permissions

    def test_mv2_url_patterns_split(self, tmp_path):
        p = _write_manifest(tmp_path, {
            "manifest_version": 2,
            "name": "MV2 Extension",
            "version": "1.0",
            # MV2: host perms live inside permissions[]
            "permissions": ["tabs", "<all_urls>", "webRequestBlocking"],
        })
        m = parse_manifest(p)
        assert m.manifest_version == 2
        assert "tabs" in m.permissions
        assert "webRequestBlocking" in m.permissions
        # URL pattern split out into host_permissions
        assert "<all_urls>" in m.host_permissions
        assert "<all_urls>" not in m.permissions

    def test_non_google_update_url_detected(self, tmp_path):
        p = _write_manifest(tmp_path, {
            "manifest_version": 3,
            "name": "Sideloaded",
            "version": "1.0",
            "update_url": "https://evil.com/updates",
        })
        m = parse_manifest(p)
        assert m.update_url_non_google is True

    def test_google_update_url_not_flagged(self, tmp_path):
        p = _write_manifest(tmp_path, {
            "manifest_version": 3,
            "name": "Legit",
            "version": "1.0",
            "update_url": "https://clients2.google.com/service/update2/crx",
        })
        m = parse_manifest(p)
        assert m.update_url_non_google is False

    def test_csp_unsafe_eval_detected(self, tmp_path):
        p = _write_manifest(tmp_path, {
            "manifest_version": 3,
            "name": "Unsafe",
            "version": "1.0",
            "content_security_policy": {
                "extension_pages": "script-src 'self' 'unsafe-eval'; object-src 'self'"
            },
        })
        m = parse_manifest(p)
        assert m.has_unsafe_eval is True

    def test_mv3_service_worker_parsed(self, tmp_path):
        p = _write_manifest(tmp_path, {
            "manifest_version": 3,
            "name": "SW",
            "version": "1.0",
            "background": {"service_worker": "sw.js"},
        })
        m = parse_manifest(p)
        assert m.background_service_worker == "sw.js"
        assert m.background_scripts == []

    def test_content_scripts_all_urls_flag(self, tmp_path):
        p = _write_manifest(tmp_path, {
            "manifest_version": 3,
            "name": "CS",
            "version": "1.0",
            "content_scripts": [{"matches": ["<all_urls>"], "js": ["cs.js"]}],
        })
        m = parse_manifest(p)
        assert m.content_scripts_all_urls is True

    def test_missing_fields_defaults(self, tmp_path):
        p = _write_manifest(tmp_path, {"manifest_version": 3, "version": "1"})
        m = parse_manifest(p)
        assert m.name == ""
        assert m.permissions == []
        assert m.host_permissions == []
        assert m.update_url == ""
        assert m.has_unsafe_eval is False


class TestGetAllPermissions:
    def test_combines_all_perm_sets(self, tmp_path):
        p = _write_manifest(tmp_path, {
            "manifest_version": 3,
            "version": "1",
            "permissions": ["tabs"],
            "optional_permissions": ["history"],
            "host_permissions": ["https://*.example.com/*"],
        })
        m = parse_manifest(p)
        all_p = get_all_permissions(m)
        assert "tabs" in all_p
        assert "history" in all_p
        assert "https://*.example.com/*" in all_p
