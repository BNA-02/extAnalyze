"""
Unit tests: analysis/permissions.py
- PermissionEntry scoring
- HostScopeAssessment classification
- Combo detection
- URL patterns must not appear in pa.permissions
"""
import json
import pytest
from pathlib import Path
from extanalyze.core.manifest_parser import ExtensionManifest
from extanalyze.analysis.permissions import (
    analyze,
    _assess_host_scope,
    _score_permission,
    HostScopeAssessment,
)


def _make_manifest(**overrides) -> ExtensionManifest:
    defaults = dict(
        manifest_version=3,
        name="Test",
        version="1.0",
        description="",
        permissions=[],
        optional_permissions=[],
        host_permissions=[],
        optional_host_permissions=[],
        content_scripts=[],
        content_scripts_all_urls=False,
        background_scripts=[],
        background_page="",
        background_service_worker="",
        background_persistent=None,
        content_security_policy="",
        has_unsafe_eval=False,
        update_url="",
        update_url_non_google=False,
        web_accessible_resources=[],
        externally_connectable={},
        oauth2={},
        raw={},
    )
    defaults.update(overrides)
    return ExtensionManifest(**defaults)


class TestScorePermission:
    def test_known_critical_permission(self):
        e = _score_permission("debugger", 3)
        assert e.sensitivity == "CRITICAL"
        assert e.risk_score >= 8
        assert e.known is True

    def test_unknown_permission_gets_low_score(self):
        e = _score_permission("some_unknown_perm_xyz", 3)
        assert e.sensitivity == "LOW"
        assert e.risk_score == 1
        assert e.known is False

    def test_mv2_only_permission_in_mv3_bumps_score(self):
        e_mv2 = _score_permission("webRequestBlocking", 2)
        e_mv3 = _score_permission("webRequestBlocking", 3)
        # MV3 version should get a score bump for anomaly
        assert e_mv3.risk_score >= e_mv2.risk_score


class TestAssessHostScope:
    def test_all_urls_is_broad(self):
        s = _assess_host_scope(["<all_urls>"], True)
        assert s.is_broad
        assert s.scope_label == "BROAD"

    def test_wildcard_equivalent_is_broad(self):
        s = _assess_host_scope(["https://*/*"], False)
        assert s.is_broad
        assert s.scope_label == "BROAD"

    def test_many_specific_domains_is_scoped(self):
        domains = [f"https://*.site{i}.com/*" for i in range(10)]
        s = _assess_host_scope(domains, False)
        assert not s.is_broad
        assert s.scope_label == "SCOPED"
        assert s.domain_count == 10
        assert "better than" in s.risk_note

    def test_single_domain_is_minimal(self):
        s = _assess_host_scope(["https://api.example.com/*"], False)
        assert s.scope_label == "MINIMAL"
        assert s.domain_count == 1

    def test_empty_is_none(self):
        s = _assess_host_scope([], False)
        assert s.scope_label == "NONE"
        assert s.domain_count == 0


class TestAnalyze:
    def test_url_patterns_not_in_pa_permissions(self):
        m = _make_manifest(
            permissions=["tabs", "storage"],
            host_permissions=["<all_urls>", "https://*.example.com/*"],
        )
        pa = analyze(m)
        url_in_named = [p for p in pa.permissions if p.name.startswith("http") or "/" in p.name]
        assert len(url_in_named) == 0, f"URL patterns leaked: {[p.name for p in url_in_named]}"

    def test_host_permissions_separate(self):
        m = _make_manifest(
            permissions=["tabs"],
            host_permissions=["https://api.example.com/*", "https://cdn.example.com/*"],
        )
        pa = analyze(m)
        assert len(pa.permissions) == 1  # only tabs
        assert len(pa.host_permissions) == 2

    def test_all_urls_detected(self):
        m = _make_manifest(host_permissions=["<all_urls>"])
        pa = analyze(m)
        assert pa.has_all_urls is True
        assert pa.host_scope.is_broad is True

    def test_scoped_host_scope(self):
        domains = [f"https://*.job{i}.com/*" for i in range(24)]
        m = _make_manifest(host_permissions=domains)
        pa = analyze(m)
        assert pa.host_scope.scope_label == "SCOPED"
        assert pa.host_scope.domain_count == 24
        assert not pa.host_scope.is_broad

    def test_dangerous_combo_detected(self):
        m = _make_manifest(
            permissions=["tabs", "webRequest"],
            host_permissions=["<all_urls>"],
        )
        pa = analyze(m)
        combo_ids = [c.combo_id for c in pa.combo_hits]
        assert "COMBO_001" in combo_ids  # Full Browsing Exfiltration Pipeline

    def test_cookie_theft_combo_detected(self):
        m = _make_manifest(
            permissions=["cookies"],
            host_permissions=["<all_urls>"],
        )
        pa = analyze(m)
        combo_ids = [c.combo_id for c in pa.combo_hits]
        assert "COMBO_002" in combo_ids

    def test_mv2_only_combo_skipped_on_mv3(self):
        m = _make_manifest(
            manifest_version=3,
            permissions=["webRequestBlocking"],
            host_permissions=["<all_urls>"],
        )
        pa = analyze(m)
        # COMBO_007 is mv2_only — must not fire on MV3
        combo_ids = [c.combo_id for c in pa.combo_hits]
        assert "COMBO_007" not in combo_ids

    def test_mv2_only_combo_fires_on_mv2(self):
        m = _make_manifest(
            manifest_version=2,
            permissions=["webRequestBlocking", "<all_urls>"],
        )
        pa = analyze(m)
        combo_ids = [c.combo_id for c in pa.combo_hits]
        assert "COMBO_007" in combo_ids

    def test_non_cws_update_url_signal(self):
        m = _make_manifest(
            update_url="https://evil.com/updates",
            update_url_non_google=True,
        )
        pa = analyze(m)
        combo_ids = [c.combo_id for c in pa.combo_hits]
        assert "COMBO_012" in combo_ids  # Non-CWS Update Channel

    def test_necessity_mapping_with_category(self):
        # history is BORDERLINE for ad_blocker (some use it, some don't)
        # Use a permission that's clearly unexpected: nativeMessaging for ad_blocker
        m = _make_manifest(permissions=["webRequest", "tabs", "nativeMessaging"])
        pa = analyze(m, category="ad_blocker", category_confidence="HIGH")
        verdict_map = {v.permission: v.verdict for v in pa.necessity_verdicts}
        # nativeMessaging is not in ad_blocker baseline at all -> UNEXPECTED
        assert verdict_map.get("nativeMessaging") == "UNEXPECTED"
        # webRequest is expected for ad_blockers
        assert verdict_map.get("webRequest") in ("NEEDED", "BORDERLINE")

    def test_no_permissions_gives_empty_analysis(self):
        m = _make_manifest()
        pa = analyze(m)
        assert pa.permissions == []
        assert pa.host_permissions == []
        assert pa.combo_hits == []
        assert pa.has_all_urls is False
        assert pa.host_scope.scope_label == "NONE"
