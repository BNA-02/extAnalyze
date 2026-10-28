import json
from datetime import UTC, datetime
from types import SimpleNamespace

from extanalyze.analysis.code_review import CodeFinding, CodeReviewResult
from extanalyze.api import rescore, to_record
from extanalyze.core.store_meta import StoreMeta, parse_update_response
from extanalyze.output.record import ruleset_hash, scoring_hash
from extanalyze.scoring import config as scoring_config
from extanalyze.scoring.aggregator import aggregate
from extanalyze.scoring.signals import Signals, score_signals, signals_from
from test_aggregator import (
    _clean_liveness,
    _clean_sentry,
    _clean_tpci,
    _empty_pa,
    _make_manifest,
)

from extanalyze.analysis.permissions import analyze as analyze_permissions

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _result(permissions=("cookies", "nativeMessaging", "<all_urls>"), findings=(), flows=()):
    manifest = _make_manifest(permissions=list(permissions))
    pa = analyze_permissions(manifest, category="productivity", category_confidence="HIGH")
    cr = CodeReviewResult(
        [CodeFinding(i, i, "X", sev, "d", n) for i, sev, n in findings], [], 3, [], list(flows)
    )
    risk = aggregate(_clean_tpci(), _clean_sentry(), _clean_liveness(), pa, cr)
    store = StoreMeta("N", "", "", "", "1.0", "1,000", True, "cws", False, False)
    return SimpleNamespace(
        ext_id="a" * 32, browser="chrome", enrichment=SimpleNamespace(name="N"), store=store,
        liveness=_clean_liveness(), tpci=_clean_tpci(), sentry=_clean_sentry(), manifest=manifest,
        perm_analysis=pa, download_sha256="h", download_size_bytes=10, crx_format="crx3",
        risk=risk, download_error="", manifest_error="", code_review=cr,
    )  # fmt: skip


def test_record_is_json_safe_and_deterministic():
    r = _result(findings=[("CR-DYN-001", "MEDIUM", 4), ("CR-EXF-006", "MEDIUM", 1)])
    a, b = to_record(r, now=NOW), to_record(r, now=NOW)
    assert a == b
    json.dumps(a)  # must not raise
    assert a["code"]["rule_hits"] == {"CR-DYN-001": 4, "CR-EXF-006": 1}
    assert a["ruleset_hash"] == ruleset_hash() and a["scoring_hash"] == scoring_hash()
    assert "snippet" not in json.dumps(a)


def test_rescore_from_stored_record_equals_live_score():
    r = _result(
        findings=[("CR-DYN-003", "HIGH", 2), ("CR-SEC-002", "CRITICAL", 1), ("CR-DYN-001", "MEDIUM", 9)],
        flows=["bg.js"],
    )  # fmt: skip
    rec = json.loads(json.dumps(to_record(r, now=NOW)))  # round-trip like a stored file
    assert rescore(rec) == (r.risk.score, r.risk.level)


def test_rescore_with_different_weights_changes_the_score():
    r = _result(findings=[("CR-DYN-001", "MEDIUM", 9)])
    rec = to_record(r, now=NOW)
    base = rescore(rec)[0]
    raw = json.loads(json.dumps(scoring_config.default_config().raw))
    raw["rule_points"] = {"CR-DYN-001": 30}
    tuned = scoring_config.from_dict(raw)
    assert rescore(rec, tuned)[0] == base - 2 + 30


def test_ti_minimum_and_reason(monkeypatch):
    from extanalyze.intel.tpci import TPCIResult

    t = _clean_tpci()
    t = TPCIResult(**{**t.__dict__, "hit": True, "confirm_mal": 1})
    report = aggregate(t, _clean_sentry(), _clean_liveness(), _empty_pa())
    assert report.score >= 41 and report.ti_confirmed_malicious


def test_signals_roundtrip_ignores_unknown_keys():
    s = signals_from(_clean_tpci(), _clean_sentry(), _clean_liveness(), _empty_pa())
    d = s.to_dict() | {"future_field": 1}
    assert score_signals(Signals.from_dict(d)).score == score_signals(s).score


def test_config_requires_zero_threshold():
    raw = json.loads(json.dumps(scoring_config.default_config().raw))
    raw["thresholds"] = [[10, "HIGH"]]
    try:
        scoring_config.from_dict(raw)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


UPDATE_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<gupdate xmlns="http://www.google.com/update2/response" protocol="2.0">
 <app appid="gighmmpiobklfepjocnamgkkbiglidom" status="ok">
  <updatecheck codebase="https://clients2.googleusercontent.com/crx/x.crx" hash_sha256="620bb6612e5ba22a"
   size="71682084" status="ok" version="6.51.0"/></app>
 <app appid="cjpalhdlnbpafiamejdnhcphjbkeiagm" status="ok"><updatecheck status="noupdate"/></app>
 <app appid="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" status="error-unknownApplication"/>
 <app appid="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" status="ok">
  <updatecheck status="ok" _malware="true" version="1.0" size="10"/></app>
 <app appid="not-an-id" status="ok"/>
</gupdate>"""


def test_parse_update_response():
    got = parse_update_response(UPDATE_XML)
    live = got["gighmmpiobklfepjocnamgkkbiglidom"]
    assert (live.status, live.version, live.size_bytes) == ("ok", "6.51.0", 71682084)
    assert live.sha256.startswith("620bb661")
    assert got["cjpalhdlnbpafiamejdnhcphjbkeiagm"].status == "noupdate"
    assert got["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"].status == "error-unknownApplication"
    assert got["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"].malware is True
    assert "not-an-id" not in got


def test_parse_update_response_rejects_hostile_xml():
    bomb = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><gupdate><app appid="&a;"/></gupdate>'
    assert parse_update_response(bomb) == {}
    assert parse_update_response(b"not xml") == {}
