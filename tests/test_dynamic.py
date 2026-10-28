import json
import subprocess
from pathlib import Path

import pytest
from extanalyze_dynamic import runner
from extanalyze_dynamic.schema import InvalidDriverOutput, validate

from extanalyze import plugins
from extanalyze.analysis.code_review import CodeReviewResult
from extanalyze.analysis.dynamic import apply_dynamic
from extanalyze.scoring.aggregator import DYNAMIC_CAP, aggregate

from test_aggregator import _clean_liveness, _clean_sentry, _clean_tpci, _empty_pa


def _obs(**over):
    base = {
        "schema": 1, "browser": "chrome-linux64", "extension_id": None, "background_observed": True,
        "pages_visited": ["www.google.com"], "requests": [], "external_hosts": [],
        "canary_hits": [], "console_errors": [], "notes": [], "duration_s": 1.0,
    }  # fmt: skip
    base.update(over)
    return base


def _review():
    return CodeReviewResult([], [], 0, [], [])


# ── schema ──────────────────────────────────────────────────────────────────────────────────
def test_validate_sanitizes_and_caps():
    raw = _obs(requests=[{"url": "x" * 5000, "method": "POST", "resource_type": "fetch",
                          "source": "evil", "body_bytes": "nope", "canaries": ["password", "bogus"]}] * 900,
               canary_hits=[{"canary": "password", "encoding": "raw", "url": "u", "method": "GET"},
                            {"canary": "not-a-canary"}, "junk"], injected="ignored")  # fmt: skip
    out = validate(raw)
    assert len(out["requests"]) == 500 and len(out["requests"][0]["url"]) == 300
    assert out["requests"][0]["source"] == "page" and out["requests"][0]["body_bytes"] == 0
    assert out["requests"][0]["canaries"] == ["password"]
    assert [h["canary"] for h in out["canary_hits"]] == ["password"]
    assert "injected" not in out


@pytest.mark.parametrize("bad", [None, [], {"schema": 2}, {"schema": 1, "error": "boom"}])
def test_validate_rejects_garbage(bad):
    with pytest.raises(InvalidDriverOutput):
        validate(bad)


# ── findings and scoring ────────────────────────────────────────────────────────────────────
def test_canary_exfiltration_is_critical():
    r = _review()
    apply_dynamic(r, _obs(external_hosts=["c2.evil.test"],
                          canary_hits=[{"canary": "password", "encoding": "base64@1",
                                        "url": "https://c2.evil.test/x", "method": "POST"}]))  # fmt: skip
    f = {x.rule_id: x for x in r.findings}
    assert f["CR-RT-001"].severity == "CRITICAL" and "CR-RT-002" not in f
    assert r.dynamic is not None


def test_external_contact_without_canary_is_medium_and_remote_code_high():
    r = _review()
    apply_dynamic(r, _obs(external_hosts=["a.test"], requests=[
        {"url": "https://a.test/p.js", "method": "GET", "resource_type": "fetch",
         "source": "service_worker", "body_bytes": 0, "canaries": []}]))  # fmt: skip
    f = {x.rule_id: x for x in r.findings}
    assert f["CR-RT-002"].severity == "MEDIUM" and f["CR-RT-003"].severity == "HIGH"


def test_external_contact_alone_scores_lightly():
    r = _review()
    apply_dynamic(r, _obs(external_hosts=["a.test"]))
    base = aggregate(_clean_tpci(), _clean_sentry(), _clean_liveness(), _empty_pa())
    scored = aggregate(
        _clean_tpci(), _clean_sentry(), _clean_liveness(), _empty_pa(), code_review=r
    )
    assert scored.score - base.score == 5


def test_runtime_findings_scored_outside_static_cap_with_own_cap():
    r = _review()
    hits = [{"canary": c, "encoding": "raw", "url": f"https://c2.test/{c}", "method": "POST"}
            for c in ("password", "email", "card")]  # fmt: skip
    apply_dynamic(r, _obs(external_hosts=["c2.test"], canary_hits=hits))
    base = aggregate(_clean_tpci(), _clean_sentry(), _clean_liveness(), _empty_pa())
    scored = aggregate(
        _clean_tpci(), _clean_sentry(), _clean_liveness(), _empty_pa(), code_review=r
    )
    assert scored.score - base.score == DYNAMIC_CAP
    assert any("CR-RT-001" in x for x in scored.reasons)


# ── runner (docker is faked) ────────────────────────────────────────────────────────────────
def test_pick_target():
    assert runner.pick_target("chrome", 3) == "chromium-mv3"
    assert runner.pick_target("edge", 2) == "chromium-mv2"
    assert runner.pick_target("firefox", 2) == "firefox"
    assert runner.pick_target("firefox", 3) == "firefox"


def test_docker_argv_is_hardened_and_network_off_by_default(tmp_path):
    argv = runner.docker_run_argv("img", "n", tmp_path, 30, allow_network=False)
    assert argv[:3] == ["docker", "run", "--rm"]
    for flag in ("--read-only", "--cap-drop", "no-new-privileges", "--pids-limit", "none"):
        assert flag in argv
    assert any(a.startswith("type=bind") and a.endswith(",readonly") for a in argv)
    assert "--network" in argv and "--allow-network" not in argv
    net = runner.docker_run_argv("img", "n", tmp_path, 30, allow_network=True)
    assert "--network" not in net and "--allow-network" in net


def _fake_docker(monkeypatch, stdout, returncode=0):
    monkeypatch.setattr(runner.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(runner, "resolve_image", lambda _t: "img")

    def fake_docker(*a, **k):
        return subprocess.CompletedProcess(a, 0, "", "")

    monkeypatch.setattr(runner, "_docker", fake_docker)
    monkeypatch.setattr(
        runner.subprocess, "run",
        lambda argv, **k: subprocess.CompletedProcess(argv, returncode, stdout, ""),
    )  # fmt: skip


def test_run_dynamic_returns_validated_output(tmp_path, monkeypatch):
    _fake_docker(monkeypatch, "log line\n" + json.dumps(_obs()) + "\n")
    assert runner.run_dynamic(tmp_path, manifest_version=3)["schema"] == 1


def test_run_dynamic_rejects_missing_output(tmp_path, monkeypatch):
    _fake_docker(monkeypatch, "", returncode=137)
    with pytest.raises(InvalidDriverOutput):
        runner.run_dynamic(tmp_path, manifest_version=3)


def test_run_dynamic_timeout_kills_container(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(runner.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(runner, "resolve_image", lambda _t: "img")
    monkeypatch.setattr(
        runner,
        "_docker",
        lambda *a, **k: calls.append(a) or subprocess.CompletedProcess(a, 0, "", ""),
    )

    def boom(argv, **k):
        raise subprocess.TimeoutExpired(argv, 1)

    monkeypatch.setattr(runner.subprocess, "run", boom)
    with pytest.raises(InvalidDriverOutput):
        runner.run_dynamic(tmp_path, manifest_version=3)
    assert any(c[0] == "kill" for c in calls)


# ── core plugin discovery ───────────────────────────────────────────────────────────────────
def test_missing_plugin_has_install_hint(monkeypatch):
    monkeypatch.setattr(plugins, "entry_points", lambda group: [])
    with pytest.raises(plugins.PluginMissing, match="extanalyze-dynamic"):
        plugins.load_dynamic_runner()


# ── real sandbox (needs Docker + a locally built image; run: pytest -m integration) ─────────
FIXTURES = Path(__file__).parent / "fixtures" / "dynamic"


def _image_available(target):
    try:
        return subprocess.run(["docker", "image", "inspect", f"extanalyze-sandbox:{target}"],
                              capture_output=True, timeout=20).returncode == 0  # fmt: skip
    except (OSError, subprocess.TimeoutExpired):
        return False


@pytest.mark.integration
@pytest.mark.skipif(not _image_available("chromium-mv3"), reason="sandbox image not built")
def test_sandbox_detects_exfiltration_and_clears_benign():
    mal = runner.run_dynamic(FIXTURES / "malicious_ext", manifest_version=3, seconds=30)
    assert {h["canary"] for h in mal["canary_hits"]} >= {"password", "cookie", "email"}
    assert "c2.evil.test" in mal["external_hosts"]
    benign = runner.run_dynamic(FIXTURES / "benign_ext", manifest_version=3, seconds=15)
    assert benign["canary_hits"] == [] and benign["external_hosts"] == []


@pytest.mark.integration
@pytest.mark.skipif(not _image_available("chromium-mv2"), reason="sandbox image not built")
def test_mv2_sandbox_loads_legacy_extension():
    obs = runner.run_dynamic(FIXTURES / "mv2_ext", manifest_version=2, seconds=15)
    assert obs["background_observed"] and "legacy-c2.evil.test" in obs["external_hosts"]


@pytest.mark.integration
@pytest.mark.skipif(not _image_available("firefox"), reason="sandbox image not built")
def test_firefox_sandbox_detects_exfiltration():
    obs = runner.run_dynamic(
        FIXTURES / "firefox_ext", manifest_version=2, browser="firefox", seconds=30
    )
    assert "ff-c2.evil.test" in obs["external_hosts"]
    assert {h["canary"] for h in obs["canary_hits"]} >= {"cookie", "password", "email"}
    assert any(r["source"] == "background_page" for r in obs["requests"])
    benign = runner.run_dynamic(
        FIXTURES / "benign_ext", manifest_version=3, browser="firefox", seconds=15
    )
    assert benign["canary_hits"] == [] and benign["external_hosts"] == []


def test_dynamic_options_bound_concurrency():
    from extanalyze.worker import DynamicOptions

    opts = DynamicOptions(workers=2)
    assert opts.slots.acquire(blocking=False) and opts.slots.acquire(blocking=False)
    assert not opts.slots.acquire(blocking=False)  # third container must wait
    assert DynamicOptions().slots.acquire(blocking=False)  # default: one at a time
    assert (
        not (d := DynamicOptions()).slots.acquire(blocking=False)
        or d.slots.acquire(blocking=False) is False
    )
