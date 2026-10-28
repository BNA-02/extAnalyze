from click.testing import CliRunner

from extanalyze import cli


def test_bare_id_routes_to_analyze(monkeypatch):
    seen = {}

    def fake(inp, deep=False, dynamic=None):
        seen["id"] = inp.ext_id
        raise SystemExit(0)

    monkeypatch.setattr(cli, "analyze_single", fake)
    CliRunner().invoke(cli.main, ["cjpalhdlnbpafiamejdnhcphjbkeiagm"])
    assert seen["id"] == "cjpalhdlnbpafiamejdnhcphjbkeiagm"


def test_explicit_analyze_still_works(monkeypatch):
    seen = {}
    monkeypatch.setattr(
        cli,
        "analyze_single",
        lambda inp, deep=False, dynamic=None: (
            seen.update(id=inp.ext_id) or (_ for _ in ()).throw(SystemExit(0))
        ),
    )
    CliRunner().invoke(cli.main, ["analyze", "cjpalhdlnbpafiamejdnhcphjbkeiagm"])
    assert seen["id"] == "cjpalhdlnbpafiamejdnhcphjbkeiagm"


def test_options_first_routes_to_analyze():
    r = CliRunner().invoke(cli.main, ["--file", "/nonexistent/ids.txt"])
    assert "does not exist" in r.output.lower()


def test_subcommands_and_help_unchanged():
    runner = CliRunner()
    assert "analyze" in runner.invoke(cli.main, ["--help"]).output
    assert runner.invoke(cli.main, ["--version"]).exit_code == 0
    assert runner.invoke(cli.main, ["cache", "--help"]).exit_code == 0
