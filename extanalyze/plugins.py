"""Optional plugins discovered through entry points (importlib.metadata).

extanalyze.dynamic  a callable running the extension in a sandbox (extanalyze-dynamic)
extanalyze.cli      click commands/groups added to the main CLI
"""

from __future__ import annotations

from importlib.metadata import entry_points

DYNAMIC_INSTALL_HINT = (
    "Dynamic analysis needs the extanalyze-dynamic plugin and Docker. Install the plugin with "
    '`pip install "git+https://github.com/BNA-02/extAnalyze.git#subdirectory=plugins/dynamic"` '
    "(already included in the .deb), then run `extanalyze dynamic pull`."
)


class PluginMissing(RuntimeError):
    pass


def load_dynamic_runner():
    """Return the dynamic-analysis callable or raise PluginMissing."""
    for ep in entry_points(group="extanalyze.dynamic"):
        return ep.load()
    raise PluginMissing(DYNAMIC_INSTALL_HINT)


def register_cli_plugins(group) -> None:
    """Attach plugin-provided commands to the click group. A broken plugin never breaks the CLI."""
    for ep in entry_points(group="extanalyze.cli"):
        try:
            group.add_command(ep.load(), name=ep.name)
        except Exception:  # noqa: S112 - a bad plugin must not take the core CLI down
            continue
