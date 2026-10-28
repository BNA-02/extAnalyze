"""`extanalyze dynamic ...` subcommands registered through the extanalyze.cli entry point."""

from __future__ import annotations

import subprocess

import click

from . import runner


@click.group()
def dynamic():
    """Manage the dynamic-analysis sandbox images."""


@dynamic.command()
@click.argument("target", type=click.Choice(runner.TARGETS), required=False)
def build(target):
    """Build sandbox image(s) locally from the bundled Dockerfile."""
    runner.require_docker()
    for t in [target] if target else runner.TARGETS:
        click.echo(f"building {t} ...")
        click.echo(runner.build_image(t))


@dynamic.command()
@click.argument("target", type=click.Choice(runner.TARGETS), required=False)
def pull(target):
    """Pull published sandbox image(s) from the registry."""
    runner.require_docker()
    try:
        for t in [target] if target else runner.TARGETS:
            click.echo(f"pulling {t} ...")
            click.echo(runner.pull_image(t))
    except subprocess.CalledProcessError as e:
        raise click.ClickException(f"pull failed: {e.stderr.strip() if e.stderr else e}") from e


@dynamic.command()
def status():
    """Show which sandbox images are available."""
    runner.require_docker()
    for t in runner.TARGETS:
        try:
            click.echo(f"{t}: {runner.resolve_image(t)}")
        except runner.DynamicUnavailable:
            click.echo(f"{t}: missing")
