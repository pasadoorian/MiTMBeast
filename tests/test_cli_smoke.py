"""Smoke test: the CLI imports and `--help` prints without error."""
from __future__ import annotations

from click.testing import CliRunner

from mitmbeast import __version__
from mitmbeast.cli import main


def test_help_runs() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "MITM Beast" in result.output


def test_version_flag() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_subcommands_present() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    for sub in ["up", "down", "reload", "restore", "spoof", "delorean", "tui"]:
        assert sub in result.output, f"{sub!r} missing from --help"
