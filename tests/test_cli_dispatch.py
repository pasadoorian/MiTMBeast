"""Tests that the CLI dispatches to the right bash script with right argv.

We don't fork bash in tests; we monkeypatch ``mitmbeast.cli._run_legacy``
to capture the (script, *args) it was called with, then assert.
"""
from __future__ import annotations

import pytest
from click.testing import CliRunner

from mitmbeast import cli


@pytest.fixture
def captured(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, ...]]:
    """Replace _run_legacy with a stub that records its arguments."""
    seen: list[tuple[str, ...]] = []

    def fake(script: str, *args: str) -> int:
        seen.append((script, *args))
        return 0

    monkeypatch.setattr(cli, "_run_legacy", fake)
    return seen


def invoke(args: list[str]) -> tuple[int, str]:
    runner = CliRunner()
    result = runner.invoke(cli.main, args)
    return result.exit_code, result.output


# ----- mitm.sh dispatches -----

def test_up_basic(captured: list[tuple[str, ...]]) -> None:
    code, _ = invoke(["up"])
    assert code == 0
    assert captured == [("mitm.sh", "up")]


def test_up_with_mode_and_flags(captured: list[tuple[str, ...]]) -> None:
    invoke(["up", "-m", "mitmproxy", "-k", "-c"])
    assert captured == [("mitm.sh", "up", "-m", "mitmproxy", "-k", "-c")]


def test_up_invalid_mode_rejected_at_click_layer(captured: list[tuple[str, ...]]) -> None:
    code, _ = invoke(["up", "-m", "bogus"])
    assert code != 0
    assert captured == []  # never dispatched


def test_down_basic(captured: list[tuple[str, ...]]) -> None:
    invoke(["down"])
    assert captured == [("mitm.sh", "down")]


def test_down_keep_wan(captured: list[tuple[str, ...]]) -> None:
    invoke(["down", "-k"])
    assert captured == [("mitm.sh", "down", "-k")]


def test_reload_full(captured: list[tuple[str, ...]]) -> None:
    invoke(["reload", "-m", "intercept", "-c"])
    assert captured == [("mitm.sh", "reload", "-m", "intercept", "-c")]


def test_restore_default(captured: list[tuple[str, ...]]) -> None:
    invoke(["restore"])
    assert captured == [("mitm.sh", "restore")]


def test_restore_with_manager(captured: list[tuple[str, ...]]) -> None:
    invoke(["restore", "--manager", "NetworkManager"])
    assert captured == [("mitm.sh", "restore", "--manager", "NetworkManager")]


# ----- dns-spoof.sh dispatches -----

def test_spoof_add(captured: list[tuple[str, ...]]) -> None:
    invoke(["spoof", "add", "foo.example.com", "192.168.200.1"])
    assert captured == [("dns-spoof.sh", "add", "foo.example.com", "192.168.200.1")]


def test_spoof_add_with_force(captured: list[tuple[str, ...]]) -> None:
    invoke(["spoof", "add", "api.example.com", "1.2.3.4", "--force"])
    assert captured == [
        ("dns-spoof.sh", "add", "api.example.com", "1.2.3.4", "--force")
    ]


def test_spoof_rm(captured: list[tuple[str, ...]]) -> None:
    invoke(["spoof", "rm", "foo.example.com"])
    assert captured == [("dns-spoof.sh", "rm", "foo.example.com")]


def test_spoof_list(captured: list[tuple[str, ...]]) -> None:
    invoke(["spoof", "list"])
    assert captured == [("dns-spoof.sh", "list")]


def test_spoof_dump_with_domain(captured: list[tuple[str, ...]]) -> None:
    invoke(["spoof", "dump", "example.com"])
    assert captured == [("dns-spoof.sh", "dump", "example.com")]


def test_spoof_logs_with_count(captured: list[tuple[str, ...]]) -> None:
    invoke(["spoof", "logs", "100"])
    assert captured == [("dns-spoof.sh", "logs", "100")]


# ----- delorean.sh dispatches -----

def test_delorean_start_default(captured: list[tuple[str, ...]]) -> None:
    invoke(["delorean", "start"])
    assert captured == [("delorean.sh", "start", "+1000")]


def test_delorean_start_offset(captured: list[tuple[str, ...]]) -> None:
    invoke(["delorean", "start", "+1500"])
    assert captured == [("delorean.sh", "start", "+1500")]


def test_delorean_stop(captured: list[tuple[str, ...]]) -> None:
    invoke(["delorean", "stop"])
    assert captured == [("delorean.sh", "stop")]


def test_delorean_status(captured: list[tuple[str, ...]]) -> None:
    invoke(["delorean", "status"])
    assert captured == [("delorean.sh", "status")]


def test_delorean_set(captured: list[tuple[str, ...]]) -> None:
    invoke(["delorean", "set", "+2000"])
    assert captured == [("delorean.sh", "set", "+2000")]


# ----- exit-code propagation -----

def test_exit_code_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_failing(script: str, *args: str) -> int:
        return 7
    monkeypatch.setattr(cli, "_run_legacy", fake_failing)
    code, _ = invoke(["up"])
    assert code == 7


# ----- tui command surface -----

def test_tui_command_listed_in_help() -> None:
    """The TUI subcommand is registered. (We can't actually invoke it
    in pytest since Textual needs a real TTY.)"""
    code, output = invoke(["--help"])
    assert code == 0
    assert "tui" in output


def test_no_subcommand_invokes_tui_in_click() -> None:
    """`mitmbeast` (no args) should resolve to the tui subcommand. We
    verify by checking click's introspection rather than running it,
    since launching Textual outside a real TTY is a separate concern."""
    # The main group has invoke_without_command=True
    assert cli.main.invoke_without_command is True


# ----- repo root resolution -----

def test_repo_root_points_at_legacy_scripts() -> None:
    """REPO_ROOT must contain mitm.sh so subprocess can find it."""
    assert (cli.REPO_ROOT / "mitm.sh").is_file()
    assert (cli.REPO_ROOT / "dns-spoof.sh").is_file()
    assert (cli.REPO_ROOT / "delorean.sh").is_file()


# ----- _run_legacy real-call smoke -----

def test_run_legacy_real_call_against_real_script(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """_run_legacy is the only un-mocked path to subprocess; smoke-test it."""
    script = tmp_path / "noop.sh"
    script.write_text("#!/bin/sh\nexit 0\n")
    script.chmod(0o755)
    monkeypatch.setattr(cli, "REPO_ROOT", tmp_path)
    assert cli._run_legacy("noop.sh") == 0
