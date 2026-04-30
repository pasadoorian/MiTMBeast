"""Tests for ``mitmbeast.core.fakefw``."""
from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path

import pytest

from mitmbeast.core.fakefw import (
    FirmwareConfig,
    calculate_sha256,
    serve_in_thread,
)


def test_calculate_sha256(tmp_path: Path) -> None:
    p = tmp_path / "hello.bin"
    p.write_bytes(b"hello\n")
    digest = calculate_sha256(p)
    # `printf 'hello\n' | sha256sum`
    assert digest == "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"


def test_firmware_config_defaults() -> None:
    cfg = FirmwareConfig()
    assert cfg.firmware_dir == "./firmware"
    assert cfg.https_port == 443
    assert cfg.firmware_version == "99.0.0"
    assert cfg.app_filename == "firmware_app"
    assert cfg.allowed_files == []


def test_serve_rejects_empty_config() -> None:
    cfg = FirmwareConfig()  # no http_port, no cert/key
    with pytest.raises(ValueError, match="must enable HTTP"):
        serve_in_thread(cfg)


def test_serve_in_thread_http_releases_endpoint(tmp_path: Path) -> None:
    cfg = FirmwareConfig(
        firmware_dir=str(tmp_path),
        server_host="127.0.0.1",
        http_port=18080,   # unprivileged port
        firmware_version="99.0.0",
        update_host="update.example.test",
        app_filename="firmware_app",
    )
    session = serve_in_thread(cfg)
    try:
        # Give the server a beat to bind
        time.sleep(0.1)
        with urllib.request.urlopen(
            "http://127.0.0.1:18080/releases?deviceId=test123",
            timeout=3.0,
        ) as resp:
            payload = json.loads(resp.read())
        assert payload["appVersion"] == "99.0.0"
        assert payload["appUrl"] == \
            "https://update.example.test/app/99.0.0/firmware_app"
        assert payload["systemUrl"] == \
            "https://update.example.test/system/99.0.0/system.tar"
    finally:
        session.shutdown()


def test_serve_in_thread_threaded_concurrent_clients(tmp_path: Path) -> None:
    """Two concurrent clients shouldn't queue. (Smoke test of threading.)"""
    cfg = FirmwareConfig(
        firmware_dir=str(tmp_path),
        server_host="127.0.0.1",
        http_port=18081,
    )
    session = serve_in_thread(cfg)
    try:
        time.sleep(0.1)
        # Fire two requests "simultaneously" — each completes independently.
        results: list[int] = []
        import threading

        def fetch() -> None:
            with urllib.request.urlopen(
                "http://127.0.0.1:18081/", timeout=3.0,
            ) as resp:
                results.append(resp.status)

        threads = [threading.Thread(target=fetch) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)
        assert results == [200] * 4
    finally:
        session.shutdown()


def test_disallowed_file_returns_403(tmp_path: Path) -> None:
    cfg = FirmwareConfig(
        firmware_dir=str(tmp_path),
        server_host="127.0.0.1",
        http_port=18082,
        allowed_files=["only_this.bin"],
    )
    session = serve_in_thread(cfg)
    try:
        time.sleep(0.1)
        # /app/<v>/firmware_app — path matches but firmware_app is not allowed.
        url = "http://127.0.0.1:18082/app/99.0.0/firmware_app"
        try:
            urllib.request.urlopen(url, timeout=3.0)  # noqa: S310 — localhost test
            raise AssertionError("expected HTTP 403")
        except urllib.error.HTTPError as e:
            assert e.code == 403
    finally:
        session.shutdown()
