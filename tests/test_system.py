"""Tests for ``mitmbeast.core.system``."""
from __future__ import annotations

import os
import sys

import pytest

from mitmbeast.core.system import (
    CommandFailedError,
    CommandTimeoutError,
    ProcessResult,
    StreamLine,
    require_root,
    run_capture,
    run_capture_sync,
    run_streaming,
)

# ----- run_capture -----

@pytest.mark.asyncio
async def test_run_capture_basic() -> None:
    r = await run_capture("/bin/echo", "hello")
    assert r.ok
    assert r.returncode == 0
    assert r.stdout == "hello\n"
    assert r.stderr == ""


@pytest.mark.asyncio
async def test_run_capture_nonzero_exit() -> None:
    r = await run_capture("/bin/false")
    assert not r.ok
    assert r.returncode == 1


@pytest.mark.asyncio
async def test_run_capture_check_raises_on_failure() -> None:
    with pytest.raises(CommandFailedError) as ei:
        await run_capture("/bin/false", check=True)
    assert ei.value.result.returncode == 1


@pytest.mark.asyncio
async def test_run_capture_check_passes_on_success() -> None:
    r = await run_capture("/bin/true", check=True)
    assert r.ok


@pytest.mark.asyncio
async def test_run_capture_stderr_captured() -> None:
    r = await run_capture(sys.executable, "-c", "import sys; sys.stderr.write('err\\n')")
    assert r.stderr == "err\n"
    assert r.stdout == ""


@pytest.mark.asyncio
async def test_run_capture_input_sent() -> None:
    r = await run_capture("/usr/bin/cat", input="payload\n")
    assert r.stdout == "payload\n"


@pytest.mark.asyncio
async def test_run_capture_timeout_kills() -> None:
    with pytest.raises(CommandTimeoutError) as ei:
        await run_capture("/bin/sleep", "10", timeout=0.2)
    assert ei.value.timeout == 0.2
    assert "/bin/sleep" in ei.value.args[0]


@pytest.mark.asyncio
async def test_run_capture_empty_argv_raises() -> None:
    with pytest.raises(ValueError, match="argv"):
        await run_capture()


def test_run_capture_sync() -> None:
    r = run_capture_sync("/bin/echo", "sync")
    assert isinstance(r, ProcessResult)
    assert r.ok
    assert r.stdout == "sync\n"


# ----- run_streaming -----

@pytest.mark.asyncio
async def test_run_streaming_yields_stdout_lines() -> None:
    lines = [
        line async for line in run_streaming(
            sys.executable, "-c",
            "import sys, time\n"
            "for i in range(3):\n"
            "    print(f'line{i}', flush=True)\n"
        )
    ]
    stdout_lines = [ln.line for ln in lines if ln.stream == "stdout"]
    assert stdout_lines == ["line0", "line1", "line2"]


@pytest.mark.asyncio
async def test_run_streaming_separates_streams() -> None:
    lines = [
        line async for line in run_streaming(
            sys.executable, "-c",
            "import sys\n"
            "print('out1'); sys.stderr.write('err1\\n'); print('out2')\n"
        )
    ]
    by_stream = {(ln.stream, ln.line) for ln in lines}
    assert ("stdout", "out1") in by_stream
    assert ("stderr", "err1") in by_stream
    assert ("stdout", "out2") in by_stream


@pytest.mark.asyncio
async def test_run_streaming_no_zombie_on_break() -> None:
    """Breaking out of the iterator early must reap the subprocess."""
    gen = run_streaming(sys.executable, "-c",
                        "import time\nwhile True: print('tick'); time.sleep(0.05)")
    seen = 0
    async for _ in gen:
        seen += 1
        if seen >= 3:
            break
    await gen.aclose()
    # No assertion needed — just demonstrate no hang / no exception.


# ----- require_root -----

def test_require_root_raises_when_non_root() -> None:
    if os.geteuid() == 0:
        pytest.skip("test only meaningful when running as non-root")
    with pytest.raises(PermissionError, match="root"):
        require_root()


def test_streamline_immutable() -> None:
    sl = StreamLine(stream="stdout", line="hi")
    with pytest.raises(AttributeError):
        sl.line = "boom"  # type: ignore[misc]
