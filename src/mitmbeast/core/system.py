"""Async subprocess helpers used across the mitmbeast core.

The bash scripts shelled out to dozens of commands and parsed stdout/stderr
ad-hoc. The Python core needs three primitives:

* :func:`run_capture` — fire-and-collect: run a command, capture both
  streams, return a structured :class:`ProcessResult`. Optional ``check``
  flag raises on non-zero exit. Optional ``timeout`` aborts long runs.
* :func:`run_streaming` — yield lines from stdout/stderr as they arrive.
  Used for log-tailing daemons (hostapd events, dnsmasq DHCP traffic) and
  feeding the event bus.
* :func:`require_root` — refuse to proceed unless we are root. Most of
  what mitmbeast does requires root (iptables, hostapd, raw sockets).

Errors are first-class:

* :class:`CommandFailedError` — non-zero exit when ``check=True``.
* :class:`CommandTimeoutError` — exceeded ``timeout``.

Both carry the full :class:`ProcessResult` (or the argv) for diagnostics.

A synchronous wrapper :func:`run_capture_sync` is provided for the
phase-2a Click CLI which is itself synchronous; later phases use the
async API directly from the supervisor.
"""
from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "CommandFailedError",
    "CommandTimeoutError",
    "ProcessResult",
    "StreamLine",
    "require_root",
    "run_capture",
    "run_capture_sync",
    "run_streaming",
]


@dataclass(frozen=True, slots=True)
class ProcessResult:
    """Outcome of a captured subprocess run."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


@dataclass(frozen=True, slots=True)
class StreamLine:
    """One line from a streaming subprocess.

    ``stream`` is ``"stdout"`` or ``"stderr"``. ``line`` has no trailing
    newline.
    """

    stream: str
    line: str


class CommandFailedError(Exception):
    """A subprocess invoked with ``check=True`` exited non-zero."""

    def __init__(self, result: ProcessResult) -> None:
        self.result = result
        argv = " ".join(result.argv)
        msg = f"command exited {result.returncode}: {argv}"
        if result.stderr.strip():
            msg += f"\nstderr: {result.stderr.strip()}"
        super().__init__(msg)


class CommandTimeoutError(Exception):
    """A subprocess exceeded its ``timeout`` and was killed."""

    def __init__(self, argv: Iterable[str], timeout: float) -> None:
        self.argv = tuple(argv)
        self.timeout = timeout
        super().__init__(
            f"command timed out after {timeout:.1f}s: {' '.join(self.argv)}"
        )


def require_root() -> None:
    """Raise :class:`PermissionError` unless the process is root.

    Most mitmbeast operations need CAP_NET_ADMIN at minimum and in
    practice we just require euid 0. The bash scripts had the same check.
    """
    if os.geteuid() != 0:
        raise PermissionError(
            "mitmbeast must run as root for this operation. Re-run with sudo."
        )


async def run_capture(
    *argv: str,
    env: Mapping[str, str] | None = None,
    cwd: str | Path | None = None,
    timeout: float | None = None,  # noqa: ASYNC109 — mirrors subprocess.run
    check: bool = False,
    input: str | None = None,
) -> ProcessResult:
    """Run ``argv`` and capture stdout/stderr.

    :param argv: program and arguments — strings only, no shell.
    :param env: environment override (``None`` = inherit).
    :param cwd: working directory (``None`` = current).
    :param timeout: kill after this many seconds. Raises
        :class:`CommandTimeoutError`.
    :param check: raise :class:`CommandFailedError` on non-zero exit.
    :param input: stdin payload (text). ``None`` = no stdin.
    """
    if not argv:
        raise ValueError("run_capture requires at least one argv element")

    proc = await asyncio.create_subprocess_exec(
        *argv,
        env=dict(env) if env is not None else None,
        cwd=str(cwd) if cwd is not None else None,
        stdin=asyncio.subprocess.PIPE if input is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdin_data = input.encode("utf-8") if input is not None else None
    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(stdin_data),
            timeout=timeout,
        )
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise CommandTimeoutError(argv, timeout or 0.0) from None

    result = ProcessResult(
        argv=tuple(argv),
        returncode=proc.returncode or 0,
        stdout=stdout_b.decode("utf-8", errors="replace"),
        stderr=stderr_b.decode("utf-8", errors="replace"),
    )
    if check and not result.ok:
        raise CommandFailedError(result)
    return result


def run_capture_sync(*argv: str, **kwargs: Any) -> ProcessResult:
    """Synchronous wrapper for :func:`run_capture`.

    Convenient for Click commands that aren't themselves async. Avoid
    nesting this inside an already-running event loop — call
    :func:`run_capture` directly there.
    """
    return asyncio.run(run_capture(*argv, **kwargs))


async def run_streaming(
    *argv: str,
    env: Mapping[str, str] | None = None,
    cwd: str | Path | None = None,
) -> AsyncIterator[StreamLine]:
    """Run ``argv`` and yield stdout/stderr lines as they arrive.

    Lines from both streams are interleaved in arrival order. The
    iterator completes when the subprocess exits and both streams hit
    EOF. If the consumer breaks early, the subprocess is killed and
    reaped before the function returns (no zombies).
    """
    if not argv:
        raise ValueError("run_streaming requires at least one argv element")

    proc = await asyncio.create_subprocess_exec(
        *argv,
        env=dict(env) if env is not None else None,
        cwd=str(cwd) if cwd is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    # Both readers feed a single queue. Sentinel `None` signals EOF on a
    # stream; we yield until both streams have closed.
    queue: asyncio.Queue[StreamLine | None] = asyncio.Queue()

    async def _reader(stream: asyncio.StreamReader | None, name: str) -> None:
        if stream is None:
            await queue.put(None)
            return
        try:
            async for raw in stream:
                text = raw.decode("utf-8", errors="replace").rstrip("\n")
                await queue.put(StreamLine(stream=name, line=text))
        finally:
            await queue.put(None)

    tasks = [
        asyncio.create_task(_reader(proc.stdout, "stdout")),
        asyncio.create_task(_reader(proc.stderr, "stderr")),
    ]

    try:
        sentinels = 0
        while sentinels < 2:
            item = await queue.get()
            if item is None:
                sentinels += 1
                continue
            yield item
        await proc.wait()
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        if proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            await proc.wait()
