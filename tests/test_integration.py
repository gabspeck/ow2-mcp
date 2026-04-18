"""Integration test against a real ``tcpserv``.

Skipped unless ``OW2_MCP_TEST_HOST`` (and optionally ``OW2_MCP_TEST_PORT``) is
set. Run with, e.g.::

    OW2_MCP_TEST_HOST=10.0.0.5 uv run pytest tests/test_integration.py
"""

from __future__ import annotations

import os

import pytest

from ow2_mcp.client import TrapClient
from ow2_mcp.protocol import DEFAULT_PORT, DIG_ARCH_NAMES

HOST = os.environ.get("OW2_MCP_TEST_HOST")
PORT = int(os.environ.get("OW2_MCP_TEST_PORT", DEFAULT_PORT))


pytestmark = pytest.mark.skipif(
    HOST is None,
    reason="OW2_MCP_TEST_HOST not set — set it to the tcpserv host to enable integration",
)


async def test_connect_sys_config_disconnect() -> None:
    assert HOST is not None
    client = TrapClient()
    result = await client.connect(HOST, PORT)
    try:
        assert result.max_msg_size >= 256
        cfg = await client.get_sys_config()
        assert 0 <= cfg.arch < len(DIG_ARCH_NAMES)
    finally:
        await client.disconnect()


async def test_flat_read_mem_at_eip_returns_bytes() -> None:
    assert HOST is not None
    client = TrapClient()
    await client.connect(HOST, PORT)
    try:
        cfg = await client.get_sys_config()
        if not (cfg.arch == 1 and cfg.os == 10):  # x86 + Win32
            pytest.skip(
                f"flat-mode fix only applies to x86/Win32 "
                f"(got arch={cfg.arch}, os={cfg.os})"
            )
        load = await client.prog_load("C:\\WINDOWS\\NOTEPAD.EXE")
        assert load.err == 0, f"prog_load failed: err={load.err}"
        try:
            regs = await client.read_regs()
            assert len(regs) >= 36, f"register block too short: {len(regs)}"
            eip = int.from_bytes(regs[32:36], "little")
            # segment=0 must now resolve to FlatDS server-side.
            data = await client.read_mem(eip, 16)
            assert len(data) == 16, f"flat-mode read returned {len(data)} bytes (expected 16)"
            assert client.flat_ds is not None and client.flat_ds != 0
        finally:
            await client.prog_kill()
    finally:
        await client.disconnect()
