"""Manual smoke test: connect → get_sys_config → disconnect.

Usage::

    uv run python scripts/smoke.py <host> [port]
"""

from __future__ import annotations

import asyncio
import sys

from ow2_mcp import TrapClient
from ow2_mcp.protocol import DEFAULT_PORT, arch_name, os_name


async def run(host: str, port: int) -> int:
    client = TrapClient()
    result = await client.connect(host, port)
    print(f"connected to {result.endpoint}")
    print(f"  server_reported_max = {result.server_reported_max}")
    print(f"  negotiated max_msg_size = {result.max_msg_size}")
    try:
        cfg = await client.get_sys_config()
        print("sys_config:")
        print(f"  cpu        = {cfg.cpu}")
        print(f"  fpu        = {cfg.fpu}")
        print(f"  os         = {os_name(cfg.os)} ({cfg.os_major}.{cfg.os_minor})")
        print(f"  arch       = {arch_name(cfg.arch)}")
        print(f"  huge_shift = {cfg.huge_shift}")
    finally:
        await client.disconnect()
        print("disconnected.")
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: smoke.py <host> [port]", file=sys.stderr)
        return 2
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
    return asyncio.run(run(host, port))


if __name__ == "__main__":
    raise SystemExit(main())
