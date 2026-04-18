"""Reproduce the short-reply failures we saw against a Win95 trap server.

Drives the client through a full exercise of all trap tools:
connect -> get_sys_config -> prog_load(NOTEPAD.EXE) -> read_regs -> write_regs ->
read_mem -> prog_step -> read_regs -> prog_kill -> disconnect.

Runs through the MITM proxy (default port 12341) so the wire dump lines up with the
error path.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import traceback

from ow2_mcp import TrapClient
from ow2_mcp.protocol import Addr48


async def run(host: str, port: int, program: str) -> None:
    client = TrapClient()

    def step(label: str) -> None:
        print(f"\n=== {label} ===", flush=True)

    try:
        step("connect")
        conn = await client.connect(host, port)
        print(conn)

        step("get_sys_config")
        cfg = await client.get_sys_config()
        print(cfg)

        step(f"prog_load {program}")
        load = await client.prog_load(program)
        print(load)

        step("read_regs #1")
        regs = await client.read_regs()
        print(f"len={len(regs)} hex={regs.hex()}")

        step("write_regs (echo)")
        written = await client.write_regs(regs)
        print(f"written={written}")

        step("read_mem at EIP=0xbff76694 seg=0")
        data = await client.read_mem(0xBFF76694, 16)
        print(f"len={len(data)} hex={data.hex()}")

        step("prog_step")
        stepped = await client.prog_step()
        print(stepped)

        step("read_regs #2 (post-step)")
        regs2 = await client.read_regs()
        print(f"len={len(regs2)} hex={regs2.hex()}")

        step("prog_kill")
        try:
            killed = await client.prog_kill()
            print(f"killed={killed}")
        except Exception as exc:
            print(f"prog_kill FAILED: {exc!r}")

    except Exception:
        traceback.print_exc()
    finally:
        step("disconnect")
        try:
            await client.disconnect()
        except Exception as exc:
            print(f"disconnect failed: {exc!r}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=12341)
    ap.add_argument("--program", default="C:\\WINDOWS\\NOTEPAD.EXE")
    args = ap.parse_args()
    asyncio.run(run(args.host, args.port, args.program))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
