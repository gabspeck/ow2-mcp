"""MITM logging proxy for the Watcom trap-server wire protocol.

Listens on ``listen_host:listen_port`` and forwards to ``upstream_host:upstream_port``,
dumping each request/reply frame with direction, length, and hex payload. Frame
boundaries follow the trap protocol: u16 little-endian length prefix followed by
``length`` bytes of payload.

Usage::

    uv run python scripts/trap_proxy.py --listen 0.0.0.0:12341 --upstream localhost:12340
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path


def _now() -> str:
    return time.strftime("%H:%M:%S", time.localtime()) + f".{int((time.time() % 1) * 1000):03d}"


async def _read_frame(reader: asyncio.StreamReader) -> bytes | None:
    header = await reader.readexactly(2) if not reader.at_eof() else b""
    if len(header) < 2:
        return None
    length = int.from_bytes(header, "little")
    if length == 0:
        return b""
    payload = await reader.readexactly(length)
    return payload


async def _pump(
    direction: str,
    src: asyncio.StreamReader,
    dst: asyncio.StreamWriter,
    log: Path,
) -> None:
    try:
        while True:
            try:
                header = await src.readexactly(2)
            except asyncio.IncompleteReadError as exc:
                if exc.partial:
                    _log(log, direction, b"<partial-header>", exc.partial)
                break
            length = int.from_bytes(header, "little")
            if length == 0:
                payload = b""
            else:
                try:
                    payload = await src.readexactly(length)
                except asyncio.IncompleteReadError as exc:
                    _log(log, direction, b"<truncated-payload>", exc.partial, expected=length)
                    dst.write(header + exc.partial)
                    await dst.drain()
                    break
            _log(log, direction, payload, expected=length)
            dst.write(header + payload)
            await dst.drain()
    finally:
        try:
            dst.close()
        except Exception:
            pass


def _log(log: Path, direction: str, payload: bytes, partial: bytes | None = None, *, expected: int | None = None) -> None:
    tag = direction
    parts = [f"[{_now()}] {tag:>8s}"]
    if expected is not None:
        parts.append(f"len={expected:5d}")
    parts.append(f"bytes={len(payload):5d}")
    parts.append(payload.hex())
    line = " ".join(parts) + "\n"
    with log.open("a") as fh:
        fh.write(line)
    sys.stdout.write(line)
    sys.stdout.flush()


async def handle_client(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    upstream_host: str,
    upstream_port: int,
    log: Path,
) -> None:
    peer = client_writer.get_extra_info("peername")
    _log(log, "CONNECT", f"client={peer} upstream={upstream_host}:{upstream_port}".encode())
    try:
        up_reader, up_writer = await asyncio.open_connection(upstream_host, upstream_port)
    except Exception as exc:
        _log(log, "ERROR", f"upstream open failed: {exc!r}".encode())
        client_writer.close()
        return

    c2u = asyncio.create_task(_pump("C->S", client_reader, up_writer, log))
    u2c = asyncio.create_task(_pump("S->C", up_reader, client_writer, log))
    try:
        await asyncio.gather(c2u, u2c)
    finally:
        _log(log, "CLOSE", f"client={peer}".encode())
        for w in (client_writer, up_writer):
            try:
                w.close()
            except Exception:
                pass


async def main_async(args: argparse.Namespace) -> int:
    log = Path(args.log)
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text("")  # truncate
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, args.upstream_host, args.upstream_port, log),
        host=args.listen_host,
        port=args.listen_port,
    )
    _log(log, "LISTEN", f"{args.listen_host}:{args.listen_port} -> {args.upstream_host}:{args.upstream_port}".encode())
    async with server:
        await server.serve_forever()
    return 0


def _parse_hostport(s: str) -> tuple[str, int]:
    host, _, port = s.rpartition(":")
    return host or "127.0.0.1", int(port)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="127.0.0.1:12341")
    ap.add_argument("--upstream", default="127.0.0.1:12340")
    ap.add_argument("--log", default="/tmp/ow2-trap-proxy.log")
    raw = ap.parse_args()
    lh, lp = _parse_hostport(raw.listen)
    uh, up = _parse_hostport(raw.upstream)
    ns = argparse.Namespace(
        listen_host=lh,
        listen_port=lp,
        upstream_host=uh,
        upstream_port=up,
        log=raw.log,
    )
    try:
        return asyncio.run(main_async(ns))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
