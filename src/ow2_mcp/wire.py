"""Async length-prefixed packet framing for the TRAP TCP link.

Mirrors ``RemoteGet`` / ``RemotePut`` in ``bld/trap/tcp/c/tcplink.c``: each
packet on the wire is ``[u16 length LE][payload]``. ``PACKET_MAX = 0x400``
(from ``bld/trap/common/packet.h`` ``PackBuff[0x400]``).
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import struct
from typing import Final

from .errors import ProtocolError, TransportError
from .protocol import PACKET_MAX

_HEADER: Final[int] = 2


class PacketChannel:
    """Pair of ``StreamReader``/``StreamWriter`` framed as TRAP packets."""

    __slots__ = ("_reader", "_writer")

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._reader = reader
        self._writer = writer

    async def send_packet(self, payload: bytes) -> None:
        if len(payload) > PACKET_MAX:
            raise ProtocolError(
                f"outgoing packet exceeds PACKET_MAX: {len(payload)} > {PACKET_MAX}"
            )
        frame = struct.pack("<H", len(payload)) + payload
        try:
            self._writer.write(frame)
            await self._writer.drain()
        except (OSError, asyncio.IncompleteReadError) as exc:
            raise TransportError(f"send failed: {exc}") from exc

    async def recv_packet(self, timeout: float | None = None) -> bytes:
        async def _recv() -> bytes:
            header = await self._reader.readexactly(_HEADER)
            (length,) = struct.unpack("<H", header)
            if length > PACKET_MAX:
                raise ProtocolError(
                    f"incoming packet exceeds PACKET_MAX: {length} > {PACKET_MAX}"
                )
            if length == 0:
                return b""
            return await self._reader.readexactly(length)

        try:
            if timeout is None:
                return await _recv()
            return await asyncio.wait_for(_recv(), timeout=timeout)
        except TimeoutError as exc:
            raise TransportError(f"recv timed out after {timeout:g}s") from exc
        except asyncio.IncompleteReadError as exc:
            raise TransportError(
                f"short read (expected {exc.expected}, got {len(exc.partial)})"
            ) from exc
        except OSError as exc:
            raise TransportError(f"recv failed: {exc}") from exc

    async def wait_peer_close(self, timeout: float) -> bool:
        """Wait for the peer to close the stream.

        Returns ``True`` on EOF, ``False`` on timeout, and raises
        :class:`TransportError` on other socket failures.
        """

        async def _wait() -> bool:
            data = await self._reader.read(1)
            return data == b""

        try:
            return await asyncio.wait_for(_wait(), timeout=timeout)
        except TimeoutError:
            return False
        except OSError as exc:
            raise TransportError(f"recv failed: {exc}") from exc

    async def close(self, *, abortive: bool = False) -> None:
        if abortive:
            sock = self._writer.get_extra_info("socket")
            if sock is not None:
                linger = struct.pack("ii", 1, 0)
                with contextlib.suppress(OSError):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
        try:
            self._writer.close()
            await self._writer.wait_closed()
        except OSError:
            pass


async def open_channel(host: str, port: int, timeout: float = 10.0) -> PacketChannel:
    """Open a TCP connection and wrap it in a ``PacketChannel``."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (OSError, TimeoutError) as exc:
        raise TransportError(f"connect to {host}:{port} failed: {exc}") from exc
    sock = writer.get_extra_info("socket")
    if sock is not None:
        with contextlib.suppress(OSError):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return PacketChannel(reader, writer)
