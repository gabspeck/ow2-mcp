"""Unit tests for the length-prefixed packet framing."""

from __future__ import annotations

import asyncio
import socket
import struct

import pytest

from ow2_mcp.errors import ProtocolError, TransportError
from ow2_mcp.protocol import PACKET_MAX
from ow2_mcp.wire import PacketChannel


class _FakeWriter:
    """Minimal ``StreamWriter`` stand-in that captures every ``write``."""

    def __init__(self) -> None:
        self.buffer = bytearray()
        self.closed = False
        self.sock: object | None = None

    def write(self, data: bytes) -> None:
        self.buffer.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None

    def get_extra_info(self, name: str, default: object = None) -> object:
        if name == "socket" and self.sock is not None:
            return self.sock
        return default


class _FakeSocket:
    def __init__(self) -> None:
        self.calls: list[tuple[int, int, bytes]] = []

    def setsockopt(self, level: int, optname: int, value: bytes) -> None:
        self.calls.append((level, optname, value))


def _reader_from(data: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


async def _channel(reader_data: bytes = b"") -> tuple[PacketChannel, _FakeWriter]:
    writer = _FakeWriter()
    reader = _reader_from(reader_data)
    return PacketChannel(reader, writer), writer  # type: ignore[arg-type]


async def test_send_empty_packet_writes_header_only() -> None:
    channel, writer = await _channel()
    await channel.send_packet(b"")
    assert writer.buffer == b"\x00\x00"


async def test_send_payload_prepends_u16_le_length() -> None:
    channel, writer = await _channel()
    await channel.send_packet(b"abc")
    assert writer.buffer == b"\x03\x00abc"


async def test_send_rejects_oversized_packet() -> None:
    channel, _ = await _channel()
    with pytest.raises(ProtocolError):
        await channel.send_packet(b"\x00" * (PACKET_MAX + 1))


async def test_recv_packet_handles_split_reads() -> None:
    reader = asyncio.StreamReader()
    writer = _FakeWriter()
    channel = PacketChannel(reader, writer)  # type: ignore[arg-type]

    async def feed() -> None:
        reader.feed_data(b"\x05\x00he")
        await asyncio.sleep(0)
        reader.feed_data(b"llo")
        reader.feed_eof()

    feeder = asyncio.create_task(feed())
    payload = await channel.recv_packet()
    await feeder
    assert payload == b"hello"


async def test_recv_zero_length_packet() -> None:
    channel, _ = await _channel(b"\x00\x00")
    assert await channel.recv_packet() == b""


async def test_recv_short_read_raises_transport_error() -> None:
    channel, _ = await _channel(b"\x05\x00he")  # header promises 5 bytes, only 2 delivered
    with pytest.raises(TransportError):
        await channel.recv_packet()


async def test_recv_timeout_raises_transport_error() -> None:
    reader = asyncio.StreamReader()
    writer = _FakeWriter()
    channel = PacketChannel(reader, writer)  # type: ignore[arg-type]
    with pytest.raises(TransportError, match="recv timed out"):
        await channel.recv_packet(timeout=0.01)


async def test_recv_oversized_length_raises_protocol_error() -> None:
    # Announce PACKET_MAX+1 bytes. Must reject before attempting a huge read.
    bogus = (PACKET_MAX + 1).to_bytes(2, "little")
    channel, _ = await _channel(bogus)
    with pytest.raises(ProtocolError):
        await channel.recv_packet()


async def test_abortive_close_sets_linger_before_close() -> None:
    writer = _FakeWriter()
    sock = _FakeSocket()
    writer.sock = sock
    reader = _reader_from(b"")
    channel = PacketChannel(reader, writer)  # type: ignore[arg-type]

    await channel.close(abortive=True)

    assert writer.closed
    assert len(sock.calls) == 1
    level, optname, value = sock.calls[0]
    assert level == socket.SOL_SOCKET
    assert optname == socket.SO_LINGER
    assert value == struct.pack("ii", 1, 0)


async def test_wait_peer_close_returns_true_on_eof() -> None:
    writer = _FakeWriter()
    reader = _reader_from(b"")
    channel = PacketChannel(reader, writer)  # type: ignore[arg-type]

    assert await channel.wait_peer_close(0.01) is True


async def test_wait_peer_close_times_out_when_peer_stays_open() -> None:
    reader = asyncio.StreamReader()
    writer = _FakeWriter()
    channel = PacketChannel(reader, writer)  # type: ignore[arg-type]

    assert await channel.wait_peer_close(0.01) is False
