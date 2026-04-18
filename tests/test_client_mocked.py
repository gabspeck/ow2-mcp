"""End-to-end tests against a scripted asyncio server speaking TRAP framing."""

from __future__ import annotations

import asyncio
import struct
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import asynccontextmanager

import pytest

from ow2_mcp import protocol as p
from ow2_mcp.client import TrapClient, send_interrupt
from ow2_mcp.errors import (
    AlreadyConnectedError,
    NotConnectedError,
    ProtocolError,
    TrapServerError,
)
from ow2_mcp.protocol import PACKET_MAX, Req


async def _read_packet(reader: asyncio.StreamReader) -> bytes:
    header = await reader.readexactly(2)
    (length,) = struct.unpack("<H", header)
    if length == 0:
        return b""
    return await reader.readexactly(length)


async def _write_packet(writer: asyncio.StreamWriter, payload: bytes) -> None:
    writer.write(struct.pack("<H", len(payload)) + payload)
    await writer.drain()


Handler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], "asyncio.Future[None] | object"]


@asynccontextmanager
async def _server(handler: Handler) -> AsyncIterator[tuple[str, int]]:
    async def _serve(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            result = handler(reader, writer)
            if asyncio.iscoroutine(result):
                await result
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass

    srv = await asyncio.start_server(_serve, "127.0.0.1", 0)
    sockets = srv.sockets or ()
    host, port = sockets[0].getsockname()[:2]
    try:
        yield host, port
    finally:
        srv.close()
        await srv.wait_closed()


def _scripted(script: Sequence[tuple[bytes | None, bytes | None]]) -> Handler:
    """Build a handler that, for each ``(expected_request, response)`` pair:

    - If ``expected_request`` is not None, asserts the next packet matches it.
    - If ``response`` is not None, sends it back (``b""`` means empty packet).
    - If ``response`` is None, drops the socket (simulates peer abort).
    """

    async def _handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        for expected, response in script:
            try:
                got = await _read_packet(reader)
            except asyncio.IncompleteReadError:
                return
            if expected is not None:
                assert got == expected, f"expected {expected!r}, got {got!r}"
            if response is None:
                writer.transport.close()  # type: ignore[union-attr]
                return
            await _write_packet(writer, response)

    return _handler


# ---------- connect/disconnect ------------------------------------------------


async def test_connect_success_and_disconnect() -> None:
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),   # connect → max=1024
        (b"\x01", None),                            # disconnect is best-effort, no reply
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        result = await client.connect(host, port)
        assert result.max_msg_size == 1024
        assert result.server_reported_max == 1024
        assert client.connected
        await client.disconnect()
        assert not client.connected


async def test_connect_clamps_server_reported_max() -> None:
    # Some local traps return 0xFFFF — we must clamp to PACKET_MAX.
    script = [(b"\x00\x12\x00\x00", b"\xff\xff\x00")]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        result = await client.connect(host, port)
        assert result.server_reported_max == 0xFFFF
        assert result.max_msg_size == PACKET_MAX


async def test_connect_error_string_raises() -> None:
    payload = b"\x00\x04" + b"bad version\x00"
    async with _server(_scripted([(b"\x00\x12\x00\x00", payload)])) as (host, port):
        client = TrapClient()
        with pytest.raises(TrapServerError) as excinfo:
            await client.connect(host, port)
        assert "bad version" in str(excinfo.value)


async def test_double_connect_raises_unless_forced() -> None:
    # One connect succeeds, next raises AlreadyConnectedError without force.
    script = [(b"\x00\x12\x00\x00", b"\x00\x04\x00")]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        with pytest.raises(AlreadyConnectedError):
            await client.connect(host, port)


# ---------- RPC gate & teardown ----------------------------------------------


async def test_rpc_before_connect_raises_not_connected() -> None:
    client = TrapClient()
    with pytest.raises(NotConnectedError):
        await client.get_sys_config()


async def test_teardown_on_socket_drop() -> None:
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (b"\x06", None),  # server drops socket mid-request
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        from ow2_mcp.errors import TransportError

        with pytest.raises(TransportError):
            await client.get_sys_config()
        assert not client.connected
        with pytest.raises(NotConnectedError):
            await client.get_sys_config()


# ---------- typed calls -------------------------------------------------------


async def test_get_sys_config_round_trip() -> None:
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (bytes([Req.GET_SYS_CONFIG]), b"\x05\x02\x00\x01\x0D\x00\x01"),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        cfg = await client.get_sys_config()
        assert cfg.os == 13
        assert cfg.arch == 1


async def test_read_mem_chunks_by_max_msg_size() -> None:
    """``read_mem(3000)`` with max=1024 ⇒ 3 round trips: 1024 + 1024 + 952."""
    chunks = [b"\xaa" * 1024, b"\xbb" * 1024, b"\xcc" * 952]
    script = [(b"\x00\x12\x00\x00", b"\x00\x04\x00")]
    offset = 0x1000
    for i, ch in enumerate(chunks):
        req = p.pack_read_mem_req(p.Addr48(offset=offset + i * 1024, segment=1), len(ch))
        script.append((req, ch))
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        data = await client.read_mem(0x1000, 3000, segment=1)
        assert len(data) == 3000
        assert data[:1024] == b"\xaa" * 1024
        assert data[1024:2048] == b"\xbb" * 1024
        assert data[2048:] == b"\xcc" * 952


async def test_read_mem_short_reply_stops_loop() -> None:
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (p.pack_read_mem_req(p.Addr48(offset=0, segment=1), 500), b"\x01\x02\x03"),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        data = await client.read_mem(0, 500, segment=1)
        assert data == b"\x01\x02\x03"


async def test_write_mem_chunks_by_max_msg_size_minus_header() -> None:
    """``write_mem`` chunks = max_msg_size - 7 (u8 req + 6-byte addr)."""
    payload = b"\xde" * 2000
    max_chunk = 1024 - 7
    chunks = [payload[i : i + max_chunk] for i in range(0, len(payload), max_chunk)]
    script = [(b"\x00\x12\x00\x00", b"\x00\x04\x00")]
    cursor = 0
    for ch in chunks:
        req = p.pack_write_mem_req(p.Addr48(offset=cursor, segment=1), ch)
        reply = struct.pack("<H", len(ch))
        script.append((req, reply))
        cursor += len(ch)
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        written = await client.write_mem(0, payload, segment=1)
        assert written == 2000


async def test_write_regs_requires_prior_read_regs() -> None:
    script = [(b"\x00\x12\x00\x00", b"\x00\x04\x00")]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        with pytest.raises(ProtocolError):
            await client.write_regs(b"\x00" * 16)


async def test_read_regs_then_write_regs() -> None:
    reg_data = b"\x11" * 40
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (bytes([Req.READ_REGS]), reg_data),
        (bytes([Req.WRITE_REGS]) + reg_data, b""),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        got = await client.read_regs()
        assert got == reg_data
        assert client.reg_size == 40
        written = await client.write_regs(reg_data)
        assert written == 40


async def test_write_regs_size_mismatch_rejected() -> None:
    reg_data = b"\x11" * 40
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (bytes([Req.READ_REGS]), reg_data),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        await client.read_regs()
        with pytest.raises(ProtocolError):
            await client.write_regs(b"\x00" * 8)


async def test_prog_load_stores_task_id_and_kill_defaults_to_it() -> None:
    load_reply = b"\x00\x00\x00\x00" + b"\xcd\xab\x00\x00" + b"\x34\x12\x00\x00" + b"\x04"
    kill_reply = b"\x00\x00\x00\x00"
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (b"\x0f\x00hello\x00\x00", load_reply),
        (b"\x10\xcd\xab\x00\x00", kill_reply),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        result = await client.prog_load("hello")
        assert result.task_id == 0xABCD
        assert result.mod_handle == 0x1234
        assert client.loaded is not None
        assert client.loaded.task_id == 0xABCD
        err = await client.prog_kill()
        assert err == 0
        assert client.loaded is None


async def test_set_break_returns_old_and_clear_break_echoes_it() -> None:
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (p.pack_set_break_req(p.Addr48(offset=0x400, segment=1)), b"\xcc\x00\x00\x00"),
        (p.pack_clear_break_req(p.Addr48(offset=0x400, segment=1), 0xCC), b""),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        old = await client.set_break(0x400, segment=1)
        assert old == 0xCC
        await client.clear_break(0x400, old, segment=1)


async def test_prog_go_decodes_conditions() -> None:
    go_reply = (
        b"\x00\x00\x00\x00\x00\x00"  # SP
        b"\x00\x10\x00\x00\x00\x00"  # PC 0x1000
        b"\x80\x20"                  # BREAK|STOP
    )
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (bytes([Req.PROG_GO]), go_reply),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        result = await client.prog_go()
        assert result.program_counter.offset == 0x1000
        assert result.conditions == (p.Cond.BREAK | p.Cond.STOP)


# ---------- flat-mode segment substitution (seg=0 → cached DS) ---------------


def _x86_reg_block(ds: int = 0x0023, cs: int = 0x001B) -> bytes:
    """Build a 304-byte x86 register reply with DS and CS at the canonical offsets."""
    block = bytearray(304)
    struct.pack_into("<H", block, p.X86_REG_DS_OFFSET, ds)
    struct.pack_into("<H", block, p.X86_REG_CS_OFFSET, cs)
    return bytes(block)


async def test_read_mem_substitutes_cached_flat_ds() -> None:
    reg_block = _x86_reg_block(ds=0x0023, cs=0x001B)
    mem_bytes = b"\x90\x90\x90\x90"
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (bytes([Req.READ_REGS]), reg_block),
        (p.pack_read_mem_req(p.Addr48(offset=0x1000, segment=0x0023), 4), mem_bytes),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        await client.read_regs()
        assert client.flat_ds == 0x0023
        assert client.flat_cs == 0x001B
        data = await client.read_mem(0x1000, 4)
        assert data == mem_bytes


async def test_read_mem_auto_triggers_read_regs_when_cache_empty() -> None:
    reg_block = _x86_reg_block(ds=0x0023, cs=0x001B)
    mem_bytes = b"\x90\x90\x90\x90"
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (bytes([Req.READ_REGS]), reg_block),
        (p.pack_read_mem_req(p.Addr48(offset=0x1000, segment=0x0023), 4), mem_bytes),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        data = await client.read_mem(0x1000, 4)
        assert data == mem_bytes
        assert client.flat_ds == 0x0023


async def test_prog_go_zero_byte_reply_has_hint() -> None:
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (bytes([Req.PROG_GO]), b""),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        with pytest.raises(ProtocolError) as excinfo:
            await client.prog_go()
        assert "state corruption" in str(excinfo.value).lower()


async def test_send_interrupt_suspend_uses_one_shot_connection() -> None:
    seen: list[bytes] = []
    eof = asyncio.Event()

    async def _handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        seen.append(await _read_packet(reader))
        tail = await reader.read()
        assert tail == b""
        eof.set()

    async with _server(_handler) as (host, port):
        await send_interrupt(host, port)
        await asyncio.wait_for(eof.wait(), timeout=1.0)
    assert seen == [p.pack_suspend_req()]


async def test_send_interrupt_resume_uses_resume_opcode() -> None:
    seen: list[bytes] = []
    eof = asyncio.Event()

    async def _handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        seen.append(await _read_packet(reader))
        tail = await reader.read()
        assert tail == b""
        eof.set()

    async with _server(_handler) as (host, port):
        await send_interrupt(host, port, resume=True)
        await asyncio.wait_for(eof.wait(), timeout=1.0)
    assert seen == [p.pack_resume_req()]


async def test_get_supplementary_service_round_trip() -> None:
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (p.pack_get_supplementary_service_req("files"), b"\x00\x00\x00\x00\x34\x12\x00\x00"),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        result = await client.get_supplementary_service("files")
        assert result.err == 0
        assert result.shandle == 0x1234


async def test_map_addr_does_not_substitute_flat_segment() -> None:
    map_reply = b"\x00\x20\x00\x00\x00\x00\x11\x11\x11\x11\x22\x22\x22\x22"
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (p.pack_map_addr_req(p.Addr48(offset=0x2000, segment=0), 0x99), map_reply),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        result = await client.map_addr(0x2000, 0, mod_handle=0x99)
        assert result.out_addr.offset == 0x2000
        assert result.out_addr.segment == 0


async def test_map_addr_flat_code_uses_magic_selector() -> None:
    map_reply = b"\x00\x20\x00\x00\x23\x00\x11\x11\x11\x11\x22\x22\x22\x22"
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (
            p.pack_map_addr_req(
                p.Addr48(offset=0x2000, segment=p.MAP_FLAT_CODE_SELECTOR),
                0x99,
            ),
            map_reply,
        ),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        result = await client.map_addr(0x2000, mod_handle=0x99, space="flat_code")
        assert result.out_addr.segment == 0x0023


async def test_map_addr_flat_data_uses_magic_selector() -> None:
    map_reply = b"\x34\x12\x00\x00\x24\x00\x11\x11\x11\x11\x22\x22\x22\x22"
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (
            p.pack_map_addr_req(
                p.Addr48(offset=0x1234, segment=p.MAP_FLAT_DATA_SELECTOR),
                0x77,
            ),
            map_reply,
        ),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        result = await client.map_addr(0x1234, mod_handle=0x77, space="flat_data")
        assert result.out_addr.segment == 0x0024


async def test_map_addr_invalid_space_rejected() -> None:
    script = [(b"\x00\x12\x00\x00", b"\x00\x04\x00")]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        with pytest.raises(ValueError, match="invalid MAP_ADDR space"):
            await client.map_addr(0x2000, space="flat")


async def test_checksum_mem_round_trip() -> None:
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (p.pack_checksum_mem_req(p.Addr48(offset=0x1000, segment=1), 16), b"\xef\xbe\xad\xde"),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        checksum = await client.checksum_mem(0x1000, 16, segment=1)
        assert checksum == 0xDEADBEEF


async def test_checksum_mem_substitutes_cached_flat_ds() -> None:
    reg_block = _x86_reg_block(ds=0x0023, cs=0x001B)
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (bytes([Req.READ_REGS]), reg_block),
        (p.pack_checksum_mem_req(p.Addr48(offset=0x1000, segment=0x0023), 16), b"\x78\x56\x34\x12"),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        checksum = await client.checksum_mem(0x1000, 16)
        assert checksum == 0x12345678


async def test_read_io_and_write_io_round_trip() -> None:
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (p.pack_read_io_req(0x3F8, 4), b"\xaa\xbb\xcc\xdd"),
        (p.pack_write_io_req(0x3F8, b"\x11\x22"), b"\x02"),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        assert await client.read_io(0x3F8, 4) == b"\xaa\xbb\xcc\xdd"
        assert await client.write_io(0x3F8, b"\x11\x22") == 2


async def test_get_next_alias_round_trip() -> None:
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (p.pack_get_next_alias_req(0x1234), b"\x34\x12\x78\x56"),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        result = await client.get_next_alias(0x1234)
        assert result.seg == 0x1234
        assert result.alias == 0x5678


async def test_set_watch_and_clear_watch_round_trip() -> None:
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (
            p.pack_set_watch_req(p.Addr48(offset=0x2000, segment=1), 4),
            b"\x01\x00\x00\x00\x04\x00\x00\x00",
        ),
        (p.pack_clear_watch_req(p.Addr48(offset=0x2000, segment=1), 4), b""),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        result = await client.set_watch(0x2000, 4, segment=1)
        assert result.err == 1
        assert result.multiplier == 4
        await client.clear_watch(0x2000, 4, segment=1)


async def test_set_and_clear_watch_substitute_cached_flat_ds() -> None:
    reg_block = _x86_reg_block(ds=0x0023, cs=0x001B)
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (bytes([Req.READ_REGS]), reg_block),
        (
            p.pack_set_watch_req(p.Addr48(offset=0x2000, segment=0x0023), 2),
            b"\x00\x00\x00\x00\x01\x00\x00\x00",
        ),
        (p.pack_clear_watch_req(p.Addr48(offset=0x2000, segment=0x0023), 2), b""),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        result = await client.set_watch(0x2000, 2)
        assert result.multiplier == 1
        await client.clear_watch(0x2000, 2)


async def test_set_user_screen_round_trip() -> None:
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (p.pack_set_user_screen_req(), b""),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        await client.set_user_screen()


async def test_set_debug_screen_round_trip() -> None:
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (p.pack_set_debug_screen_req(), b""),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        await client.set_debug_screen()


async def test_keyboard_lib_redirect_and_split_round_trip() -> None:
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (p.pack_read_user_keyboard_req(250), b"A"),
        (p.pack_get_lib_name_req(0), b"\x34\x12\x00\x00watcom.dll\x00"),
        (p.pack_redirect_stdin_req("input.txt"), b"\x00\x00\x00\x00"),
        (p.pack_redirect_stdout_req("output.txt"), b"\x05\x00\x00\x00"),
        (p.pack_split_cmd_req("prog arg"), b"\x04\x00\x05\x00"),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        assert await client.read_user_keyboard(250) == 0x41
        lib = await client.get_lib_name(0)
        assert lib.mod_handle == 0x1234
        assert lib.name == "watcom.dll"
        assert await client.redirect_stdin("input.txt") == 0
        assert await client.redirect_stdout("output.txt") == 5
        split = await client.split_cmd("prog arg")
        assert split.cmd_end == 4
        assert split.parm_start == 5


async def test_machine_data_round_trip() -> None:
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (
            p.pack_machine_data_req(2, p.Addr48(offset=0x3000, segment=1), b"\xaa\xbb"),
            b"\x00\x10\x00\x00\x00\x20\x00\x00\xde\xad",
        ),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        result = await client.machine_data(2, 0x3000, segment=1, extra=b"\xaa\xbb")
        assert result.cache_start == 0x1000
        assert result.cache_end == 0x2000
        assert result.extra == b"\xde\xad"


async def test_machine_data_substitutes_cached_flat_ds() -> None:
    reg_block = _x86_reg_block(ds=0x0023, cs=0x001B)
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (bytes([Req.READ_REGS]), reg_block),
        (
            p.pack_machine_data_req(1, p.Addr48(offset=0x4000, segment=0x0023), b"\x99"),
            b"\x00\x10\x00\x00\x00\x20\x00\x00",
        ),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        result = await client.machine_data(1, 0x4000, extra=b"\x99")
        assert result.cache_start == 0x1000
        assert result.cache_end == 0x2000


async def test_supplementary_handle_is_cached_per_service() -> None:
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (p.pack_get_supplementary_service_req(p.SUPP_FILES), b"\x00\x00\x00\x00\x44\x33\x22\x11"),
        (p.pack_file_get_config_req(0x11223344), b".:\\/\r\n;"),
        (
            p.pack_file_open_req(0x11223344, 2, "config.sys"),
            b"\x00\x00\x00\x00" + b"\x88\x77\x66\x55\x00\x00\x00\x00",
        ),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        cfg = await client.file_get_config()
        opened = await client.file_open(2, "config.sys")
        assert cfg.ext_separator == "."
        assert opened.handle == 0x55667788


async def test_env_overlay_thread_runthread_rfx_capability_and_async_round_trip() -> None:
    script = [
        (b"\x00\x12\x00\x00", b"\x00\x04\x00"),
        (
            p.pack_get_supplementary_service_req(p.SUPP_ENVIRONMENT),
            b"\x00\x00\x00\x00\x10\x00\x00\x00",
        ),
        (
            p.pack_env_get_var_req(0x10, 128, "PATH"),
            b"\x00\x00\x00\x00C:\\OW2;C:\\BIN\x00",
        ),
        (
            p.pack_get_supplementary_service_req(p.SUPP_OVERLAYS),
            b"\x00\x00\x00\x00\x20\x00\x00\x00",
        ),
        (
            p.pack_ovl_trans_vect_addr_req(
                0x20, p.OvlAddress(mach=p.Addr48(offset=0x1000, segment=0x23), sect_id=7)
            ),
            b"\x78\x56\x34\x12\x9a\x00\x05\x00",
        ),
        (p.pack_get_supplementary_service_req(p.SUPP_THREADS), b"\x00\x00\x00\x00\x30\x00\x00\x00"),
        (p.pack_thread_get_next_req(0x30, 0), b"\x34\x12\x00\x00\x01"),
        (
            p.pack_get_supplementary_service_req(p.SUPP_RUN_THREAD),
            b"\x00\x00\x00\x00\x40\x00\x00\x00",
        ),
        (p.pack_run_thread_info_req(0x40, 1), b"\x01\x0c\x00Name\x00"),
        (p.pack_get_supplementary_service_req(p.SUPP_RFX), b"\x00\x00\x00\x00\x50\x00\x00\x00"),
        (
            p.pack_rfx_findfirst_req(0x50, 0x20, "*.exe"),
            b"\x00\x00\x00\x00"
            + (b"\x00" * 21)
            + b"\x20"
            + b"\x34\x12"
            + b"\x78\x56"
            + b"\x10\x00\x00\x00"
            + b"kernel.exe\x00",
        ),
        (
            p.pack_get_supplementary_service_req(p.SUPP_CAPABILITIES),
            b"\x00\x00\x00\x00\x60\x00\x00\x00",
        ),
        (p.pack_capabilities_get_exact_bp_req(0x60), b"\x00\x00\x00\x00\x01"),
        (p.pack_get_supplementary_service_req(p.SUPP_ASYNCH), b"\x00\x00\x00\x00\x70\x00\x00\x00"),
        (
            p.pack_async_go_req(0x70),
            b"\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x23\x00\x80\x20",
        ),
    ]
    async with _server(_scripted(script)) as (host, port):
        client = TrapClient()
        await client.connect(host, port)
        env = await client.env_get_var(128, "PATH")
        ovl = await client.ovl_trans_vect_addr(
            p.OvlAddress(mach=p.Addr48(offset=0x1000, segment=0x23), sect_id=7)
        )
        thread = await client.thread_get_next(0)
        info = await client.run_thread_info(1)
        found = await client.rfx_findfirst(0x20, "*.exe")
        cap = await client.capabilities_get_exact_bp()
        async_result = await client.async_go()
        assert env.value == "C:\\OW2;C:\\BIN"
        assert ovl.sect_id == 5
        assert thread.state == p.ThreadState.FROZEN
        assert info.header == "Name"
        assert found.info is not None and found.info.name == "kernel.exe"
        assert cap.status == 1
        assert async_result.conditions == (p.Cond.BREAK | p.Cond.STOP)
