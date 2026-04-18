"""Stateful asyncio client for the OpenWatcom TRAP protocol."""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass

from . import protocol as p
from .errors import (
    AlreadyConnectedError,
    NotConnectedError,
    ProtocolError,
    TransportError,
    TrapServerError,
)
from .protocol import (
    Addr48,
    AliasResult,
    LibNameResult,
    MachineDataResult,
    MapAddrResult,
    MessageText,
    ProgGoResult,
    ProgLoadResult,
    SetWatchResult,
    SplitCmdResult,
    SupplementaryServiceResult,
    SysConfig,
)
from .wire import PacketChannel, open_channel

MapAddrSpace = str


@dataclass(slots=True)
class LoadedProgram:
    task_id: int
    mod_handle: int
    flags: int
    program: str


@dataclass(frozen=True, slots=True)
class ConnectResult:
    max_msg_size: int
    server_reported_max: int
    endpoint: str


async def send_interrupt(
    host: str,
    port: int = p.DEFAULT_PORT,
    *,
    resume: bool = False,
    timeout: float = 5.0,
) -> None:
    """Send REQ_SUSPEND or REQ_RESUME on a fresh one-shot TCP connection."""
    channel = await open_channel(host, port, timeout=timeout)
    try:
        payload = p.pack_resume_req() if resume else p.pack_suspend_req()
        await channel.send_packet(payload)
    finally:
        await channel.close()


class TrapClient:
    """Single-connection TRAP client.

    The OpenWatcom TRAP protocol is strictly request/reply — one outstanding
    request at a time. A single :class:`asyncio.Lock` serialises every RPC.
    """

    def __init__(self) -> None:
        self._channel: PacketChannel | None = None
        self._lock = asyncio.Lock()
        self._max_msg_size: int = p.PACKET_MAX
        self._reg_size: int | None = None
        self._loaded: LoadedProgram | None = None
        self._endpoint: str | None = None
        self._flat_ds: int | None = None
        self._flat_cs: int | None = None

    @property
    def connected(self) -> bool:
        return self._channel is not None

    @property
    def max_msg_size(self) -> int:
        return self._max_msg_size

    @property
    def reg_size(self) -> int | None:
        return self._reg_size

    @property
    def loaded(self) -> LoadedProgram | None:
        return self._loaded

    @property
    def endpoint(self) -> str | None:
        return self._endpoint

    @property
    def flat_ds(self) -> int | None:
        return self._flat_ds

    @property
    def flat_cs(self) -> int | None:
        return self._flat_cs

    # --- connection lifecycle ------------------------------------------------

    async def connect(
        self,
        host: str,
        port: int = p.DEFAULT_PORT,
        *,
        force: bool = False,
        timeout: float = 10.0,
    ) -> ConnectResult:
        async with self._lock:
            if self._channel is not None:
                if not force:
                    raise AlreadyConnectedError(
                        f"already connected to {self._endpoint}; pass force=True to reconnect"
                    )
                await self._teardown_locked()

            channel = await open_channel(host, port, timeout=timeout)
            try:
                await channel.send_packet(p.pack_connect_req())
                reply = await channel.recv_packet()
            except TransportError:
                await channel.close()
                raise
            server_max, err_msg = p.parse_connect_ret(reply)
            if err_msg:
                await channel.close()
                raise TrapServerError(err_msg)

            self._channel = channel
            self._max_msg_size = min(max(server_max, 1), p.PACKET_MAX)
            self._reg_size = None
            self._loaded = None
            self._flat_ds = None
            self._flat_cs = None
            self._endpoint = f"{host}:{port}"
            return ConnectResult(
                max_msg_size=self._max_msg_size,
                server_reported_max=server_max,
                endpoint=self._endpoint,
            )

    async def disconnect(self) -> None:
        async with self._lock:
            if self._channel is None:
                return
            with contextlib.suppress(TransportError):
                await self._channel.send_packet(p.pack_disconnect_req())
            await self._teardown_locked()

    async def _teardown_locked(self) -> None:
        """Close the channel and clear per-connection state. Caller holds the lock."""
        channel = self._channel
        self._channel = None
        self._reg_size = None
        self._loaded = None
        self._flat_ds = None
        self._flat_cs = None
        self._endpoint = None
        if channel is not None:
            await channel.close()

    # --- RPC gate ------------------------------------------------------------

    async def _rpc(self, payload: bytes, *, expect_reply: bool = True) -> bytes:
        """Send ``payload``, return the reply. Tears down on socket failure."""
        async with self._lock:
            if self._channel is None:
                raise NotConnectedError("no active TRAP connection")
            channel = self._channel
            try:
                await channel.send_packet(payload)
                if not expect_reply:
                    return b""
                return await channel.recv_packet()
            except TransportError:
                await self._teardown_locked()
                raise

    # --- typed request methods ----------------------------------------------

    async def get_sys_config(self) -> SysConfig:
        reply = await self._rpc(p.pack_get_sys_config_req())
        return p.parse_get_sys_config_ret(reply)

    async def get_supplementary_service(self, service: str) -> SupplementaryServiceResult:
        reply = await self._rpc(p.pack_get_supplementary_service_req(service))
        return p.parse_get_supplementary_service_ret(reply)

    async def _resolve_flat_segment(self, segment: int) -> int:
        """Return ``segment`` unchanged unless it's 0 — then return the cached
        flat DS (x86/Win32). Lazy-triggers ``read_regs`` on first use.

        Rationale: ``tcpserv`` on Win32 rejects ``segment=0`` (getRealBase in
        accmem.c expects FlatDS or FlatCS). Callers using the simple "flat
        address" convention must be mapped to the real selector.
        """
        if segment != 0:
            return segment
        if self._flat_ds is None:
            # Populates both _flat_ds and _flat_cs via extract_x86_flat_selectors.
            await self.read_regs()
        return self._flat_ds if self._flat_ds is not None else 0

    def _map_addr_selector(self, segment: int, space: MapAddrSpace) -> int:
        if space == "segmented":
            return segment
        if space == "flat_code":
            return p.MAP_FLAT_CODE_SELECTOR
        if space == "flat_data":
            return p.MAP_FLAT_DATA_SELECTOR
        raise ValueError(
            f"invalid MAP_ADDR space {space!r}; expected segmented, flat_code, or flat_data"
        )

    async def map_addr(
        self,
        offset: int,
        segment: int = 0,
        mod_handle: int = 0,
        *,
        space: MapAddrSpace = "segmented",
    ) -> MapAddrResult:
        req_segment = self._map_addr_selector(segment, space)
        reply = await self._rpc(
            p.pack_map_addr_req(Addr48(offset=offset, segment=req_segment), mod_handle)
        )
        try:
            return p.parse_map_addr_ret(reply)
        except ProtocolError as exc:
            if (
                not reply
                and space == "segmented"
                and segment == 0
                and self._loaded is not None
                and (self._loaded.flags & p.LoadFlag.IGNORE_SEGMENTS)
            ):
                raise ProtocolError(
                    "map_addr_ret: empty reply for segmented address 0 on a flat target; "
                    "use space='flat_code' or space='flat_data'"
                ) from exc
            raise

    async def checksum_mem(self, offset: int, length: int, segment: int = 0) -> int:
        segment = await self._resolve_flat_segment(segment)
        reply = await self._rpc(
            p.pack_checksum_mem_req(Addr48(offset=offset, segment=segment), length)
        )
        return p.parse_checksum_mem_ret(reply)

    async def read_mem(self, offset: int, length: int, segment: int = 0) -> bytes:
        if length < 0:
            raise ValueError("length must be >= 0")
        if length == 0:
            return b""
        segment = await self._resolve_flat_segment(segment)
        buf = bytearray()
        remaining = length
        cursor = offset & 0xFFFFFFFF
        while remaining > 0:
            chunk_len = min(remaining, self._max_msg_size)
            req = p.pack_read_mem_req(Addr48(offset=cursor, segment=segment), chunk_len)
            reply = await self._rpc(req)
            if not reply:
                break
            buf.extend(reply)
            cursor = (cursor + len(reply)) & 0xFFFFFFFF
            remaining -= len(reply)
            if len(reply) < chunk_len:
                # Server returned fewer bytes than requested — trust it and stop.
                break
        return bytes(buf)

    async def write_mem(self, offset: int, data: bytes, segment: int = 0) -> int:
        if not data:
            return 0
        segment = await self._resolve_flat_segment(segment)
        header_size = 1 + 6  # req + addr48
        max_chunk = self._max_msg_size - header_size
        if max_chunk <= 0:
            raise ProtocolError(
                f"negotiated max_msg_size ({self._max_msg_size}) leaves no room for WRITE_MEM"
            )
        written = 0
        cursor = offset & 0xFFFFFFFF
        view = memoryview(data)
        while written < len(data):
            chunk = bytes(view[written : written + max_chunk])
            req = p.pack_write_mem_req(Addr48(offset=cursor, segment=segment), chunk)
            reply = await self._rpc(req)
            acked = p.parse_write_mem_ret(reply)
            if acked == 0:
                break
            written += acked
            cursor = (cursor + acked) & 0xFFFFFFFF
            if acked < len(chunk):
                break
        return written

    async def read_io(self, io_offset: int, length: int) -> bytes:
        reply = await self._rpc(p.pack_read_io_req(io_offset, length))
        return reply

    async def write_io(self, io_offset: int, data: bytes) -> int:
        reply = await self._rpc(p.pack_write_io_req(io_offset, data))
        return p.parse_write_io_ret(reply)

    async def read_regs(self) -> bytes:
        reply = await self._rpc(p.pack_read_regs_req())
        self._reg_size = len(reply)
        sel = p.extract_x86_flat_selectors(reply)
        if sel is not None:
            self._flat_ds, self._flat_cs = sel
        return reply

    async def write_regs(self, data: bytes) -> int:
        if self._reg_size is None:
            raise ProtocolError(
                "call read_regs() first — write_regs requires the register-block size"
            )
        if len(data) != self._reg_size:
            raise ProtocolError(
                f"register block size mismatch: got {len(data)}, expected {self._reg_size}"
            )
        if 1 + len(data) > self._max_msg_size:
            raise ProtocolError(
                f"register block ({len(data)} bytes) exceeds max_msg_size-1 "
                f"({self._max_msg_size - 1})"
            )
        await self._rpc(p.pack_write_regs_req(data))
        return len(data)

    async def set_watch(self, offset: int, size: int, segment: int = 0) -> SetWatchResult:
        segment = await self._resolve_flat_segment(segment)
        reply = await self._rpc(p.pack_set_watch_req(Addr48(offset=offset, segment=segment), size))
        return p.parse_set_watch_ret(reply)

    async def clear_watch(self, offset: int, size: int, segment: int = 0) -> None:
        segment = await self._resolve_flat_segment(segment)
        await self._rpc(p.pack_clear_watch_req(Addr48(offset=offset, segment=segment), size))

    async def set_break(self, offset: int, segment: int = 0) -> int:
        segment = await self._resolve_flat_segment(segment)
        reply = await self._rpc(p.pack_set_break_req(Addr48(offset=offset, segment=segment)))
        return p.parse_set_break_ret(reply)

    async def clear_break(self, offset: int, old: int, segment: int = 0) -> None:
        segment = await self._resolve_flat_segment(segment)
        await self._rpc(p.pack_clear_break_req(Addr48(offset=offset, segment=segment), old))

    async def get_next_alias(self, seg: int) -> AliasResult:
        reply = await self._rpc(p.pack_get_next_alias_req(seg))
        return p.parse_get_next_alias_ret(reply)

    async def set_user_screen(self) -> None:
        await self._rpc(p.pack_set_user_screen_req())

    async def set_debug_screen(self) -> None:
        await self._rpc(p.pack_set_debug_screen_req())

    async def read_user_keyboard(self, wait_ms: int = 0) -> int:
        reply = await self._rpc(p.pack_read_user_keyboard_req(wait_ms))
        return p.parse_read_user_keyboard_ret(reply)

    async def get_lib_name(self, mod_handle: int) -> LibNameResult:
        reply = await self._rpc(p.pack_get_lib_name_req(mod_handle))
        return p.parse_get_lib_name_ret(reply)

    async def redirect_stdin(self, filename: str) -> int:
        reply = await self._rpc(p.pack_redirect_stdin_req(filename))
        return p.parse_redirect_stdio_ret(reply)

    async def redirect_stdout(self, filename: str) -> int:
        reply = await self._rpc(p.pack_redirect_stdout_req(filename))
        return p.parse_redirect_stdio_ret(reply)

    async def split_cmd(self, command: str) -> SplitCmdResult:
        reply = await self._rpc(p.pack_split_cmd_req(command))
        return p.parse_split_cmd_ret(reply)

    async def prog_go(self) -> ProgGoResult:
        reply = await self._rpc(p.pack_prog_go_req())
        return p.parse_prog_go_ret(reply)

    async def prog_step(self) -> ProgGoResult:
        reply = await self._rpc(p.pack_prog_step_req())
        return p.parse_prog_go_ret(reply)

    async def prog_load(
        self,
        program: str,
        args: str = "",
        true_argv: bool = False,
    ) -> ProgLoadResult:
        req = p.pack_prog_load_req(program, args, true_argv=true_argv)
        if len(req) > self._max_msg_size:
            raise ProtocolError(
                f"prog_load payload ({len(req)} bytes) exceeds max_msg_size "
                f"({self._max_msg_size})"
            )
        reply = await self._rpc(req)
        result = p.parse_prog_load_ret(reply)
        # NOTE: we record the loaded program regardless of err — a failed load
        # still reports a task_id in some implementations. Callers branch on err.
        self._loaded = LoadedProgram(
            task_id=result.task_id,
            mod_handle=result.mod_handle,
            flags=result.flags,
            program=program,
        )
        self._flat_ds = None
        self._flat_cs = None
        return result

    async def prog_kill(self, task_id: int | None = None) -> int:
        if task_id is None:
            if self._loaded is None:
                raise ProtocolError(
                    "no loaded program — call prog_load first or pass task_id explicitly"
                )
            task_id = self._loaded.task_id
        reply = await self._rpc(p.pack_prog_kill_req(task_id))
        err = p.parse_prog_kill_ret(reply)
        if err == 0:
            self._loaded = None
        return err

    async def get_err_text(self, error: int) -> str:
        reply = await self._rpc(p.pack_get_err_text_req(error))
        return p.parse_get_err_text_ret(reply)

    async def get_message_text(self) -> MessageText:
        reply = await self._rpc(p.pack_get_message_text_req())
        return p.parse_get_message_text_ret(reply)

    async def machine_data(
        self,
        info_type: int,
        offset: int,
        segment: int = 0,
        extra: bytes = b"",
    ) -> MachineDataResult:
        segment = await self._resolve_flat_segment(segment)
        reply = await self._rpc(
            p.pack_machine_data_req(info_type, Addr48(offset=offset, segment=segment), extra)
        )
        return p.parse_machine_data_ret(reply)
