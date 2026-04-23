"""Stateful asyncio client for the OpenWatcom TRAP protocol."""

from __future__ import annotations

import asyncio
import contextlib
import struct
from collections.abc import Sequence
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
    ExactBreakpointSupport,
    FileComponents,
    FileDateResult,
    FileOpenResult,
    FileReadResult,
    FileSeekResult,
    FileWriteResult,
    LibNameResult,
    MachineDataResult,
    MapAddrResult,
    MessageText,
    OvlAddress,
    OvlGetDataResult,
    OvlRemapEntryResult,
    ProgGoResult,
    ProgLoadResult,
    RfxFindReply,
    RfxFindResult,
    RunThreadGetNextResult,
    RunThreadInfoResult,
    RunThreadRuntimeResult,
    RunThreadSetResult,
    SetWatchResult,
    SplitCmdResult,
    StringResult,
    SupplementaryServiceResult,
    SysConfig,
    ThreadGetNextResult,
    ThreadSetResult,
)
from .wire import PacketChannel, open_channel

MapAddrSpace = str
_DEFAULT_RECV_TIMEOUT = object()
_DISCONNECT_CLOSE_WAIT = 0.25


def _latin1z(text: str) -> bytes:
    return text.encode("latin-1", errors="replace") + b"\x00"


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

    def __init__(self, recv_timeout: float | None = 5.0) -> None:
        if recv_timeout is not None and recv_timeout <= 0:
            raise ValueError("recv_timeout must be > 0 or None")
        self._channel: PacketChannel | None = None
        self._lock = asyncio.Lock()
        self._max_msg_size: int = p.PACKET_MAX
        self._reg_size: int | None = None
        self._loaded: LoadedProgram | None = None
        self._endpoint: str | None = None
        self._flat_ds: int | None = None
        self._flat_cs: int | None = None
        self._supp_handles: dict[str, int] = {}
        self._recv_timeout = recv_timeout

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
    def recv_timeout(self) -> float | None:
        return self._recv_timeout

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
            self._supp_handles = {}
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
            channel = self._channel
            sent_disconnect = False
            with contextlib.suppress(TransportError):
                await channel.send_packet(p.pack_disconnect_req())
                sent_disconnect = True
            if sent_disconnect:
                with contextlib.suppress(TransportError):
                    if await channel.wait_peer_close(_DISCONNECT_CLOSE_WAIT):
                        await self._teardown_locked()
                        return
            await self._teardown_locked(abortive=True)

    async def _teardown_locked(self, *, abortive: bool = False) -> None:
        """Close the channel and clear per-connection state. Caller holds the lock."""
        channel = self._channel
        self._channel = None
        self._reg_size = None
        self._loaded = None
        self._flat_ds = None
        self._flat_cs = None
        self._supp_handles = {}
        self._endpoint = None
        if channel is not None:
            await channel.close(abortive=abortive)

    # --- RPC gate ------------------------------------------------------------

    async def _rpc(
        self,
        payload: bytes,
        *,
        expect_reply: bool = True,
        recv_timeout: float | None | object = _DEFAULT_RECV_TIMEOUT,
    ) -> bytes:
        """Send ``payload``, return the reply. Tears down on socket failure."""
        async with self._lock:
            if self._channel is None:
                raise NotConnectedError("no active TRAP connection")
            channel = self._channel
            if recv_timeout is _DEFAULT_RECV_TIMEOUT:
                recv_timeout = self._recv_timeout
            try:
                await channel.send_packet(payload)
                if not expect_reply:
                    return b""
                return await channel.recv_packet(timeout=recv_timeout)
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

    def _supp_label(self, service: str, request: str) -> str:
        return f"{service}.{request}"

    def _raise_supp_err(self, label: str, err: int) -> None:
        if err != 0:
            raise TrapServerError(f"{label} failed with trap error 0x{err:08x}", trap_err_code=err)

    async def _supp_handle(self, service: str) -> int:
        cached = self._supp_handles.get(service)
        if cached is not None:
            return cached
        result = await self.get_supplementary_service(service)
        self._raise_supp_err(service, result.err)
        self._supp_handles[service] = result.shandle
        return result.shandle

    async def _supp_rpc(
        self,
        service: str,
        req: int,
        body: bytes = b"",
        *,
        recv_timeout: float | None | object = _DEFAULT_RECV_TIMEOUT,
    ) -> bytes:
        shandle = await self._supp_handle(service)
        return await self._rpc(
            p.pack_supplementary_req(shandle, req, body),
            recv_timeout=recv_timeout,
        )

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

    async def prog_go(self, timeout: float | None = None) -> ProgGoResult:
        if timeout is not None and timeout <= 0:
            raise ValueError("timeout must be > 0 or None")
        reply = await self._rpc(p.pack_prog_go_req(), recv_timeout=timeout)
        return p.parse_prog_go_ret(reply)

    async def prog_step(self) -> ProgGoResult:
        reply = await self._rpc(p.pack_prog_step_req(), recv_timeout=None)
        return p.parse_prog_go_ret(reply)

    async def prog_load(
        self,
        argv: Sequence[str],
        true_argv: bool = False,
    ) -> ProgLoadResult:
        argv_items = p.normalize_prog_load_argv(argv)
        req = p.pack_prog_load_req(argv_items, true_argv=true_argv)
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
            program=argv_items[0],
        )
        self._flat_ds = None
        self._flat_cs = None
        return result

    async def prog_attach(self, pid: int, hex_format: bool = True) -> ProgLoadResult:
        if pid < 0:
            raise ValueError("pid must be >= 0")
        token = f"#{pid:X}" if hex_format else f"#{pid}"
        return await self.prog_load([token])

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

    async def file_get_config(self) -> FileComponents:
        reply = await self._supp_rpc(p.SUPP_FILES, p.FileReq.GET_CONFIG)
        return p.parse_file_get_config_ret(reply)

    async def file_open(self, mode: int, name: str) -> FileOpenResult:
        body = struct.pack("<B", mode & 0xFF) + _latin1z(name)
        reply = await self._supp_rpc(p.SUPP_FILES, p.FileReq.OPEN, body)
        result = p.parse_file_open_ret(reply)
        self._raise_supp_err(self._supp_label(p.SUPP_FILES, "open"), result.err)
        return result

    async def file_seek(self, handle: int, mode: int, pos: int) -> FileSeekResult:
        reply = await self._supp_rpc(
            p.SUPP_FILES,
            p.FileReq.SEEK,
            struct.pack("<QBI", handle & 0xFFFFFFFFFFFFFFFF, mode & 0xFF, pos & 0xFFFFFFFF),
        )
        result = p.parse_file_seek_ret(reply)
        self._raise_supp_err(self._supp_label(p.SUPP_FILES, "seek"), result.err)
        return result

    async def file_read(self, handle: int, length: int) -> FileReadResult:
        reply = await self._supp_rpc(
            p.SUPP_FILES,
            p.FileReq.READ,
            struct.pack("<QH", handle & 0xFFFFFFFFFFFFFFFF, length & 0xFFFF),
        )
        result = p.parse_file_read_ret(reply)
        self._raise_supp_err(self._supp_label(p.SUPP_FILES, "read"), result.err)
        return result

    async def file_write(self, handle: int, data: bytes) -> FileWriteResult:
        reply = await self._supp_rpc(
            p.SUPP_FILES,
            p.FileReq.WRITE,
            struct.pack("<Q", handle & 0xFFFFFFFFFFFFFFFF) + data,
        )
        result = p.parse_file_write_ret(reply)
        self._raise_supp_err(self._supp_label(p.SUPP_FILES, "write"), result.err)
        return result

    async def file_write_console(self, data: bytes) -> FileWriteResult:
        reply = await self._supp_rpc(p.SUPP_FILES, p.FileReq.WRITE_CONSOLE, data)
        result = p.parse_file_write_console_ret(reply)
        self._raise_supp_err(self._supp_label(p.SUPP_FILES, "write_console"), result.err)
        return result

    async def file_close(self, handle: int) -> None:
        reply = await self._supp_rpc(
            p.SUPP_FILES, p.FileReq.CLOSE, struct.pack("<Q", handle & 0xFFFFFFFFFFFFFFFF)
        )
        self._raise_supp_err(self._supp_label(p.SUPP_FILES, "close"), p.parse_file_close_ret(reply))

    async def file_erase(self, name: str) -> None:
        reply = await self._supp_rpc(p.SUPP_FILES, p.FileReq.ERASE, _latin1z(name))
        self._raise_supp_err(
            self._supp_label(p.SUPP_FILES, "erase"),
            p.parse_file_erase_ret(reply),
        )

    async def file_string_to_fullpath(self, file_type: int, name: str) -> StringResult:
        body = struct.pack("<B", file_type & 0xFF) + _latin1z(name)
        reply = await self._supp_rpc(
            p.SUPP_FILES,
            p.FileReq.STRING_TO_FULLPATH,
            body,
        )
        result = p.parse_file_string_to_fullpath_ret(reply)
        self._raise_supp_err(self._supp_label(p.SUPP_FILES, "string_to_fullpath"), result.err)
        return result

    async def file_run_cmd(self, chk_size: int, command: str) -> None:
        body = struct.pack("<H", chk_size & 0xFFFF) + _latin1z(command)
        reply = await self._supp_rpc(
            p.SUPP_FILES,
            p.FileReq.RUN_CMD,
            body,
        )
        self._raise_supp_err(
            self._supp_label(p.SUPP_FILES, "run_cmd"),
            p.parse_file_run_cmd_ret(reply),
        )

    async def file_info_get_date(self, name: str) -> FileDateResult:
        reply = await self._supp_rpc(p.SUPP_FILE_INFO, p.FileInfoReq.GET_DATE, _latin1z(name))
        result = p.parse_file_info_get_date_ret(reply)
        self._raise_supp_err(self._supp_label(p.SUPP_FILE_INFO, "get_date"), result.err)
        return result

    async def file_info_set_date(self, date: int, name: str) -> None:
        body = struct.pack("<i", date) + _latin1z(name)
        reply = await self._supp_rpc(
            p.SUPP_FILE_INFO,
            p.FileInfoReq.SET_DATE,
            body,
        )
        self._raise_supp_err(
            self._supp_label(p.SUPP_FILE_INFO, "set_date"),
            p.parse_file_info_set_date_ret(reply),
        )

    async def env_get_var(self, res_len: int, name: str) -> StringResult:
        body = struct.pack("<I", res_len & 0xFFFFFFFF) + _latin1z(name)
        reply = await self._supp_rpc(
            p.SUPP_ENVIRONMENT,
            p.EnvReq.GET_VAR,
            body,
        )
        result = p.parse_env_get_var_ret(reply)
        self._raise_supp_err(self._supp_label(p.SUPP_ENVIRONMENT, "get_var"), result.err)
        return result

    async def env_set_var(self, name: str, value: str) -> None:
        body = _latin1z(name) + _latin1z(value)
        reply = await self._supp_rpc(
            p.SUPP_ENVIRONMENT,
            p.EnvReq.SET_VAR,
            body,
        )
        self._raise_supp_err(
            self._supp_label(p.SUPP_ENVIRONMENT, "set_var"),
            p.parse_env_set_var_ret(reply),
        )

    async def ovl_state_size(self) -> int:
        reply = await self._supp_rpc(p.SUPP_OVERLAYS, p.OvlReq.STATE_SIZE)
        return p.parse_ovl_state_size_ret(reply)

    async def ovl_get_data(self, sect_id: int) -> OvlGetDataResult:
        reply = await self._supp_rpc(
            p.SUPP_OVERLAYS, p.OvlReq.GET_DATA, struct.pack("<H", sect_id & 0xFFFF)
        )
        return p.parse_ovl_get_data_ret(reply)

    async def ovl_read_state(self) -> bytes:
        reply = await self._supp_rpc(p.SUPP_OVERLAYS, p.OvlReq.READ_STATE)
        return reply

    async def ovl_write_state(self, data: bytes) -> None:
        await self._supp_rpc(p.SUPP_OVERLAYS, p.OvlReq.WRITE_STATE, data)

    async def ovl_trans_vect_addr(self, ovl_addr: OvlAddress) -> OvlAddress:
        reply = await self._supp_rpc(p.SUPP_OVERLAYS, p.OvlReq.TRANS_VECT_ADDR, ovl_addr.pack())
        return p.parse_ovl_trans_addr_ret(reply)

    async def ovl_trans_ret_addr(self, ovl_addr: OvlAddress) -> OvlAddress:
        reply = await self._supp_rpc(p.SUPP_OVERLAYS, p.OvlReq.TRANS_RET_ADDR, ovl_addr.pack())
        return p.parse_ovl_trans_addr_ret(reply)

    async def ovl_get_remap_entry(self, ovl_addr: OvlAddress) -> OvlRemapEntryResult:
        reply = await self._supp_rpc(p.SUPP_OVERLAYS, p.OvlReq.GET_REMAP_ENTRY, ovl_addr.pack())
        return p.parse_ovl_get_remap_entry_ret(reply)

    async def thread_get_next(self, thread: int) -> ThreadGetNextResult:
        reply = await self._supp_rpc(
            p.SUPP_THREADS, p.ThreadReq.GET_NEXT, struct.pack("<I", thread & 0xFFFFFFFF)
        )
        return p.parse_thread_get_next_ret(reply)

    async def thread_set(self, thread: int) -> ThreadSetResult:
        reply = await self._supp_rpc(
            p.SUPP_THREADS, p.ThreadReq.SET, struct.pack("<I", thread & 0xFFFFFFFF)
        )
        result = p.parse_thread_set_ret(reply)
        self._raise_supp_err(self._supp_label(p.SUPP_THREADS, "set"), result.err)
        return result

    async def thread_freeze(self, thread: int) -> None:
        reply = await self._supp_rpc(
            p.SUPP_THREADS, p.ThreadReq.FREEZE, struct.pack("<I", thread & 0xFFFFFFFF)
        )
        self._raise_supp_err(
            self._supp_label(p.SUPP_THREADS, "freeze"),
            p.parse_thread_freeze_ret(reply),
        )

    async def thread_thaw(self, thread: int) -> None:
        reply = await self._supp_rpc(
            p.SUPP_THREADS, p.ThreadReq.THAW, struct.pack("<I", thread & 0xFFFFFFFF)
        )
        self._raise_supp_err(
            self._supp_label(p.SUPP_THREADS, "thaw"),
            p.parse_thread_thaw_ret(reply),
        )

    async def thread_get_extra(self, thread: int) -> str:
        reply = await self._supp_rpc(
            p.SUPP_THREADS, p.ThreadReq.GET_EXTRA, struct.pack("<I", thread & 0xFFFFFFFF)
        )
        return p.parse_thread_get_extra_ret(reply)

    async def run_thread_info(self, col: int) -> RunThreadInfoResult:
        reply = await self._supp_rpc(
            p.SUPP_RUN_THREAD, p.RunThreadReq.INFO, struct.pack("<H", col & 0xFFFF)
        )
        return p.parse_run_thread_info_ret(reply)

    async def run_thread_get_next(self, thread: int) -> RunThreadGetNextResult:
        reply = await self._supp_rpc(
            p.SUPP_RUN_THREAD, p.RunThreadReq.GET_NEXT, struct.pack("<I", thread & 0xFFFFFFFF)
        )
        return p.parse_run_thread_get_next_ret(reply)

    async def run_thread_get_runtime(self, thread: int) -> RunThreadRuntimeResult:
        reply = await self._supp_rpc(
            p.SUPP_RUN_THREAD, p.RunThreadReq.GET_RUNTIME, struct.pack("<I", thread & 0xFFFFFFFF)
        )
        return p.parse_run_thread_get_runtime_ret(reply)

    async def run_thread_poll(self) -> int:
        reply = await self._supp_rpc(p.SUPP_RUN_THREAD, p.RunThreadReq.POLL)
        return p.parse_run_thread_poll_ret(reply)

    async def run_thread_set(self, thread: int) -> RunThreadSetResult:
        reply = await self._supp_rpc(
            p.SUPP_RUN_THREAD, p.RunThreadReq.SET, struct.pack("<I", thread & 0xFFFFFFFF)
        )
        result = p.parse_run_thread_set_ret(reply)
        self._raise_supp_err(self._supp_label(p.SUPP_RUN_THREAD, "set"), result.err)
        return result

    async def run_thread_get_name(self, thread: int) -> str:
        reply = await self._supp_rpc(
            p.SUPP_RUN_THREAD, p.RunThreadReq.GET_NAME, struct.pack("<I", thread & 0xFFFFFFFF)
        )
        return p.parse_run_thread_get_name_ret(reply)

    async def run_thread_stop(self, thread: int) -> None:
        await self._supp_rpc(
            p.SUPP_RUN_THREAD, p.RunThreadReq.STOP, struct.pack("<I", thread & 0xFFFFFFFF)
        )

    async def run_thread_signal_stop(self, thread: int) -> None:
        await self._supp_rpc(
            p.SUPP_RUN_THREAD, p.RunThreadReq.SIGNAL_STOP, struct.pack("<I", thread & 0xFFFFFFFF)
        )

    async def rfx_rename(self, old_name: str, new_name: str) -> None:
        body = _latin1z(old_name) + _latin1z(new_name)
        reply = await self._supp_rpc(
            p.SUPP_RFX,
            p.RfxReq.RENAME,
            body,
        )
        self._raise_supp_err(
            self._supp_label(p.SUPP_RFX, "rename"),
            p.parse_rfx_rename_ret(reply),
        )

    async def rfx_mkdir(self, dirname: str) -> None:
        reply = await self._supp_rpc(p.SUPP_RFX, p.RfxReq.MKDIR, _latin1z(dirname))
        self._raise_supp_err(self._supp_label(p.SUPP_RFX, "mkdir"), p.parse_rfx_mkdir_ret(reply))

    async def rfx_rmdir(self, dirname: str) -> None:
        reply = await self._supp_rpc(p.SUPP_RFX, p.RfxReq.RMDIR, _latin1z(dirname))
        self._raise_supp_err(self._supp_label(p.SUPP_RFX, "rmdir"), p.parse_rfx_rmdir_ret(reply))

    async def rfx_setdrive(self, drive: int) -> None:
        reply = await self._supp_rpc(
            p.SUPP_RFX, p.RfxReq.SETDRIVE, struct.pack("<B", drive & 0xFF)
        )
        self._raise_supp_err(
            self._supp_label(p.SUPP_RFX, "setdrive"),
            p.parse_rfx_setdrive_ret(reply),
        )

    async def rfx_getdrive(self) -> int:
        reply = await self._supp_rpc(p.SUPP_RFX, p.RfxReq.GETDRIVE)
        return p.parse_rfx_getdrive_ret(reply)

    async def rfx_setcwd(self, cwd: str) -> None:
        reply = await self._supp_rpc(p.SUPP_RFX, p.RfxReq.SETCWD, _latin1z(cwd))
        self._raise_supp_err(self._supp_label(p.SUPP_RFX, "setcwd"), p.parse_rfx_setcwd_ret(reply))

    async def rfx_getcwd(self, drive: int) -> StringResult:
        reply = await self._supp_rpc(p.SUPP_RFX, p.RfxReq.GETCWD, struct.pack("<B", drive & 0xFF))
        result = p.parse_rfx_getcwd_ret(reply)
        self._raise_supp_err(self._supp_label(p.SUPP_RFX, "getcwd"), result.err)
        return result

    async def rfx_setdatetime(self, handle: int, time: int) -> None:
        reply = await self._supp_rpc(
            p.SUPP_RFX,
            p.RfxReq.SETDATETIME,
            struct.pack("<QI", handle & 0xFFFFFFFFFFFFFFFF, time & 0xFFFFFFFF),
        )
        if reply:
            self._raise_supp_err(
                self._supp_label(p.SUPP_RFX, "setdatetime"),
                p.parse_trap_error_ret(reply, "rfx_setdatetime_ret"),
            )

    async def rfx_getdatetime(self, handle: int) -> int:
        reply = await self._supp_rpc(
            p.SUPP_RFX, p.RfxReq.GETDATETIME, struct.pack("<Q", handle & 0xFFFFFFFFFFFFFFFF)
        )
        return p.parse_rfx_getdatetime_ret(reply)

    async def rfx_getfreespace(self, drive: int) -> int:
        reply = await self._supp_rpc(
            p.SUPP_RFX, p.RfxReq.GETFREESPACE, struct.pack("<B", drive & 0xFF)
        )
        return p.parse_rfx_getfreespace_ret(reply)

    async def rfx_setfileattr(self, attribute: int, name: str) -> None:
        body = struct.pack("<I", attribute & 0xFFFFFFFF) + _latin1z(name)
        reply = await self._supp_rpc(
            p.SUPP_RFX,
            p.RfxReq.SETFILEATTR,
            body,
        )
        self._raise_supp_err(
            self._supp_label(p.SUPP_RFX, "setfileattr"),
            p.parse_rfx_setfileattr_ret(reply),
        )

    async def rfx_getfileattr(self, name: str) -> int:
        reply = await self._supp_rpc(p.SUPP_RFX, p.RfxReq.GETFILEATTR, _latin1z(name))
        return p.parse_rfx_getfileattr_ret(reply)

    async def rfx_nametocanonical(self, name: str) -> StringResult:
        reply = await self._supp_rpc(p.SUPP_RFX, p.RfxReq.NAMETOCANONICAL, _latin1z(name))
        result = p.parse_rfx_nametocanonical_ret(reply)
        self._raise_supp_err(self._supp_label(p.SUPP_RFX, "nametocanonical"), result.err)
        return result

    async def rfx_findfirst(self, attrib: int, pattern: str) -> RfxFindReply:
        body = struct.pack("<B", attrib & 0xFF) + _latin1z(pattern)
        reply = await self._supp_rpc(
            p.SUPP_RFX,
            p.RfxReq.FINDFIRST,
            body,
        )
        return p.parse_rfx_findfirst_ret(reply)

    async def rfx_findnext(self, info: RfxFindResult) -> RfxFindReply:
        reply = await self._supp_rpc(p.SUPP_RFX, p.RfxReq.FINDNEXT, info.pack())
        return p.parse_rfx_findnext_ret(reply)

    async def rfx_findclose(self, info: RfxFindResult) -> None:
        reply = await self._supp_rpc(p.SUPP_RFX, p.RfxReq.FINDCLOSE, info.pack())
        self._raise_supp_err(
            self._supp_label(p.SUPP_RFX, "findclose"),
            p.parse_rfx_findclose_ret(reply),
        )

    async def capabilities_get_exact_bp(self) -> ExactBreakpointSupport:
        reply = await self._supp_rpc(p.SUPP_CAPABILITIES, p.CapabilitiesReq.GET_EXACT_BP)
        result = p.parse_capabilities_get_exact_bp_ret(reply)
        self._raise_supp_err(self._supp_label(p.SUPP_CAPABILITIES, "get_exact_bp"), result.err)
        return result

    async def capabilities_set_exact_bp(self, status: int) -> ExactBreakpointSupport:
        reply = await self._supp_rpc(
            p.SUPP_CAPABILITIES, p.CapabilitiesReq.SET_EXACT_BP, struct.pack("<B", status & 0xFF)
        )
        result = p.parse_capabilities_set_exact_bp_ret(reply)
        self._raise_supp_err(self._supp_label(p.SUPP_CAPABILITIES, "set_exact_bp"), result.err)
        return result

    async def async_go(self) -> ProgGoResult:
        reply = await self._supp_rpc(p.SUPP_ASYNCH, p.AsyncReq.GO, recv_timeout=None)
        return p.parse_async_ret(reply)

    async def async_step(self) -> ProgGoResult:
        reply = await self._supp_rpc(p.SUPP_ASYNCH, p.AsyncReq.STEP, recv_timeout=None)
        return p.parse_async_ret(reply)

    async def async_poll(self) -> ProgGoResult:
        reply = await self._supp_rpc(p.SUPP_ASYNCH, p.AsyncReq.POLL)
        return p.parse_async_ret(reply)

    async def async_stop(self) -> ProgGoResult:
        reply = await self._supp_rpc(p.SUPP_ASYNCH, p.AsyncReq.STOP)
        return p.parse_async_ret(reply)

    async def async_add_break(self, offset: int, segment: int = 0, *, local: bool = False) -> None:
        segment = await self._resolve_flat_segment(segment)
        await self._supp_rpc(
            p.SUPP_ASYNCH,
            p.AsyncReq.ADD_BREAK,
            Addr48(offset=offset, segment=segment).pack() + struct.pack("<B", 1 if local else 0),
        )

    async def async_remove_break(
        self, offset: int, segment: int = 0, *, local: bool = False
    ) -> None:
        segment = await self._resolve_flat_segment(segment)
        await self._supp_rpc(
            p.SUPP_ASYNCH,
            p.AsyncReq.REMOVE_BREAK,
            Addr48(offset=offset, segment=segment).pack() + struct.pack("<B", 1 if local else 0),
        )
