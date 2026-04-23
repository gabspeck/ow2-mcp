"""FastMCP server exposing the core TRAP tools over stdio."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from . import protocol as p
from .client import TrapClient, send_interrupt
from .errors import (
    AlreadyConnectedError,
    NotConnectedError,
    ProtocolError,
    TransportError,
    TrapError,
    TrapServerError,
)

mcp: FastMCP = FastMCP("ow2-mcp")
_client = TrapClient()


def _err(exc: TrapError) -> dict[str, Any]:
    """Translate a :class:`TrapError` into the uniform ``{ok: false, ...}`` shape."""
    if isinstance(exc, TransportError):
        code = "transport_error"
    elif isinstance(exc, ProtocolError):
        code = "protocol_error"
    elif isinstance(exc, NotConnectedError):
        code = "not_connected"
    elif isinstance(exc, AlreadyConnectedError):
        code = "already_connected"
    elif isinstance(exc, TrapServerError):
        code = "trap_error"
    else:
        code = "trap_error"
    error: dict[str, Any] = {"code": code, "message": str(exc)}
    if isinstance(exc, TrapServerError) and exc.trap_err_code is not None:
        error["trap_err_code"] = exc.trap_err_code
    return {"ok": False, "error": error}


def _value_err(exc: ValueError) -> dict[str, Any]:
    return {"ok": False, "error": {"code": "protocol_error", "message": str(exc)}}


def _parse_attach_pid(pid: int | str) -> int:
    if isinstance(pid, int):
        value = pid
    elif isinstance(pid, str):
        text = pid.strip()
        if not text:
            raise ValueError("pid must not be empty")
        if text.startswith("#"):
            text = text[1:]
            if not text:
                raise ValueError("pid must include digits after '#'")
            base = 16
        elif text.lower().startswith("0x"):
            text = text[2:]
            if not text:
                raise ValueError("pid must include digits after '0x'")
            base = 16
        elif any(ch in "abcdefABCDEF" for ch in text):
            base = 16
        else:
            base = 10
        try:
            value = int(text, base)
        except ValueError as exc:
            raise ValueError(f"invalid pid: {pid!r}") from exc
    else:
        raise ValueError("pid must be an integer or string")
    if value < 0:
        raise ValueError("pid must be >= 0")
    return value


def _unhex(text: str) -> bytes:
    """Parse a hex string tolerantly: accepts ``0x`` prefix, whitespace, underscores."""
    cleaned = text.strip()
    if cleaned.startswith(("0x", "0X")):
        cleaned = cleaned[2:]
    cleaned = cleaned.replace(" ", "").replace("\t", "").replace("_", "").replace("\n", "")
    if len(cleaned) % 2 != 0:
        raise ValueError(f"hex string has odd number of nibbles: {len(cleaned)}")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"invalid hex: {exc}") from exc


def _addr48(addr: p.Addr48) -> dict[str, int]:
    return {"segment": addr.segment, "offset": addr.offset}


def _ovl_addr(addr: p.OvlAddress) -> dict[str, Any]:
    return {"mach": _addr48(addr.mach), "sect_id": addr.sect_id}


def _rfx_find(info: p.RfxFindResult | None) -> dict[str, Any] | None:
    if info is None:
        return None
    return {
        "reserved": info.reserved.hex(),
        "attr": info.attr,
        "time": info.time,
        "date": info.date,
        "size": info.size,
        "name": info.name,
    }


@mcp.tool()
async def trap_connect(
    host: str, port: int = p.DEFAULT_PORT, force: bool = False
) -> dict[str, Any]:
    """Open a TCP connection to a running ``tcpserv`` and perform the TRAP handshake.

    Pass ``force=True`` to tear down an existing connection and reconnect.
    Returns the negotiated ``max_msg_size`` (clamped to 1024) and the raw
    ``server_reported_max``.
    """
    try:
        result = await _client.connect(host, port, force=force)
    except TrapError as exc:
        return _err(exc)
    return {
        "ok": True,
        "max_msg_size": result.max_msg_size,
        "server_reported_max": result.server_reported_max,
        "endpoint": result.endpoint,
    }


@mcp.tool()
async def trap_disconnect() -> dict[str, Any]:
    """Send REQ_DISCONNECT (best-effort) and close the TCP socket."""
    try:
        await _client.disconnect()
    except TrapError as exc:
        return _err(exc)
    return {"ok": True}


@mcp.tool()
async def trap_suspend(host: str, port: int = p.DEFAULT_PORT) -> dict[str, Any]:
    """Sends REQ_SUSPEND on a fresh TCP connection.

    The server closes its current session on receipt, so any in-flight
    ``trap_prog_go`` will raise ``TransportError`` and the MCP side must call
    ``trap_connect(force=True)`` before issuing more stateful requests.
    """
    try:
        await send_interrupt(host, port, resume=False)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True}


@mcp.tool()
async def trap_resume(host: str, port: int = p.DEFAULT_PORT) -> dict[str, Any]:
    """Sends REQ_RESUME on a fresh TCP connection to continue a suspended session."""
    try:
        await send_interrupt(host, port, resume=True)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True}


@mcp.tool()
async def trap_get_sys_config() -> dict[str, Any]:
    """Query the debug server's target machine description."""
    try:
        cfg = await _client.get_sys_config()
    except TrapError as exc:
        return _err(exc)
    return {
        "ok": True,
        "cpu": cfg.cpu,
        "fpu": cfg.fpu,
        "os": p.os_name(cfg.os),
        "os_code": cfg.os,
        "os_major": cfg.os_major,
        "os_minor": cfg.os_minor,
        "arch": p.arch_name(cfg.arch),
        "arch_code": cfg.arch,
        "huge_shift": cfg.huge_shift,
    }


@mcp.tool()
async def trap_get_supplementary_service(service: str) -> dict[str, Any]:
    """Resolve a supplementary-service name to its server handle."""
    try:
        result = await _client.get_supplementary_service(service)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "err": result.err, "shandle": result.shandle}


@mcp.tool()
async def trap_map_addr(
    offset: int,
    segment: int = 0,
    mod_handle: int = 0,
    space: str = "segmented",
) -> dict[str, Any]:
    """Map an address through the server's loader relocation tables.

    Use ``space='segmented'`` for literal ``segment:offset`` input.
    Use ``space='flat_code'`` or ``space='flat_data'`` for flat Win32
    addresses; those map to Open Watcom's special flat selectors.
    """
    try:
        result = await _client.map_addr(offset, segment, mod_handle=mod_handle, space=space)
    except ValueError as exc:
        return {"ok": False, "error": {"code": "protocol_error", "message": str(exc)}}
    except TrapError as exc:
        return _err(exc)
    return {
        "ok": True,
        "out_addr": {"segment": result.out_addr.segment, "offset": result.out_addr.offset},
        "lo_bound": result.lo_bound,
        "hi_bound": result.hi_bound,
        "space": space,
    }


@mcp.tool()
async def trap_checksum_mem(offset: int, length: int, segment: int = 0) -> dict[str, Any]:
    """Checksum ``length`` bytes starting at ``segment:offset``.

    On Win32/x86, ``segment=0`` means "flat mode" and is substituted with the
    live DS selector before the request is sent.
    """
    try:
        checksum = await _client.checksum_mem(offset, length, segment=segment)
    except TrapError as exc:
        return _err(exc)
    return {
        "ok": True,
        "checksum": checksum,
        "checksum_hex": f"0x{checksum:08x}",
        "flat_segment_used": _client.flat_ds if segment == 0 else segment,
    }


@mcp.tool()
async def trap_read_mem(offset: int, length: int, segment: int = 0) -> dict[str, Any]:
    """Read ``length`` bytes from the target starting at ``segment:offset``.

    Automatically splits reads larger than the negotiated ``max_msg_size``.
    Returns lowercase hex in ``data``. On Win32/x86, ``segment=0`` means
    "flat mode" — it is substituted with the live DS selector.
    """
    try:
        data = await _client.read_mem(offset, length, segment=segment)
    except TrapError as exc:
        return _err(exc)
    return {
        "ok": True,
        "data": data.hex(),
        "read_length": len(data),
        "flat_segment_used": _client.flat_ds if segment == 0 else segment,
    }


@mcp.tool()
async def trap_write_mem(offset: int, data: str, segment: int = 0) -> dict[str, Any]:
    """Write hex-encoded ``data`` to ``segment:offset``.

    ``data`` accepts an optional ``0x`` prefix and whitespace/underscore separators.
    Large writes are split automatically. On Win32/x86, ``segment=0`` means
    "flat mode" — it is substituted with the live DS selector.
    """
    try:
        raw = _unhex(data)
        written = await _client.write_mem(offset, raw, segment=segment)
    except ValueError as exc:
        return {"ok": False, "error": {"code": "protocol_error", "message": str(exc)}}
    except TrapError as exc:
        return _err(exc)
    return {
        "ok": True,
        "written": written,
        "requested": len(raw),
        "flat_segment_used": _client.flat_ds if segment == 0 else segment,
    }


@mcp.tool()
async def trap_read_io(io_offset: int, length: int) -> dict[str, Any]:
    """Read up to 255 bytes from an I/O port or bus offset.

    The request length is a u8 on the wire, so values above 255 are rejected.
    Typical use is x86 port I/O.
    """
    try:
        data = await _client.read_io(io_offset, length)
    except ValueError as exc:
        return {"ok": False, "error": {"code": "protocol_error", "message": str(exc)}}
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "data": data.hex(), "read_length": len(data)}


@mcp.tool()
async def trap_write_io(io_offset: int, data: str) -> dict[str, Any]:
    """Write hex-encoded bytes to an I/O port or bus offset.

    ``data`` accepts ``0x`` prefixes and whitespace/underscore separators. The
    payload length is limited to 255 bytes by the TRAP wire format.
    """
    try:
        raw = _unhex(data)
        written = await _client.write_io(io_offset, raw)
    except ValueError as exc:
        return {"ok": False, "error": {"code": "protocol_error", "message": str(exc)}}
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "written": written, "requested": len(raw)}


@mcp.tool()
async def trap_read_regs() -> dict[str, Any]:
    """Read the full register block. The size is target-specific and used to
    validate subsequent :func:`trap_write_regs` calls."""
    try:
        regs = await _client.read_regs()
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "hex": regs.hex(), "length": len(regs)}


@mcp.tool()
async def trap_write_regs(data: str) -> dict[str, Any]:
    """Write a full register block. You MUST call :func:`trap_read_regs` first:
    the block size is learned from that reply, and this call is rejected if
    ``data`` does not match that size exactly."""
    try:
        raw = _unhex(data)
        written = await _client.write_regs(raw)
    except ValueError as exc:
        return {"ok": False, "error": {"code": "protocol_error", "message": str(exc)}}
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "written": written}


@mcp.tool()
async def trap_set_watch(offset: int, size: int, segment: int = 0) -> dict[str, Any]:
    """Set a watchpoint of size 1, 2, or 4 bytes at ``segment:offset``.

    On Win32/x86, ``segment=0`` means "flat mode" and is substituted with the
    live DS selector before the request is sent.
    """
    try:
        result = await _client.set_watch(offset, size, segment=segment)
    except ValueError as exc:
        return {"ok": False, "error": {"code": "protocol_error", "message": str(exc)}}
    except TrapError as exc:
        return _err(exc)
    return {
        "ok": True,
        "err": result.err,
        "multiplier": result.multiplier,
        "flat_segment_used": _client.flat_ds if segment == 0 else segment,
    }


@mcp.tool()
async def trap_clear_watch(offset: int, size: int, segment: int = 0) -> dict[str, Any]:
    """Clear a watchpoint of size 1, 2, or 4 bytes at ``segment:offset``."""
    try:
        await _client.clear_watch(offset, size, segment=segment)
    except ValueError as exc:
        return {"ok": False, "error": {"code": "protocol_error", "message": str(exc)}}
    except TrapError as exc:
        return _err(exc)
    return {
        "ok": True,
        "flat_segment_used": _client.flat_ds if segment == 0 else segment,
    }


@mcp.tool()
async def trap_set_break(offset: int, segment: int = 0) -> dict[str, Any]:
    """Set a breakpoint at ``segment:offset``.

    Returns the server-supplied ``old`` value (u32) — forward it verbatim to
    :func:`trap_clear_break` to remove the breakpoint. On Win32/x86,
    ``segment=0`` means "flat mode" — it is substituted with the live DS selector.
    """
    try:
        old = await _client.set_break(offset, segment=segment)
    except TrapError as exc:
        return _err(exc)
    return {
        "ok": True,
        "old": old,
        "old_hex": f"0x{old:08x}",
        "flat_segment_used": _client.flat_ds if segment == 0 else segment,
    }


@mcp.tool()
async def trap_clear_break(offset: int, old: int, segment: int = 0) -> dict[str, Any]:
    """Clear the breakpoint at ``segment:offset`` using the ``old`` value
    returned by the matching :func:`trap_set_break`. On Win32/x86, ``segment=0``
    means "flat mode" — it is substituted with the live DS selector."""
    try:
        await _client.clear_break(offset, old, segment=segment)
    except TrapError as exc:
        return _err(exc)
    return {
        "ok": True,
        "flat_segment_used": _client.flat_ds if segment == 0 else segment,
    }


@mcp.tool()
async def trap_get_next_alias(seg: int) -> dict[str, Any]:
    """Query the next alias mapping for ``seg`` in a segmented target."""
    try:
        result = await _client.get_next_alias(seg)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "seg": result.seg, "alias": result.alias}


@mcp.tool()
async def trap_set_user_screen() -> dict[str, Any]:
    """Switch the target display back to the user screen."""
    try:
        await _client.set_user_screen()
    except TrapError as exc:
        return _err(exc)
    return {"ok": True}


@mcp.tool()
async def trap_set_debug_screen() -> dict[str, Any]:
    """Switch the target display to the debugger screen."""
    try:
        await _client.set_debug_screen()
    except TrapError as exc:
        return _err(exc)
    return {"ok": True}


@mcp.tool()
async def trap_read_user_keyboard(wait_ms: int = 0) -> dict[str, Any]:
    """Poll the user's keyboard with an optional wait timeout in milliseconds."""
    try:
        key = await _client.read_user_keyboard(wait_ms=wait_ms)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "key": key, "key_hex": f"0x{key:02x}"}


@mcp.tool()
async def trap_get_lib_name(mod_handle: int) -> dict[str, Any]:
    """Enumerate loaded modules.

    Pass ``mod_handle=0`` to start. The returned ``next_mod_handle`` is the
    handle to pass on the next call; an empty ``name`` marks the end of the list.
    """
    try:
        result = await _client.get_lib_name(mod_handle)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "next_mod_handle": result.mod_handle, "name": result.name}


@mcp.tool()
async def trap_redirect_stdin(filename: str) -> dict[str, Any]:
    """Redirect stdin to a server-side file path and return the TRAP error code."""
    try:
        err = await _client.redirect_stdin(filename)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "err": err}


@mcp.tool()
async def trap_redirect_stdout(filename: str) -> dict[str, Any]:
    """Redirect stdout to a server-side file path and return the TRAP error code."""
    try:
        err = await _client.redirect_stdout(filename)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "err": err}


@mcp.tool()
async def trap_split_cmd(command: str) -> dict[str, Any]:
    """Split a command line into program and parameter spans using the trap server."""
    try:
        result = await _client.split_cmd(command)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "cmd_end": result.cmd_end, "parm_start": result.parm_start}


def _go_result(result: Any) -> dict[str, Any]:
    return {
        "ok": True,
        "sp": {"segment": result.stack_pointer.segment, "offset": result.stack_pointer.offset},
        "pc": {"segment": result.program_counter.segment, "offset": result.program_counter.offset},
        "conditions": p.decode_conditions(result.conditions),
        "conditions_raw": result.conditions,
    }


def _load_result(result: p.ProgLoadResult) -> dict[str, Any]:
    return {
        "ok": True,
        "err": result.err,
        "task_id": result.task_id,
        "mod_handle": result.mod_handle,
        "flags": result.flags,
        "load_flag_names": p.decode_load_flags(result.flags),
    }


@mcp.tool()
async def trap_prog_go(timeout_ms: int | None = None) -> dict[str, Any]:
    """Run the target until it hits a breakpoint, watchpoint, exception, or
    termination. Returns SP, PC, and the decoded condition flags.

    By default this blocks until the target stops. Pass ``timeout_ms`` to bound
    the wait and surface expiry as a transport error.
    """
    try:
        if timeout_ms is not None and timeout_ms <= 0:
            raise ValueError("timeout_ms must be > 0 or None")
        timeout = None if timeout_ms is None else timeout_ms / 1000.0
        result = await _client.prog_go(timeout=timeout)
    except ValueError as exc:
        return _value_err(exc)
    except TrapError as exc:
        return _err(exc)
    return _go_result(result)


@mcp.tool()
async def trap_prog_step() -> dict[str, Any]:
    """Single-step the target. Returns SP, PC, and decoded condition flags."""
    try:
        result = await _client.prog_step()
    except TrapError as exc:
        return _err(exc)
    return _go_result(result)


@mcp.tool()
async def trap_prog_load(argv: list[str], true_argv: bool = False) -> dict[str, Any]:
    """Load or attach via TRAP ``PROG_LOAD`` using a structured argv vector.

    With ``true_argv=False``, ``argv[0]`` is the program or attach token and
    ``argv[1:]`` are joined into the legacy second trailing string. With
    ``true_argv=True``, every argv element is serialized as its own NUL-terminated
    string on the wire.

    Branch on the top-level ``ok`` AND on the inner ``err`` (a non-zero TRAP
    error code — the load failed server-side even if the wire reply was valid).
    """
    try:
        p.normalize_prog_load_argv(argv)
        result = await _client.prog_load(argv, true_argv=true_argv)
    except ValueError as exc:
        return _value_err(exc)
    except TrapError as exc:
        return _err(exc)
    return _load_result(result)


@mcp.tool()
async def trap_prog_attach(pid: int | str, hex_format: bool = True) -> dict[str, Any]:
    """Attach to an existing process through TRAP ``PROG_LOAD``.

    Open Watcom trap servers encode attach as a special token in the first
    trailing string. ``pid`` accepts an integer or string forms such as
    ``"FFFE9DD7"``, ``"0xFFFE9DD7"``, or ``"#FFFE9DD7"``. Call this tool
    instead of constructing ``#PID`` manually.
    """
    try:
        result = await _client.prog_attach(_parse_attach_pid(pid), hex_format=hex_format)
    except ValueError as exc:
        return _value_err(exc)
    except TrapError as exc:
        return _err(exc)
    return _load_result(result)


@mcp.tool()
async def trap_prog_kill(task_id: int | None = None) -> dict[str, Any]:
    """Terminate a loaded task. Defaults to the task stored by the most recent
    :func:`trap_prog_load`. ``err`` is inlined — branch on ``ok`` AND ``err``."""
    try:
        err = await _client.prog_kill(task_id)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "err": err}


@mcp.tool()
async def trap_get_err_text(error: int) -> dict[str, Any]:
    """Resolve a TRAP error code (as returned in ``prog_load.err`` etc.) to
    the server's human-readable error string."""
    try:
        text = await _client.get_err_text(error)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "text": text}


@mcp.tool()
async def trap_get_message_text() -> dict[str, Any]:
    """Pull the next queued message from the debug server. ``flag_names``
    decodes the message-flag bitmask (NEWLINE/MORE/WARNING/ERROR)."""
    try:
        msg = await _client.get_message_text()
    except TrapError as exc:
        return _err(exc)
    return {
        "ok": True,
        "flags": msg.flags,
        "flag_names": p.decode_msg_flags(msg.flags),
        "text": msg.text,
    }


@mcp.tool()
async def trap_machine_data(
    info_type: int,
    offset: int,
    segment: int = 0,
    extra: str = "",
) -> dict[str, Any]:
    """Query machine-specific metadata for ``segment:offset``.

    ``extra`` is arch-specific request data encoded as hex. The reply exposes
    ``cache_start``/``cache_end`` plus arch-specific trailing bytes in ``extra``
    as lowercase hex; callers must decode it using the relevant MAD headers
    such as ``madx86.h`` or ``madx64.h``.
    """
    try:
        raw_extra = _unhex(extra) if extra else b""
        result = await _client.machine_data(info_type, offset, segment=segment, extra=raw_extra)
    except ValueError as exc:
        return {"ok": False, "error": {"code": "protocol_error", "message": str(exc)}}
    except TrapError as exc:
        return _err(exc)
    return {
        "ok": True,
        "cache_start": result.cache_start,
        "cache_end": result.cache_end,
        "extra": result.extra.hex(),
        "flat_segment_used": _client.flat_ds if segment == 0 else segment,
    }


@mcp.tool()
async def trap_file_get_config() -> dict[str, Any]:
    try:
        result = await _client.file_get_config()
    except TrapError as exc:
        return _err(exc)
    return {
        "ok": True,
        "ext_separator": result.ext_separator,
        "drv_separator": result.drv_separator,
        "path_separator": result.path_separator,
        "line_eol": result.line_eol,
        "list_separator": result.list_separator,
    }


@mcp.tool()
async def trap_file_open(mode: int, name: str) -> dict[str, Any]:
    try:
        result = await _client.file_open(mode, name)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "handle": result.handle}


@mcp.tool()
async def trap_file_seek(handle: int, mode: int, pos: int) -> dict[str, Any]:
    try:
        result = await _client.file_seek(handle, mode, pos)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "pos": result.pos}


@mcp.tool()
async def trap_file_read(handle: int, length: int) -> dict[str, Any]:
    try:
        result = await _client.file_read(handle, length)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "data": result.data.hex(), "read_length": len(result.data)}


@mcp.tool()
async def trap_file_write(handle: int, data: str) -> dict[str, Any]:
    try:
        raw = _unhex(data)
        result = await _client.file_write(handle, raw)
    except ValueError as exc:
        return {"ok": False, "error": {"code": "protocol_error", "message": str(exc)}}
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "written": result.length, "requested": len(raw)}


@mcp.tool()
async def trap_file_write_console(data: str) -> dict[str, Any]:
    try:
        raw = _unhex(data)
        result = await _client.file_write_console(raw)
    except ValueError as exc:
        return {"ok": False, "error": {"code": "protocol_error", "message": str(exc)}}
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "written": result.length, "requested": len(raw)}


@mcp.tool()
async def trap_file_close(handle: int) -> dict[str, Any]:
    try:
        await _client.file_close(handle)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True}


@mcp.tool()
async def trap_file_erase(name: str) -> dict[str, Any]:
    try:
        await _client.file_erase(name)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True}


@mcp.tool()
async def trap_file_string_to_fullpath(file_type: int, name: str) -> dict[str, Any]:
    try:
        result = await _client.file_string_to_fullpath(file_type, name)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "value": result.value}


@mcp.tool()
async def trap_file_run_cmd(command: str, chk_size: int = 0) -> dict[str, Any]:
    try:
        await _client.file_run_cmd(chk_size, command)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True}


@mcp.tool()
async def trap_file_info_get_date(name: str) -> dict[str, Any]:
    try:
        result = await _client.file_info_get_date(name)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "date": result.date}


@mcp.tool()
async def trap_file_info_set_date(name: str, date: int) -> dict[str, Any]:
    try:
        await _client.file_info_set_date(date, name)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True}


@mcp.tool()
async def trap_env_get_var(name: str, res_len: int = 4096) -> dict[str, Any]:
    try:
        result = await _client.env_get_var(res_len, name)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "value": result.value}


@mcp.tool()
async def trap_env_set_var(name: str, value: str) -> dict[str, Any]:
    try:
        await _client.env_set_var(name, value)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True}


@mcp.tool()
async def trap_ovl_state_size() -> dict[str, Any]:
    try:
        size = await _client.ovl_state_size()
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "size": size}


@mcp.tool()
async def trap_ovl_get_data(sect_id: int) -> dict[str, Any]:
    try:
        result = await _client.ovl_get_data(sect_id)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "segment": result.segment, "size": result.size}


@mcp.tool()
async def trap_ovl_read_state() -> dict[str, Any]:
    try:
        data = await _client.ovl_read_state()
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "data": data.hex(), "length": len(data)}


@mcp.tool()
async def trap_ovl_write_state(data: str) -> dict[str, Any]:
    try:
        await _client.ovl_write_state(_unhex(data))
    except ValueError as exc:
        return {"ok": False, "error": {"code": "protocol_error", "message": str(exc)}}
    except TrapError as exc:
        return _err(exc)
    return {"ok": True}


@mcp.tool()
async def trap_ovl_trans_vect_addr(offset: int, segment: int, sect_id: int) -> dict[str, Any]:
    try:
        result = await _client.ovl_trans_vect_addr(
            p.OvlAddress(mach=p.Addr48(offset=offset, segment=segment), sect_id=sect_id)
        )
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "ovl_addr": _ovl_addr(result)}


@mcp.tool()
async def trap_ovl_trans_ret_addr(offset: int, segment: int, sect_id: int) -> dict[str, Any]:
    try:
        result = await _client.ovl_trans_ret_addr(
            p.OvlAddress(mach=p.Addr48(offset=offset, segment=segment), sect_id=sect_id)
        )
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "ovl_addr": _ovl_addr(result)}


@mcp.tool()
async def trap_ovl_get_remap_entry(offset: int, segment: int, sect_id: int) -> dict[str, Any]:
    try:
        result = await _client.ovl_get_remap_entry(
            p.OvlAddress(mach=p.Addr48(offset=offset, segment=segment), sect_id=sect_id)
        )
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "remapped": result.remapped, "ovl_addr": _ovl_addr(result.ovl_addr)}


@mcp.tool()
async def trap_thread_get_next(thread: int = 0) -> dict[str, Any]:
    try:
        result = await _client.thread_get_next(thread)
    except TrapError as exc:
        return _err(exc)
    return {
        "ok": True,
        "thread": result.thread,
        "state": result.state,
        "state_name": p.decode_thread_state(result.state),
    }


@mcp.tool()
async def trap_thread_set(thread: int) -> dict[str, Any]:
    try:
        result = await _client.thread_set(thread)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "old_thread": result.old_thread}


@mcp.tool()
async def trap_thread_freeze(thread: int) -> dict[str, Any]:
    try:
        await _client.thread_freeze(thread)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True}


@mcp.tool()
async def trap_thread_thaw(thread: int) -> dict[str, Any]:
    try:
        await _client.thread_thaw(thread)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True}


@mcp.tool()
async def trap_thread_get_extra(thread: int) -> dict[str, Any]:
    try:
        extra = await _client.thread_get_extra(thread)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "extra": extra}


@mcp.tool()
async def trap_run_thread_info(col: int) -> dict[str, Any]:
    try:
        result = await _client.run_thread_info(col)
    except TrapError as exc:
        return _err(exc)
    return {
        "ok": True,
        "info": result.info,
        "info_name": p.decode_run_thread_info_type(result.info),
        "width": result.width,
        "header": result.header,
    }


@mcp.tool()
async def trap_run_thread_get_next(thread: int = 0) -> dict[str, Any]:
    try:
        result = await _client.run_thread_get_next(thread)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "thread": result.thread}


@mcp.tool()
async def trap_run_thread_get_runtime(thread: int) -> dict[str, Any]:
    try:
        result = await _client.run_thread_get_runtime(thread)
    except TrapError as exc:
        return _err(exc)
    return {
        "ok": True,
        "state": result.state,
        "state_name": p.decode_thread_state(result.state),
        "cs": result.cs,
        "eip": result.eip,
        "extra": result.extra,
    }


@mcp.tool()
async def trap_run_thread_poll() -> dict[str, Any]:
    try:
        conditions = await _client.run_thread_poll()
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "conditions_raw": conditions, "conditions": p.decode_conditions(conditions)}


@mcp.tool()
async def trap_run_thread_set(thread: int) -> dict[str, Any]:
    try:
        result = await _client.run_thread_set(thread)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "old_thread": result.old_thread}


@mcp.tool()
async def trap_run_thread_get_name(thread: int) -> dict[str, Any]:
    try:
        name = await _client.run_thread_get_name(thread)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "name": name}


@mcp.tool()
async def trap_run_thread_stop(thread: int) -> dict[str, Any]:
    try:
        await _client.run_thread_stop(thread)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True}


@mcp.tool()
async def trap_run_thread_signal_stop(thread: int) -> dict[str, Any]:
    try:
        await _client.run_thread_signal_stop(thread)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True}


@mcp.tool()
async def trap_rfx_rename(old_name: str, new_name: str) -> dict[str, Any]:
    try:
        await _client.rfx_rename(old_name, new_name)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True}


@mcp.tool()
async def trap_rfx_mkdir(dirname: str) -> dict[str, Any]:
    try:
        await _client.rfx_mkdir(dirname)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True}


@mcp.tool()
async def trap_rfx_rmdir(dirname: str) -> dict[str, Any]:
    try:
        await _client.rfx_rmdir(dirname)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True}


@mcp.tool()
async def trap_rfx_setdrive(drive: int) -> dict[str, Any]:
    try:
        await _client.rfx_setdrive(drive)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True}


@mcp.tool()
async def trap_rfx_getdrive() -> dict[str, Any]:
    try:
        drive = await _client.rfx_getdrive()
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "drive": drive}


@mcp.tool()
async def trap_rfx_setcwd(cwd: str) -> dict[str, Any]:
    try:
        await _client.rfx_setcwd(cwd)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True}


@mcp.tool()
async def trap_rfx_getcwd(drive: int = 0) -> dict[str, Any]:
    try:
        result = await _client.rfx_getcwd(drive)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "cwd": result.value}


@mcp.tool()
async def trap_rfx_setdatetime(handle: int, time: int) -> dict[str, Any]:
    try:
        await _client.rfx_setdatetime(handle, time)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True}


@mcp.tool()
async def trap_rfx_getdatetime(handle: int) -> dict[str, Any]:
    try:
        time = await _client.rfx_getdatetime(handle)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "time": time}


@mcp.tool()
async def trap_rfx_getfreespace(drive: int = 0) -> dict[str, Any]:
    try:
        size = await _client.rfx_getfreespace(drive)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "size": size}


@mcp.tool()
async def trap_rfx_setfileattr(attribute: int, name: str) -> dict[str, Any]:
    try:
        await _client.rfx_setfileattr(attribute, name)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True}


@mcp.tool()
async def trap_rfx_getfileattr(name: str) -> dict[str, Any]:
    try:
        attribute = await _client.rfx_getfileattr(name)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "attribute": attribute}


@mcp.tool()
async def trap_rfx_nametocanonical(name: str) -> dict[str, Any]:
    try:
        result = await _client.rfx_nametocanonical(name)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "value": result.value}


@mcp.tool()
async def trap_rfx_findfirst(attrib: int, pattern: str) -> dict[str, Any]:
    try:
        result = await _client.rfx_findfirst(attrib, pattern)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "find": _rfx_find(result.info)}


@mcp.tool()
async def trap_rfx_findnext(
    reserved: str,
    attr: int,
    time: int,
    date: int,
    size: int,
    name: str,
) -> dict[str, Any]:
    try:
        info = p.RfxFindResult(
            reserved=_unhex(reserved),
            attr=attr,
            time=time,
            date=date,
            size=size,
            name=name,
        )
        result = await _client.rfx_findnext(info)
    except ValueError as exc:
        return {"ok": False, "error": {"code": "protocol_error", "message": str(exc)}}
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "find": _rfx_find(result.info)}


@mcp.tool()
async def trap_rfx_findclose(
    reserved: str,
    attr: int,
    time: int,
    date: int,
    size: int,
    name: str,
) -> dict[str, Any]:
    try:
        await _client.rfx_findclose(
            p.RfxFindResult(
                reserved=_unhex(reserved),
                attr=attr,
                time=time,
                date=date,
                size=size,
                name=name,
            )
        )
    except ValueError as exc:
        return {"ok": False, "error": {"code": "protocol_error", "message": str(exc)}}
    except TrapError as exc:
        return _err(exc)
    return {"ok": True}


@mcp.tool()
async def trap_capabilities_get_exact_bp() -> dict[str, Any]:
    try:
        result = await _client.capabilities_get_exact_bp()
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "status": result.status, "enabled": bool(result.status)}


@mcp.tool()
async def trap_capabilities_set_exact_bp(status: int) -> dict[str, Any]:
    try:
        result = await _client.capabilities_set_exact_bp(status)
    except TrapError as exc:
        return _err(exc)
    return {"ok": True, "status": result.status, "enabled": bool(result.status)}


@mcp.tool()
async def trap_async_go() -> dict[str, Any]:
    try:
        result = await _client.async_go()
    except TrapError as exc:
        return _err(exc)
    return _go_result(result)


@mcp.tool()
async def trap_async_step() -> dict[str, Any]:
    try:
        result = await _client.async_step()
    except TrapError as exc:
        return _err(exc)
    return _go_result(result)


@mcp.tool()
async def trap_async_poll() -> dict[str, Any]:
    try:
        result = await _client.async_poll()
    except TrapError as exc:
        return _err(exc)
    return _go_result(result)


@mcp.tool()
async def trap_async_stop() -> dict[str, Any]:
    try:
        result = await _client.async_stop()
    except TrapError as exc:
        return _err(exc)
    return _go_result(result)


@mcp.tool()
async def trap_async_add_break(
    offset: int, segment: int = 0, local: bool = False
) -> dict[str, Any]:
    try:
        await _client.async_add_break(offset, segment=segment, local=local)
    except TrapError as exc:
        return _err(exc)
    return {
        "ok": True,
        "flat_segment_used": _client.flat_ds if segment == 0 else segment,
        "local": local,
    }


@mcp.tool()
async def trap_async_remove_break(
    offset: int, segment: int = 0, local: bool = False
) -> dict[str, Any]:
    try:
        await _client.async_remove_break(offset, segment=segment, local=local)
    except TrapError as exc:
        return _err(exc)
    return {
        "ok": True,
        "flat_segment_used": _client.flat_ds if segment == 0 else segment,
        "local": local,
    }
