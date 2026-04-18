"""FastMCP server exposing 15 TRAP tools over stdio."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from . import protocol as p
from .client import TrapClient
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


def _go_result(result: Any) -> dict[str, Any]:
    return {
        "ok": True,
        "sp": {"segment": result.stack_pointer.segment, "offset": result.stack_pointer.offset},
        "pc": {"segment": result.program_counter.segment, "offset": result.program_counter.offset},
        "conditions": p.decode_conditions(result.conditions),
        "conditions_raw": result.conditions,
    }


@mcp.tool()
async def trap_prog_go() -> dict[str, Any]:
    """Run the target until it hits a breakpoint, watchpoint, exception, or
    termination. Returns SP, PC, and the decoded condition flags."""
    try:
        result = await _client.prog_go()
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
async def trap_prog_load(
    program: str, args: str = "", true_argv: bool = False
) -> dict[str, Any]:
    """Load ``program`` into the debugger with ``args``.

    Branch on the top-level ``ok`` AND on the inner ``err`` (a non-zero TRAP
    error code — the load failed server-side even if the wire reply was valid).
    """
    try:
        result = await _client.prog_load(program, args, true_argv=true_argv)
    except TrapError as exc:
        return _err(exc)
    return {
        "ok": True,
        "err": result.err,
        "task_id": result.task_id,
        "mod_handle": result.mod_handle,
        "flags": result.flags,
        "load_flag_names": p.decode_load_flags(result.flags),
    }


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
