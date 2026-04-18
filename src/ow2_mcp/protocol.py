"""Pure encode/decode for the OpenWatcom TRAP wire protocol.

No I/O — only byte manipulation. See OW2 sources for the authoritative reference:
- Request codes: ``bld/dig/h/_trpreq.h``
- Core structs: ``bld/dig/h/trpcore.h``
- Arch/OS tables: ``bld/dig/h/digarch.h`` / ``bld/dig/h/digos.h``
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum, IntFlag

TRAP_VERSION_MAJOR = 18
TRAP_VERSION_MINOR = 0
PACKET_MAX = 0x400
DEFAULT_PORT = 0x0DEB  # 3563


class Req(IntEnum):
    """TRAP request codes. Order mirrors ``_trpreq.h`` exactly."""

    CONNECT = 0
    DISCONNECT = 1
    SUSPEND = 2
    RESUME = 3
    GET_SUPPLEMENTARY_SERVICE = 4
    PERFORM_SUPPLEMENTARY_SERVICE = 5
    GET_SYS_CONFIG = 6
    MAP_ADDR = 7
    CHECKSUM_MEM = 8
    READ_MEM = 9
    WRITE_MEM = 10
    READ_IO = 11
    WRITE_IO = 12
    PROG_GO = 13
    PROG_STEP = 14
    PROG_LOAD = 15
    PROG_KILL = 16
    SET_WATCH = 17
    CLEAR_WATCH = 18
    SET_BREAK = 19
    CLEAR_BREAK = 20
    GET_NEXT_ALIAS = 21
    SET_USER_SCREEN = 22
    SET_DEBUG_SCREEN = 23
    READ_USER_KEYBOARD = 24
    GET_LIB_NAME = 25
    GET_ERR_TEXT = 26
    GET_MESSAGE_TEXT = 27
    REDIRECT_STDIN = 28
    REDIRECT_STDOUT = 29
    SPLIT_CMD = 30
    READ_REGS = 31
    WRITE_REGS = 32
    MACHINE_DATA = 33


class Cond(IntFlag):
    """``prog_go_ret.conditions`` bitmask (see ``bld/wv/doc/trap.gml``)."""

    CONFIG = 0x0001
    SECTIONS = 0x0002
    LIBRARIES = 0x0004
    ALIASING = 0x0008
    THREAD = 0x0010
    THREAD_EXTRA = 0x0020
    TRACE = 0x0040
    BREAK = 0x0080
    WATCH = 0x0100
    USER = 0x0200
    TERMINATE = 0x0400
    EXCEPTION = 0x0800
    MESSAGE = 0x1000
    STOP = 0x2000
    RUNNING = 0x4000


class LoadFlag(IntFlag):
    """``prog_load_ret.flags`` bitmask (see ``trpcore.h:237-243``)."""

    IS_BIG = 0x01
    IS_PROT = 0x02
    IS_STARTED = 0x04
    IGNORE_SEGMENTS = 0x08
    HAVE_RUNTIME_DLLS = 0x10
    DISPLAY_DAMAGED = 0x20


class MsgFlag(IntFlag):
    """``get_message_text_ret.flags`` bitmask (see ``trpcore.h:355-360``)."""

    NEWLINE = 0x01
    MORE = 0x02
    WARNING = 0x04
    ERROR = 0x08


DIG_ARCH_NAMES: tuple[str, ...] = (
    "NIL",
    "X86",
    "X64",
    "AXP",
    "PPC",
    "MIPS",
    "MSJ",
    "JVM",
)

DIG_OS_NAMES: tuple[str, ...] = (
    "Unknown",
    "DOS",
    "OS/2",
    "Phar Lap 386 DOS Extender",
    "Eclipse 386 DOS Extender",
    "NetWare 386",
    "QNX 4.x",
    "DOS/4G or compatible",
    "Windows 3.x",
    "PenPoint",
    "Win32",
    "Autocad",
    "QNX 6.x Neutrino",
    "Linux",
    "FreeBSD",
    "Windows 64-bit",
)


@dataclass(frozen=True, slots=True)
class Addr48:
    """48-bit segmented address: ``{u32 offset, u16 segment}``."""

    offset: int
    segment: int = 0

    def pack(self) -> bytes:
        return struct.pack("<IH", self.offset & 0xFFFFFFFF, self.segment & 0xFFFF)

    @classmethod
    def unpack(cls, data: bytes, pos: int = 0) -> Addr48:
        offset, segment = struct.unpack_from("<IH", data, pos)
        return cls(offset=offset, segment=segment)


ADDR48_SIZE = 6


def _latin1(s: str) -> bytes:
    return s.encode("latin-1", errors="replace")


def _latin1_from(data: bytes) -> str:
    return data.decode("latin-1", errors="replace")


def _c_string(data: bytes, pos: int = 0) -> str:
    """Decode a latin-1 C string starting at ``pos``, stopping at NUL or EOF."""
    end = data.find(b"\x00", pos)
    if end == -1:
        end = len(data)
    return _latin1_from(data[pos:end])


def decode_conditions(conditions: int) -> list[str]:
    """Return the human-readable names of every set bit in ``conditions``."""
    value = Cond(conditions & 0xFFFF)
    return [flag.name for flag in Cond if flag in value and flag.name is not None]


def decode_load_flags(flags: int) -> list[str]:
    value = LoadFlag(flags & 0xFF)
    return [flag.name for flag in LoadFlag if flag in value and flag.name is not None]


def decode_msg_flags(flags: int) -> list[str]:
    value = MsgFlag(flags & 0xFF)
    return [flag.name for flag in MsgFlag if flag in value and flag.name is not None]


def arch_name(code: int) -> str:
    if 0 <= code < len(DIG_ARCH_NAMES):
        return DIG_ARCH_NAMES[code]
    return f"unknown({code})"


def os_name(code: int) -> str:
    if 0 <= code < len(DIG_OS_NAMES):
        return DIG_OS_NAMES[code]
    return f"unknown({code})"


# --- CONNECT / DISCONNECT ---------------------------------------------------


def pack_connect_req(
    ver_major: int = TRAP_VERSION_MAJOR,
    ver_minor: int = TRAP_VERSION_MINOR,
    remote: int = 0,
) -> bytes:
    return struct.pack("<BBBB", Req.CONNECT, ver_major, ver_minor, remote)


def parse_connect_ret(data: bytes) -> tuple[int, str]:
    """Return ``(max_msg_size, error_message)``. Empty ``error_message`` == success."""
    if len(data) < 2:
        raise _short("connect_ret", need=2, got=len(data))
    (max_msg_size,) = struct.unpack_from("<H", data, 0)
    err = _c_string(data, 2)
    return max_msg_size, err


def pack_disconnect_req() -> bytes:
    return bytes([Req.DISCONNECT])


# --- GET_SYS_CONFIG ---------------------------------------------------------


def pack_get_sys_config_req() -> bytes:
    return bytes([Req.GET_SYS_CONFIG])


@dataclass(frozen=True, slots=True)
class SysConfig:
    cpu: int
    fpu: int
    os_major: int
    os_minor: int
    os: int
    huge_shift: int
    arch: int


def parse_get_sys_config_ret(data: bytes) -> SysConfig:
    if len(data) < 7:
        raise _short("get_sys_config_ret", need=7, got=len(data))
    cpu, fpu, osmajor, osminor, os_, huge_shift, arch = struct.unpack_from("<BBBBBBB", data, 0)
    return SysConfig(
        cpu=cpu,
        fpu=fpu,
        os_major=osmajor,
        os_minor=osminor,
        os=os_,
        huge_shift=huge_shift,
        arch=arch,
    )


# --- READ_MEM / WRITE_MEM ---------------------------------------------------


def pack_read_mem_req(addr: Addr48, length: int) -> bytes:
    return struct.pack("<B", Req.READ_MEM) + addr.pack() + struct.pack("<H", length & 0xFFFF)


def pack_write_mem_req(addr: Addr48, data: bytes) -> bytes:
    return struct.pack("<B", Req.WRITE_MEM) + addr.pack() + data


def parse_write_mem_ret(data: bytes) -> int:
    if len(data) < 2:
        raise _short("write_mem_ret", need=2, got=len(data))
    (written,) = struct.unpack_from("<H", data, 0)
    return int(written)


# --- READ_REGS / WRITE_REGS -------------------------------------------------


def pack_read_regs_req() -> bytes:
    return bytes([Req.READ_REGS])


# x86/Win32 register block layout — bytes inside the REQ_READ_REGS reply.
# Source: bld/dig/h/madx86.h:130-150 (struct x86_cpu, pack(1)).
X86_REG_DS_OFFSET = 52
X86_REG_CS_OFFSET = 58


def extract_x86_flat_selectors(reg_block: bytes) -> tuple[int, int] | None:
    """Return ``(ds, cs)`` from a Win32/x86 register reply, or ``None`` if short.

    The caller is responsible for knowing the target is x86 — this function
    just reads the two u16 LE fields at the canonical offsets.
    """
    if len(reg_block) < X86_REG_CS_OFFSET + 2:
        return None
    (ds,) = struct.unpack_from("<H", reg_block, X86_REG_DS_OFFSET)
    (cs,) = struct.unpack_from("<H", reg_block, X86_REG_CS_OFFSET)
    return ds, cs


def pack_write_regs_req(data: bytes) -> bytes:
    return bytes([Req.WRITE_REGS]) + data


# --- SET_BREAK / CLEAR_BREAK ------------------------------------------------


def pack_set_break_req(addr: Addr48) -> bytes:
    return struct.pack("<B", Req.SET_BREAK) + addr.pack()


def parse_set_break_ret(data: bytes) -> int:
    if len(data) < 4:
        raise _short("set_break_ret", need=4, got=len(data))
    (old,) = struct.unpack_from("<I", data, 0)
    return int(old)


def pack_clear_break_req(addr: Addr48, old: int) -> bytes:
    return struct.pack("<B", Req.CLEAR_BREAK) + addr.pack() + struct.pack("<I", old & 0xFFFFFFFF)


# --- PROG_GO / PROG_STEP ----------------------------------------------------


def pack_prog_go_req() -> bytes:
    return bytes([Req.PROG_GO])


def pack_prog_step_req() -> bytes:
    return bytes([Req.PROG_STEP])


@dataclass(frozen=True, slots=True)
class ProgGoResult:
    stack_pointer: Addr48
    program_counter: Addr48
    conditions: int


def parse_prog_go_ret(data: bytes) -> ProgGoResult:
    if len(data) < 14:
        raise _short("prog_go_ret", need=14, got=len(data))
    sp = Addr48.unpack(data, 0)
    pc = Addr48.unpack(data, 6)
    (conditions,) = struct.unpack_from("<H", data, 12)
    return ProgGoResult(stack_pointer=sp, program_counter=pc, conditions=conditions)


# --- PROG_LOAD --------------------------------------------------------------


def pack_prog_load_req(program: str, args: str = "", true_argv: bool = False) -> bytes:
    """Encode a PROG_LOAD request.

    Wire format: ``[u8 req][u8 true_argv][program\\0][args\\0]``. Always appends
    a trailing NUL after ``args`` even when ``args`` is empty, so the minimum
    payload for empty inputs is ``b"\\x0f\\x00\\x00\\x00"`` (4 bytes).
    The in-memory ``0xFF`` sentinel from the OW2 debugger source is never
    transmitted.
    """
    header = bytes([Req.PROG_LOAD, 1 if true_argv else 0])
    return header + _latin1(program) + b"\x00" + _latin1(args) + b"\x00"


@dataclass(frozen=True, slots=True)
class ProgLoadResult:
    err: int
    task_id: int
    mod_handle: int
    flags: int


def parse_prog_load_ret(data: bytes) -> ProgLoadResult:
    if len(data) < 13:
        raise _short("prog_load_ret", need=13, got=len(data))
    err, task_id, mod_handle, flags = struct.unpack_from("<IIIB", data, 0)
    return ProgLoadResult(err=err, task_id=task_id, mod_handle=mod_handle, flags=flags)


# --- PROG_KILL --------------------------------------------------------------


def pack_prog_kill_req(task_id: int) -> bytes:
    return struct.pack("<BI", Req.PROG_KILL, task_id & 0xFFFFFFFF)


def parse_prog_kill_ret(data: bytes) -> int:
    if len(data) < 4:
        raise _short("prog_kill_ret", need=4, got=len(data))
    (err,) = struct.unpack_from("<I", data, 0)
    return int(err)


# --- GET_ERR_TEXT / GET_MESSAGE_TEXT ---------------------------------------


def pack_get_err_text_req(error: int) -> bytes:
    return struct.pack("<BI", Req.GET_ERR_TEXT, error & 0xFFFFFFFF)


def parse_get_err_text_ret(data: bytes) -> str:
    return _c_string(data, 0)


def pack_get_message_text_req() -> bytes:
    return bytes([Req.GET_MESSAGE_TEXT])


@dataclass(frozen=True, slots=True)
class MessageText:
    flags: int
    text: str


def parse_get_message_text_ret(data: bytes) -> MessageText:
    if len(data) < 1:
        raise _short("get_message_text_ret", need=1, got=len(data))
    return MessageText(flags=data[0], text=_c_string(data, 1))


# --- error helpers ---------------------------------------------------------


def _short(label: str, *, need: int, got: int) -> Exception:
    from .errors import ProtocolError

    msg = f"{label}: reply too short (need {need} bytes, got {got})"
    if label == "prog_go_ret" and got == 0:
        msg += " — possible target state corruption (e.g. prior mem op on seg=0 without flat-mode)"
    return ProtocolError(msg)
