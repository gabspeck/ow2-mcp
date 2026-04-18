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
MAP_FLAT_CODE_SELECTOR = 0xFFFF
MAP_FLAT_DATA_SELECTOR = 0xFFFE


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


def _latin1z(s: str) -> bytes:
    return _latin1(s) + b"\x00"


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


# --- SUSPEND / RESUME / SUPPLEMENTARY SERVICE -------------------------------


def pack_suspend_req() -> bytes:
    return bytes([Req.SUSPEND])


def pack_resume_req() -> bytes:
    return bytes([Req.RESUME])


def pack_get_supplementary_service_req(service: str) -> bytes:
    return bytes([Req.GET_SUPPLEMENTARY_SERVICE]) + _latin1(service) + b"\x00"


@dataclass(frozen=True, slots=True)
class SupplementaryServiceResult:
    err: int
    shandle: int


def parse_get_supplementary_service_ret(data: bytes) -> SupplementaryServiceResult:
    if len(data) < 8:
        raise _short("get_supplementary_service_ret", need=8, got=len(data))
    err, shandle = struct.unpack_from("<II", data, 0)
    return SupplementaryServiceResult(err=err, shandle=shandle)


def pack_perform_supplementary_service_req(shandle: int, payload: bytes = b"") -> bytes:
    return bytes([Req.PERFORM_SUPPLEMENTARY_SERVICE]) + struct.pack(
        "<I", shandle & 0xFFFFFFFF
    ) + payload


SUPP_FILES = "Files"
SUPP_FILE_INFO = "FileInfo"
SUPP_ENVIRONMENT = "Environment"
SUPP_OVERLAYS = "Overlays"
SUPP_THREADS = "Threads"
SUPP_RUN_THREAD = "RunThread"
SUPP_RFX = "Rfx"
SUPP_CAPABILITIES = "Capabilities"
SUPP_ASYNCH = "Asynch"


class FileReq(IntEnum):
    GET_CONFIG = 0
    OPEN = 1
    SEEK = 2
    READ = 3
    WRITE = 4
    WRITE_CONSOLE = 5
    CLOSE = 6
    ERASE = 7
    STRING_TO_FULLPATH = 8
    RUN_CMD = 9


class FileInfoReq(IntEnum):
    GET_DATE = 0
    SET_DATE = 1


class EnvReq(IntEnum):
    GET_VAR = 0
    SET_VAR = 1


class OvlReq(IntEnum):
    STATE_SIZE = 0
    GET_DATA = 1
    READ_STATE = 2
    WRITE_STATE = 3
    TRANS_VECT_ADDR = 4
    TRANS_RET_ADDR = 5
    GET_REMAP_ENTRY = 6


class ThreadReq(IntEnum):
    GET_NEXT = 0
    SET = 1
    FREEZE = 2
    THAW = 3
    GET_EXTRA = 4


class ThreadState(IntEnum):
    THAWED = 0
    FROZEN = 1


class RunThreadReq(IntEnum):
    INFO = 0
    GET_NEXT = 1
    GET_RUNTIME = 2
    POLL = 3
    SET = 4
    GET_NAME = 5
    STOP = 6
    SIGNAL_STOP = 7


class RunThreadInfoType(IntEnum):
    NONE = 0
    NAME = 1
    STATE = 2
    CS_EIP = 3
    EXTRA = 4


class RfxReq(IntEnum):
    RENAME = 0
    MKDIR = 1
    RMDIR = 2
    SETDRIVE = 3
    GETDRIVE = 4
    SETCWD = 5
    GETCWD = 6
    SETDATETIME = 7
    GETDATETIME = 8
    GETFREESPACE = 9
    SETFILEATTR = 10
    GETFILEATTR = 11
    NAMETOCANONICAL = 12
    FINDFIRST = 13
    FINDNEXT = 14
    FINDCLOSE = 15


class CapabilitiesReq(IntEnum):
    GET_EXACT_BP = 0
    SET_EXACT_BP = 1


class AsyncReq(IntEnum):
    GO = 0
    STEP = 1
    POLL = 2
    STOP = 3
    ADD_BREAK = 4
    REMOVE_BREAK = 5


RFX_FIND_RESERVED_SIZE = 21
RFX_FIND_FIXED_SIZE = RFX_FIND_RESERVED_SIZE + 1 + 2 + 2 + 4


def pack_supplementary_req(shandle: int, req: int, body: bytes = b"") -> bytes:
    return pack_perform_supplementary_service_req(shandle, bytes([req & 0xFF]) + body)


@dataclass(frozen=True, slots=True)
class FileComponents:
    ext_separator: str
    drv_separator: str
    path_separator: str
    line_eol: str
    list_separator: str


@dataclass(frozen=True, slots=True)
class FileOpenResult:
    err: int
    handle: int


@dataclass(frozen=True, slots=True)
class FileSeekResult:
    err: int
    pos: int


@dataclass(frozen=True, slots=True)
class FileReadResult:
    err: int
    data: bytes


@dataclass(frozen=True, slots=True)
class FileWriteResult:
    err: int
    length: int


@dataclass(frozen=True, slots=True)
class StringResult:
    err: int
    value: str


@dataclass(frozen=True, slots=True)
class FileDateResult:
    err: int
    date: int


@dataclass(frozen=True, slots=True)
class OvlAddress:
    mach: Addr48
    sect_id: int

    def pack(self) -> bytes:
        return self.mach.pack() + struct.pack("<H", self.sect_id & 0xFFFF)

    @classmethod
    def unpack(cls, data: bytes, pos: int = 0) -> OvlAddress:
        sect_id = struct.unpack_from("<H", data, pos + 6)[0]
        return cls(mach=Addr48.unpack(data, pos), sect_id=sect_id)


OVL_ADDRESS_SIZE = 8


@dataclass(frozen=True, slots=True)
class OvlGetDataResult:
    segment: int
    size: int


@dataclass(frozen=True, slots=True)
class OvlRemapEntryResult:
    remapped: bool
    ovl_addr: OvlAddress


@dataclass(frozen=True, slots=True)
class ThreadGetNextResult:
    thread: int
    state: int


@dataclass(frozen=True, slots=True)
class ThreadSetResult:
    err: int
    old_thread: int


@dataclass(frozen=True, slots=True)
class RunThreadInfoResult:
    info: int
    width: int
    header: str


@dataclass(frozen=True, slots=True)
class RunThreadGetNextResult:
    thread: int


@dataclass(frozen=True, slots=True)
class RunThreadRuntimeResult:
    state: int
    cs: int
    eip: int
    extra: str


@dataclass(frozen=True, slots=True)
class RunThreadSetResult:
    err: int
    old_thread: int


@dataclass(frozen=True, slots=True)
class RfxFindResult:
    reserved: bytes
    attr: int
    time: int
    date: int
    size: int
    name: str

    def pack(self) -> bytes:
        return (
            self.reserved[:RFX_FIND_RESERVED_SIZE].ljust(RFX_FIND_RESERVED_SIZE, b"\x00")
            + struct.pack(
                "<BHHI",
                self.attr & 0xFF,
                self.time & 0xFFFF,
                self.date & 0xFFFF,
                self.size & 0xFFFFFFFF,
            )
            + _latin1(self.name)
            + b"\x00"
        )


@dataclass(frozen=True, slots=True)
class RfxFindReply:
    err: int
    info: RfxFindResult | None


@dataclass(frozen=True, slots=True)
class ExactBreakpointSupport:
    err: int
    status: int


def decode_thread_state(state: int) -> str:
    if state == ThreadState.THAWED:
        return "thawed"
    if state == ThreadState.FROZEN:
        return "frozen"
    return f"unknown({state})"


def decode_run_thread_info_type(info: int) -> str:
    try:
        return RunThreadInfoType(info).name.lower()
    except ValueError:
        return f"unknown({info})"


def parse_trap_error_ret(data: bytes, label: str) -> int:
    if len(data) < 4:
        raise _short(label, need=4, got=len(data))
    return int(struct.unpack_from("<I", data, 0)[0])


def _parse_error_prefixed_string(data: bytes, label: str) -> StringResult:
    err = parse_trap_error_ret(data, label)
    return StringResult(err=err, value=_c_string(data, 4))


def pack_file_get_config_req(shandle: int) -> bytes:
    return pack_supplementary_req(shandle, FileReq.GET_CONFIG)


def parse_file_get_config_ret(data: bytes) -> FileComponents:
    if len(data) < 7:
        raise _short("file_get_config_ret", need=7, got=len(data))
    return FileComponents(
        ext_separator=_latin1_from(data[0:1]),
        drv_separator=_latin1_from(data[1:2]),
        path_separator=_latin1_from(data[2:4]).rstrip("\x00"),
        line_eol=_latin1_from(data[4:6]).rstrip("\x00"),
        list_separator=_latin1_from(data[6:7]),
    )


def pack_file_open_req(shandle: int, mode: int, name: str) -> bytes:
    body = struct.pack("<B", mode & 0xFF) + _latin1z(name)
    return pack_supplementary_req(shandle, FileReq.OPEN, body)


def parse_file_open_ret(data: bytes) -> FileOpenResult:
    if len(data) < 12:
        raise _short("file_open_ret", need=12, got=len(data))
    err, handle = struct.unpack_from("<IQ", data, 0)
    return FileOpenResult(err=err, handle=handle)


def pack_file_seek_req(shandle: int, handle: int, mode: int, pos: int) -> bytes:
    body = struct.pack("<QBI", handle & 0xFFFFFFFFFFFFFFFF, mode & 0xFF, pos & 0xFFFFFFFF)
    return pack_supplementary_req(shandle, FileReq.SEEK, body)


def parse_file_seek_ret(data: bytes) -> FileSeekResult:
    if len(data) < 8:
        raise _short("file_seek_ret", need=8, got=len(data))
    err, pos = struct.unpack_from("<II", data, 0)
    return FileSeekResult(err=err, pos=pos)


def pack_file_read_req(shandle: int, handle: int, length: int) -> bytes:
    body = struct.pack("<QH", handle & 0xFFFFFFFFFFFFFFFF, length & 0xFFFF)
    return pack_supplementary_req(shandle, FileReq.READ, body)


def parse_file_read_ret(data: bytes) -> FileReadResult:
    err = parse_trap_error_ret(data, "file_read_ret")
    return FileReadResult(err=err, data=data[4:])


def pack_file_write_req(shandle: int, handle: int, data: bytes) -> bytes:
    body = struct.pack("<Q", handle & 0xFFFFFFFFFFFFFFFF) + data
    return pack_supplementary_req(shandle, FileReq.WRITE, body)


def parse_file_write_ret(data: bytes) -> FileWriteResult:
    if len(data) < 6:
        raise _short("file_write_ret", need=6, got=len(data))
    err, length = struct.unpack_from("<IH", data, 0)
    return FileWriteResult(err=err, length=length)


def pack_file_write_console_req(shandle: int, data: bytes) -> bytes:
    return pack_supplementary_req(shandle, FileReq.WRITE_CONSOLE, data)


def parse_file_write_console_ret(data: bytes) -> FileWriteResult:
    if len(data) < 6:
        raise _short("file_write_console_ret", need=6, got=len(data))
    err, length = struct.unpack_from("<IH", data, 0)
    return FileWriteResult(err=err, length=length)


def pack_file_close_req(shandle: int, handle: int) -> bytes:
    return pack_supplementary_req(
        shandle, FileReq.CLOSE, struct.pack("<Q", handle & 0xFFFFFFFFFFFFFFFF)
    )


def parse_file_close_ret(data: bytes) -> int:
    return parse_trap_error_ret(data, "file_close_ret")


def pack_file_erase_req(shandle: int, name: str) -> bytes:
    return pack_supplementary_req(shandle, FileReq.ERASE, _latin1z(name))


def parse_file_erase_ret(data: bytes) -> int:
    return parse_trap_error_ret(data, "file_erase_ret")


def pack_file_string_to_fullpath_req(shandle: int, file_type: int, name: str) -> bytes:
    body = struct.pack("<B", file_type & 0xFF) + _latin1z(name)
    return pack_supplementary_req(shandle, FileReq.STRING_TO_FULLPATH, body)


def parse_file_string_to_fullpath_ret(data: bytes) -> StringResult:
    return _parse_error_prefixed_string(data, "file_string_to_fullpath_ret")


def pack_file_run_cmd_req(shandle: int, chk_size: int, command: str) -> bytes:
    body = struct.pack("<H", chk_size & 0xFFFF) + _latin1z(command)
    return pack_supplementary_req(shandle, FileReq.RUN_CMD, body)


def parse_file_run_cmd_ret(data: bytes) -> int:
    return parse_trap_error_ret(data, "file_run_cmd_ret")


def pack_file_info_get_date_req(shandle: int, name: str) -> bytes:
    return pack_supplementary_req(shandle, FileInfoReq.GET_DATE, _latin1z(name))


def parse_file_info_get_date_ret(data: bytes) -> FileDateResult:
    if len(data) < 8:
        raise _short("file_info_get_date_ret", need=8, got=len(data))
    err, date = struct.unpack_from("<Ii", data, 0)
    return FileDateResult(err=err, date=date)


def pack_file_info_set_date_req(shandle: int, date: int, name: str) -> bytes:
    body = struct.pack("<i", date) + _latin1z(name)
    return pack_supplementary_req(shandle, FileInfoReq.SET_DATE, body)


def parse_file_info_set_date_ret(data: bytes) -> int:
    return parse_trap_error_ret(data, "file_info_set_date_ret")


def pack_env_get_var_req(shandle: int, res_len: int, name: str) -> bytes:
    body = struct.pack("<I", res_len & 0xFFFFFFFF) + _latin1z(name)
    return pack_supplementary_req(shandle, EnvReq.GET_VAR, body)


def parse_env_get_var_ret(data: bytes) -> StringResult:
    return _parse_error_prefixed_string(data, "env_get_var_ret")


def pack_env_set_var_req(shandle: int, name: str, value: str) -> bytes:
    body = _latin1z(name) + _latin1z(value)
    return pack_supplementary_req(shandle, EnvReq.SET_VAR, body)


def parse_env_set_var_ret(data: bytes) -> int:
    return parse_trap_error_ret(data, "env_set_var_ret")


def pack_ovl_state_size_req(shandle: int) -> bytes:
    return pack_supplementary_req(shandle, OvlReq.STATE_SIZE)


def parse_ovl_state_size_ret(data: bytes) -> int:
    if len(data) < 2:
        raise _short("ovl_state_size_ret", need=2, got=len(data))
    return int(struct.unpack_from("<H", data, 0)[0])


def pack_ovl_get_data_req(shandle: int, sect_id: int) -> bytes:
    return pack_supplementary_req(shandle, OvlReq.GET_DATA, struct.pack("<H", sect_id & 0xFFFF))


def parse_ovl_get_data_ret(data: bytes) -> OvlGetDataResult:
    if len(data) < 6:
        raise _short("ovl_get_data_ret", need=6, got=len(data))
    segment, size = struct.unpack_from("<HI", data, 0)
    return OvlGetDataResult(segment=segment, size=size)


def pack_ovl_read_state_req(shandle: int) -> bytes:
    return pack_supplementary_req(shandle, OvlReq.READ_STATE)


def pack_ovl_write_state_req(shandle: int, data: bytes) -> bytes:
    return pack_supplementary_req(shandle, OvlReq.WRITE_STATE, data)


def pack_ovl_trans_vect_addr_req(shandle: int, ovl_addr: OvlAddress) -> bytes:
    return pack_supplementary_req(shandle, OvlReq.TRANS_VECT_ADDR, ovl_addr.pack())


def pack_ovl_trans_ret_addr_req(shandle: int, ovl_addr: OvlAddress) -> bytes:
    return pack_supplementary_req(shandle, OvlReq.TRANS_RET_ADDR, ovl_addr.pack())


def parse_ovl_trans_addr_ret(data: bytes) -> OvlAddress:
    if len(data) < OVL_ADDRESS_SIZE:
        raise _short("ovl_trans_addr_ret", need=OVL_ADDRESS_SIZE, got=len(data))
    return OvlAddress.unpack(data, 0)


def pack_ovl_get_remap_entry_req(shandle: int, ovl_addr: OvlAddress) -> bytes:
    return pack_supplementary_req(shandle, OvlReq.GET_REMAP_ENTRY, ovl_addr.pack())


def parse_ovl_get_remap_entry_ret(data: bytes) -> OvlRemapEntryResult:
    if len(data) < 1 + OVL_ADDRESS_SIZE:
        raise _short("ovl_get_remap_entry_ret", need=1 + OVL_ADDRESS_SIZE, got=len(data))
    return OvlRemapEntryResult(remapped=bool(data[0]), ovl_addr=OvlAddress.unpack(data, 1))


def pack_thread_get_next_req(shandle: int, thread: int) -> bytes:
    return pack_supplementary_req(
        shandle, ThreadReq.GET_NEXT, struct.pack("<I", thread & 0xFFFFFFFF)
    )


def parse_thread_get_next_ret(data: bytes) -> ThreadGetNextResult:
    if len(data) < 5:
        raise _short("thread_get_next_ret", need=5, got=len(data))
    thread, state = struct.unpack_from("<IB", data, 0)
    return ThreadGetNextResult(thread=thread, state=state)


def pack_thread_set_req(shandle: int, thread: int) -> bytes:
    return pack_supplementary_req(
        shandle, ThreadReq.SET, struct.pack("<I", thread & 0xFFFFFFFF)
    )


def parse_thread_set_ret(data: bytes) -> ThreadSetResult:
    if len(data) < 8:
        raise _short("thread_set_ret", need=8, got=len(data))
    err, old_thread = struct.unpack_from("<II", data, 0)
    return ThreadSetResult(err=err, old_thread=old_thread)


def pack_thread_freeze_req(shandle: int, thread: int) -> bytes:
    return pack_supplementary_req(
        shandle, ThreadReq.FREEZE, struct.pack("<I", thread & 0xFFFFFFFF)
    )


def parse_thread_freeze_ret(data: bytes) -> int:
    return parse_trap_error_ret(data, "thread_freeze_ret")


def pack_thread_thaw_req(shandle: int, thread: int) -> bytes:
    return pack_supplementary_req(
        shandle, ThreadReq.THAW, struct.pack("<I", thread & 0xFFFFFFFF)
    )


def parse_thread_thaw_ret(data: bytes) -> int:
    return parse_trap_error_ret(data, "thread_thaw_ret")


def pack_thread_get_extra_req(shandle: int, thread: int) -> bytes:
    return pack_supplementary_req(
        shandle, ThreadReq.GET_EXTRA, struct.pack("<I", thread & 0xFFFFFFFF)
    )


def parse_thread_get_extra_ret(data: bytes) -> str:
    return _c_string(data, 0)


def pack_run_thread_info_req(shandle: int, col: int) -> bytes:
    return pack_supplementary_req(shandle, RunThreadReq.INFO, struct.pack("<H", col & 0xFFFF))


def parse_run_thread_info_ret(data: bytes) -> RunThreadInfoResult:
    if len(data) < 3:
        raise _short("run_thread_info_ret", need=3, got=len(data))
    info, width = struct.unpack_from("<BH", data, 0)
    return RunThreadInfoResult(info=info, width=width, header=_c_string(data, 3))


def pack_run_thread_get_next_req(shandle: int, thread: int) -> bytes:
    return pack_supplementary_req(
        shandle, RunThreadReq.GET_NEXT, struct.pack("<I", thread & 0xFFFFFFFF)
    )


def parse_run_thread_get_next_ret(data: bytes) -> RunThreadGetNextResult:
    if len(data) < 4:
        raise _short("run_thread_get_next_ret", need=4, got=len(data))
    return RunThreadGetNextResult(thread=int(struct.unpack_from("<I", data, 0)[0]))


def pack_run_thread_get_runtime_req(shandle: int, thread: int) -> bytes:
    return pack_supplementary_req(
        shandle, RunThreadReq.GET_RUNTIME, struct.pack("<I", thread & 0xFFFFFFFF)
    )


def parse_run_thread_get_runtime_ret(data: bytes) -> RunThreadRuntimeResult:
    if len(data) < 7:
        raise _short("run_thread_get_runtime_ret", need=7, got=len(data))
    state, cs, eip = struct.unpack_from("<BHI", data, 0)
    return RunThreadRuntimeResult(state=state, cs=cs, eip=eip, extra=_c_string(data, 7))


def pack_run_thread_poll_req(shandle: int) -> bytes:
    return pack_supplementary_req(shandle, RunThreadReq.POLL)


def parse_run_thread_poll_ret(data: bytes) -> int:
    if len(data) < 2:
        raise _short("run_thread_poll_ret", need=2, got=len(data))
    return int(struct.unpack_from("<H", data, 0)[0])


def pack_run_thread_set_req(shandle: int, thread: int) -> bytes:
    return pack_supplementary_req(
        shandle, RunThreadReq.SET, struct.pack("<I", thread & 0xFFFFFFFF)
    )


def parse_run_thread_set_ret(data: bytes) -> RunThreadSetResult:
    if len(data) < 8:
        raise _short("run_thread_set_ret", need=8, got=len(data))
    err, old_thread = struct.unpack_from("<II", data, 0)
    return RunThreadSetResult(err=err, old_thread=old_thread)


def pack_run_thread_get_name_req(shandle: int, thread: int) -> bytes:
    return pack_supplementary_req(
        shandle, RunThreadReq.GET_NAME, struct.pack("<I", thread & 0xFFFFFFFF)
    )


def parse_run_thread_get_name_ret(data: bytes) -> str:
    return _c_string(data, 0)


def pack_run_thread_stop_req(shandle: int, thread: int) -> bytes:
    return pack_supplementary_req(
        shandle, RunThreadReq.STOP, struct.pack("<I", thread & 0xFFFFFFFF)
    )


def pack_run_thread_signal_stop_req(shandle: int, thread: int) -> bytes:
    return pack_supplementary_req(
        shandle, RunThreadReq.SIGNAL_STOP, struct.pack("<I", thread & 0xFFFFFFFF)
    )


def pack_rfx_rename_req(shandle: int, old_name: str, new_name: str) -> bytes:
    return pack_supplementary_req(
        shandle, RfxReq.RENAME, _latin1z(old_name) + _latin1z(new_name)
    )


def parse_rfx_rename_ret(data: bytes) -> int:
    return parse_trap_error_ret(data, "rfx_rename_ret")


def pack_rfx_mkdir_req(shandle: int, dirname: str) -> bytes:
    return pack_supplementary_req(shandle, RfxReq.MKDIR, _latin1z(dirname))


def parse_rfx_mkdir_ret(data: bytes) -> int:
    return parse_trap_error_ret(data, "rfx_mkdir_ret")


def pack_rfx_rmdir_req(shandle: int, dirname: str) -> bytes:
    return pack_supplementary_req(shandle, RfxReq.RMDIR, _latin1z(dirname))


def parse_rfx_rmdir_ret(data: bytes) -> int:
    return parse_trap_error_ret(data, "rfx_rmdir_ret")


def pack_rfx_setdrive_req(shandle: int, drive: int) -> bytes:
    return pack_supplementary_req(shandle, RfxReq.SETDRIVE, struct.pack("<B", drive & 0xFF))


def parse_rfx_setdrive_ret(data: bytes) -> int:
    return parse_trap_error_ret(data, "rfx_setdrive_ret")


def pack_rfx_getdrive_req(shandle: int) -> bytes:
    return pack_supplementary_req(shandle, RfxReq.GETDRIVE)


def parse_rfx_getdrive_ret(data: bytes) -> int:
    if len(data) < 1:
        raise _short("rfx_getdrive_ret", need=1, got=len(data))
    return int(data[0])


def pack_rfx_setcwd_req(shandle: int, cwd: str) -> bytes:
    return pack_supplementary_req(shandle, RfxReq.SETCWD, _latin1z(cwd))


def parse_rfx_setcwd_ret(data: bytes) -> int:
    return parse_trap_error_ret(data, "rfx_setcwd_ret")


def pack_rfx_getcwd_req(shandle: int, drive: int) -> bytes:
    return pack_supplementary_req(shandle, RfxReq.GETCWD, struct.pack("<B", drive & 0xFF))


def parse_rfx_getcwd_ret(data: bytes) -> StringResult:
    return _parse_error_prefixed_string(data, "rfx_getcwd_ret")


def pack_rfx_setdatetime_req(shandle: int, handle: int, time: int) -> bytes:
    body = struct.pack("<QI", handle & 0xFFFFFFFFFFFFFFFF, time & 0xFFFFFFFF)
    return pack_supplementary_req(shandle, RfxReq.SETDATETIME, body)


def pack_rfx_getdatetime_req(shandle: int, handle: int) -> bytes:
    return pack_supplementary_req(
        shandle, RfxReq.GETDATETIME, struct.pack("<Q", handle & 0xFFFFFFFFFFFFFFFF)
    )


def parse_rfx_getdatetime_ret(data: bytes) -> int:
    if len(data) < 4:
        raise _short("rfx_getdatetime_ret", need=4, got=len(data))
    return int(struct.unpack_from("<I", data, 0)[0])


def pack_rfx_getfreespace_req(shandle: int, drive: int) -> bytes:
    return pack_supplementary_req(shandle, RfxReq.GETFREESPACE, struct.pack("<B", drive & 0xFF))


def parse_rfx_getfreespace_ret(data: bytes) -> int:
    if len(data) < 4:
        raise _short("rfx_getfreespace_ret", need=4, got=len(data))
    return int(struct.unpack_from("<I", data, 0)[0])


def pack_rfx_setfileattr_req(shandle: int, attribute: int, name: str) -> bytes:
    body = struct.pack("<I", attribute & 0xFFFFFFFF) + _latin1z(name)
    return pack_supplementary_req(shandle, RfxReq.SETFILEATTR, body)


def parse_rfx_setfileattr_ret(data: bytes) -> int:
    return parse_trap_error_ret(data, "rfx_setfileattr_ret")


def pack_rfx_getfileattr_req(shandle: int, name: str) -> bytes:
    return pack_supplementary_req(shandle, RfxReq.GETFILEATTR, _latin1z(name))


def parse_rfx_getfileattr_ret(data: bytes) -> int:
    if len(data) < 4:
        raise _short("rfx_getfileattr_ret", need=4, got=len(data))
    return int(struct.unpack_from("<I", data, 0)[0])


def pack_rfx_nametocanonical_req(shandle: int, name: str) -> bytes:
    return pack_supplementary_req(shandle, RfxReq.NAMETOCANONICAL, _latin1z(name))


def parse_rfx_nametocanonical_ret(data: bytes) -> StringResult:
    return _parse_error_prefixed_string(data, "rfx_nametocanonical_ret")


def parse_rfx_find(data: bytes, pos: int = 0) -> RfxFindResult:
    need = pos + RFX_FIND_FIXED_SIZE
    if len(data) < need:
        raise _short("rfx_find", need=need, got=len(data))
    reserved = data[pos : pos + RFX_FIND_RESERVED_SIZE]
    attr, time, date, size = struct.unpack_from("<BHHI", data, pos + RFX_FIND_RESERVED_SIZE)
    name = _c_string(data, pos + RFX_FIND_FIXED_SIZE)
    return RfxFindResult(reserved=reserved, attr=attr, time=time, date=date, size=size, name=name)


def pack_rfx_findfirst_req(shandle: int, attrib: int, pattern: str) -> bytes:
    body = struct.pack("<B", attrib & 0xFF) + _latin1z(pattern)
    return pack_supplementary_req(shandle, RfxReq.FINDFIRST, body)


def parse_rfx_findfirst_ret(data: bytes) -> RfxFindReply:
    err = parse_trap_error_ret(data, "rfx_findfirst_ret")
    info = parse_rfx_find(data, 4) if err == 0 else None
    return RfxFindReply(err=err, info=info)


def pack_rfx_findnext_req(shandle: int, info: RfxFindResult) -> bytes:
    return pack_supplementary_req(shandle, RfxReq.FINDNEXT, info.pack())


def parse_rfx_findnext_ret(data: bytes) -> RfxFindReply:
    err = parse_trap_error_ret(data, "rfx_findnext_ret")
    info = parse_rfx_find(data, 4) if err == 0 else None
    return RfxFindReply(err=err, info=info)


def pack_rfx_findclose_req(shandle: int, info: RfxFindResult) -> bytes:
    return pack_supplementary_req(shandle, RfxReq.FINDCLOSE, info.pack())


def parse_rfx_findclose_ret(data: bytes) -> int:
    return parse_trap_error_ret(data, "rfx_findclose_ret")


def pack_capabilities_get_exact_bp_req(shandle: int) -> bytes:
    return pack_supplementary_req(shandle, CapabilitiesReq.GET_EXACT_BP)


def parse_capabilities_get_exact_bp_ret(data: bytes) -> ExactBreakpointSupport:
    if len(data) < 5:
        raise _short("capabilities_get_exact_bp_ret", need=5, got=len(data))
    err, status = struct.unpack_from("<IB", data, 0)
    return ExactBreakpointSupport(err=err, status=status)


def pack_capabilities_set_exact_bp_req(shandle: int, status: int) -> bytes:
    return pack_supplementary_req(
        shandle, CapabilitiesReq.SET_EXACT_BP, struct.pack("<B", status & 0xFF)
    )


def parse_capabilities_set_exact_bp_ret(data: bytes) -> ExactBreakpointSupport:
    if len(data) < 5:
        raise _short("capabilities_set_exact_bp_ret", need=5, got=len(data))
    err, ret_status = struct.unpack_from("<IB", data, 0)
    return ExactBreakpointSupport(err=err, status=ret_status)


def pack_async_go_req(shandle: int) -> bytes:
    return pack_supplementary_req(shandle, AsyncReq.GO)


def pack_async_step_req(shandle: int) -> bytes:
    return pack_supplementary_req(shandle, AsyncReq.STEP)


def pack_async_poll_req(shandle: int) -> bytes:
    return pack_supplementary_req(shandle, AsyncReq.POLL)


def pack_async_stop_req(shandle: int) -> bytes:
    return pack_supplementary_req(shandle, AsyncReq.STOP)


def parse_async_ret(data: bytes) -> ProgGoResult:
    return parse_prog_go_ret(data)


def pack_async_add_break_req(shandle: int, break_addr: Addr48, local: bool) -> bytes:
    body = break_addr.pack() + struct.pack("<B", 1 if local else 0)
    return pack_supplementary_req(shandle, AsyncReq.ADD_BREAK, body)


def pack_async_remove_break_req(shandle: int, break_addr: Addr48, local: bool) -> bytes:
    body = break_addr.pack() + struct.pack("<B", 1 if local else 0)
    return pack_supplementary_req(shandle, AsyncReq.REMOVE_BREAK, body)


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


# --- MAP_ADDR / CHECKSUM_MEM ------------------------------------------------


@dataclass(frozen=True, slots=True)
class MapAddrResult:
    out_addr: Addr48
    lo_bound: int
    hi_bound: int


def pack_map_addr_req(in_addr: Addr48, mod_handle: int) -> bytes:
    return bytes([Req.MAP_ADDR]) + in_addr.pack() + struct.pack("<I", mod_handle & 0xFFFFFFFF)


def parse_map_addr_ret(data: bytes) -> MapAddrResult:
    if len(data) < 14:
        raise _short("map_addr_ret", need=14, got=len(data))
    out_addr = Addr48.unpack(data, 0)
    lo_bound, hi_bound = struct.unpack_from("<II", data, ADDR48_SIZE)
    return MapAddrResult(out_addr=out_addr, lo_bound=lo_bound, hi_bound=hi_bound)


def pack_checksum_mem_req(addr: Addr48, length: int) -> bytes:
    return bytes([Req.CHECKSUM_MEM]) + addr.pack() + struct.pack("<H", length & 0xFFFF)


def parse_checksum_mem_ret(data: bytes) -> int:
    if len(data) < 4:
        raise _short("checksum_mem_ret", need=4, got=len(data))
    (checksum,) = struct.unpack_from("<I", data, 0)
    return int(checksum)


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


# --- READ_IO / WRITE_IO -----------------------------------------------------


def pack_read_io_req(io_offset: int, length: int) -> bytes:
    if not 0 <= length <= 0xFF:
        raise ValueError(f"READ_IO length must fit in u8, got {length}")
    return bytes([Req.READ_IO]) + struct.pack("<IB", io_offset & 0xFFFFFFFF, length)


def pack_write_io_req(io_offset: int, data: bytes) -> bytes:
    if len(data) > 0xFF:
        raise ValueError(f"WRITE_IO data length must fit in u8, got {len(data)}")
    return bytes([Req.WRITE_IO]) + struct.pack("<I", io_offset & 0xFFFFFFFF) + data


def parse_write_io_ret(data: bytes) -> int:
    if len(data) < 1:
        raise _short("write_io_ret", need=1, got=len(data))
    return int(data[0])


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


# --- SET_WATCH / CLEAR_WATCH ------------------------------------------------


def _validate_watch_size(size: int) -> None:
    if size not in {1, 2, 4}:
        raise ValueError(f"watch size must be one of 1, 2, 4 bytes, got {size}")


@dataclass(frozen=True, slots=True)
class SetWatchResult:
    err: int
    multiplier: int


def pack_set_watch_req(addr: Addr48, size: int) -> bytes:
    _validate_watch_size(size)
    return bytes([Req.SET_WATCH]) + addr.pack() + struct.pack("<B", size)


def parse_set_watch_ret(data: bytes) -> SetWatchResult:
    if len(data) < 8:
        raise _short("set_watch_ret", need=8, got=len(data))
    err, multiplier = struct.unpack_from("<II", data, 0)
    return SetWatchResult(err=err, multiplier=multiplier)


def pack_clear_watch_req(addr: Addr48, size: int) -> bytes:
    _validate_watch_size(size)
    return bytes([Req.CLEAR_WATCH]) + addr.pack() + struct.pack("<B", size)


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


# --- GET_NEXT_ALIAS / SCREEN / KEYBOARD / LIB / REDIRECT / SPLIT -----------+


@dataclass(frozen=True, slots=True)
class AliasResult:
    seg: int
    alias: int


def pack_get_next_alias_req(seg: int) -> bytes:
    return bytes([Req.GET_NEXT_ALIAS]) + struct.pack("<H", seg & 0xFFFF)


def parse_get_next_alias_ret(data: bytes) -> AliasResult:
    if len(data) < 4:
        raise _short("get_next_alias_ret", need=4, got=len(data))
    seg, alias = struct.unpack_from("<HH", data, 0)
    return AliasResult(seg=seg, alias=alias)


def pack_set_user_screen_req() -> bytes:
    return bytes([Req.SET_USER_SCREEN])


def pack_set_debug_screen_req() -> bytes:
    return bytes([Req.SET_DEBUG_SCREEN])


def pack_read_user_keyboard_req(wait_ms: int) -> bytes:
    return bytes([Req.READ_USER_KEYBOARD]) + struct.pack("<H", wait_ms & 0xFFFF)


def parse_read_user_keyboard_ret(data: bytes) -> int:
    if len(data) < 1:
        raise _short("read_user_keyboard_ret", need=1, got=len(data))
    return int(data[0])


@dataclass(frozen=True, slots=True)
class LibNameResult:
    mod_handle: int
    name: str


def pack_get_lib_name_req(mod_handle: int) -> bytes:
    return bytes([Req.GET_LIB_NAME]) + struct.pack("<I", mod_handle & 0xFFFFFFFF)


def parse_get_lib_name_ret(data: bytes) -> LibNameResult:
    if len(data) < 4:
        raise _short("get_lib_name_ret", need=4, got=len(data))
    (mod_handle,) = struct.unpack_from("<I", data, 0)
    return LibNameResult(mod_handle=mod_handle, name=_c_string(data, 4))


def pack_redirect_stdin_req(filename: str) -> bytes:
    return bytes([Req.REDIRECT_STDIN]) + _latin1(filename) + b"\x00"


def pack_redirect_stdout_req(filename: str) -> bytes:
    return bytes([Req.REDIRECT_STDOUT]) + _latin1(filename) + b"\x00"


def parse_redirect_stdio_ret(data: bytes) -> int:
    if len(data) < 4:
        raise _short("redirect_stdio_ret", need=4, got=len(data))
    (err,) = struct.unpack_from("<I", data, 0)
    return int(err)


@dataclass(frozen=True, slots=True)
class SplitCmdResult:
    cmd_end: int
    parm_start: int


def pack_split_cmd_req(command: str) -> bytes:
    return bytes([Req.SPLIT_CMD]) + _latin1(command) + b"\x00"


def parse_split_cmd_ret(data: bytes) -> SplitCmdResult:
    if len(data) < 4:
        raise _short("split_cmd_ret", need=4, got=len(data))
    cmd_end, parm_start = struct.unpack_from("<HH", data, 0)
    return SplitCmdResult(cmd_end=cmd_end, parm_start=parm_start)


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


# --- MACHINE_DATA -----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MachineDataResult:
    cache_start: int
    cache_end: int
    extra: bytes


def pack_machine_data_req(info_type: int, addr: Addr48, extra: bytes = b"") -> bytes:
    return bytes([Req.MACHINE_DATA, info_type & 0xFF]) + addr.pack() + extra


def parse_machine_data_ret(data: bytes) -> MachineDataResult:
    if len(data) < 8:
        raise _short("machine_data_ret", need=8, got=len(data))
    cache_start, cache_end = struct.unpack_from("<II", data, 0)
    return MachineDataResult(cache_start=cache_start, cache_end=cache_end, extra=data[8:])


# --- error helpers ---------------------------------------------------------


def _short(label: str, *, need: int, got: int) -> Exception:
    from .errors import ProtocolError

    msg = f"{label}: reply too short (need {need} bytes, got {got})"
    if label == "prog_go_ret" and got == 0:
        msg += " — possible target state corruption (e.g. prior mem op on seg=0 without flat-mode)"
    return ProtocolError(msg)
