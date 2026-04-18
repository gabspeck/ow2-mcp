"""Round-trip tests for every supported pack/parse pair."""

from __future__ import annotations

import pytest

from ow2_mcp import protocol as p
from ow2_mcp.errors import ProtocolError
from ow2_mcp.protocol import Addr48, Cond, LoadFlag, MsgFlag, Req


def test_req_codes_match_trpreq_h() -> None:
    """REQ numbers must match the order in ``bld/dig/h/_trpreq.h``."""
    assert Req.CONNECT == 0
    assert Req.DISCONNECT == 1
    assert Req.GET_SYS_CONFIG == 6
    assert Req.READ_MEM == 9
    assert Req.WRITE_MEM == 10
    assert Req.PROG_GO == 13
    assert Req.PROG_STEP == 14
    assert Req.PROG_LOAD == 15
    assert Req.PROG_KILL == 16
    assert Req.SET_BREAK == 19
    assert Req.CLEAR_BREAK == 20
    assert Req.GET_ERR_TEXT == 26
    assert Req.GET_MESSAGE_TEXT == 27
    assert Req.READ_REGS == 31
    assert Req.WRITE_REGS == 32


def test_addr48_roundtrip() -> None:
    addr = Addr48(offset=0xDEADBEEF, segment=0x1234)
    packed = addr.pack()
    assert packed == b"\xef\xbe\xad\xde\x34\x12"
    assert Addr48.unpack(packed) == addr


def test_pack_connect_req_matches_plan() -> None:
    assert p.pack_connect_req() == b"\x00\x12\x00\x00"


def test_parse_connect_ret_success() -> None:
    max_size, err = p.parse_connect_ret(b"\x00\x04\x00")  # 1024 little-endian, empty err
    assert max_size == 1024
    assert err == ""


def test_parse_connect_ret_with_error_message() -> None:
    payload = b"\x00\x04" + b"permission denied\x00"
    max_size, err = p.parse_connect_ret(payload)
    assert max_size == 1024
    assert err == "permission denied"


def test_parse_connect_ret_too_short() -> None:
    with pytest.raises(ProtocolError):
        p.parse_connect_ret(b"\x00")


def test_pack_prog_load_req_canonical() -> None:
    assert p.pack_prog_load_req("a.out", "hi") == b"\x0f\x00a.out\x00hi\x00"


def test_pack_prog_load_req_empty_is_4_bytes() -> None:
    """Empty program and args still emit both NUL terminators."""
    assert p.pack_prog_load_req("", "") == b"\x0f\x00\x00\x00"


def test_pack_prog_load_req_true_argv_flag() -> None:
    assert p.pack_prog_load_req("x", "", true_argv=True) == b"\x0f\x01x\x00\x00"


def test_pack_read_mem_req_shape() -> None:
    req = p.pack_read_mem_req(Addr48(offset=0x1000, segment=0), length=16)
    # [req=9][offset u32=0x1000][seg u16=0][len u16=16]
    assert req == b"\x09\x00\x10\x00\x00\x00\x00\x10\x00"


def test_pack_write_mem_req_shape() -> None:
    req = p.pack_write_mem_req(Addr48(offset=0, segment=0), b"\xaa\xbb")
    assert req == b"\x0a\x00\x00\x00\x00\x00\x00\xaa\xbb"


def test_parse_write_mem_ret() -> None:
    assert p.parse_write_mem_ret(b"\x40\x00") == 64


def test_pack_set_break_req_shape() -> None:
    req = p.pack_set_break_req(Addr48(offset=0x12345678, segment=0x9ABC))
    assert req == b"\x13\x78\x56\x34\x12\xbc\x9a"


def test_parse_set_break_ret() -> None:
    assert p.parse_set_break_ret(b"\xcc\x00\x00\x00") == 0xCC


def test_pack_clear_break_req_shape() -> None:
    req = p.pack_clear_break_req(Addr48(offset=0x1000, segment=0), old=0xDEADBEEF)
    assert req == b"\x14\x00\x10\x00\x00\x00\x00\xef\xbe\xad\xde"


def test_pack_prog_kill_req_shape() -> None:
    assert p.pack_prog_kill_req(0x42) == b"\x10\x42\x00\x00\x00"


def test_parse_prog_kill_ret() -> None:
    assert p.parse_prog_kill_ret(b"\x00\x00\x00\x00") == 0
    assert p.parse_prog_kill_ret(b"\x05\x00\x00\x00") == 5


def test_parse_prog_go_ret_decodes_fields() -> None:
    # SP=0x11223344:0x0001, PC=0x55667788:0x0002, cond=BREAK|STOP=0x2080
    buf = (
        b"\x44\x33\x22\x11\x01\x00"  # SP: offset LE, segment LE
        b"\x88\x77\x66\x55\x02\x00"  # PC
        b"\x80\x20"                  # conditions
    )
    result = p.parse_prog_go_ret(buf)
    assert result.stack_pointer == Addr48(offset=0x11223344, segment=1)
    assert result.program_counter == Addr48(offset=0x55667788, segment=2)
    assert result.conditions == (Cond.BREAK | Cond.STOP)


def test_parse_prog_load_ret_decodes_fields() -> None:
    # err=0, task=0x10, mod=0x20, flags=0x04 (IS_STARTED)
    buf = b"\x00\x00\x00\x00" + b"\x10\x00\x00\x00" + b"\x20\x00\x00\x00" + b"\x04"
    result = p.parse_prog_load_ret(buf)
    assert result.err == 0
    assert result.task_id == 0x10
    assert result.mod_handle == 0x20
    assert result.flags == LoadFlag.IS_STARTED


def test_parse_get_sys_config_ret() -> None:
    buf = b"\x05\x02\x00\x01\x0D\x00\x01"  # DIG_OS_LINUX=13, DIG_ARCH_X86=1
    cfg = p.parse_get_sys_config_ret(buf)
    assert cfg.cpu == 5
    assert cfg.fpu == 2
    assert cfg.os == 13
    assert cfg.arch == 1
    assert p.os_name(cfg.os) == "Linux"
    assert p.arch_name(cfg.arch) == "X86"


def test_parse_get_err_text_ret_strips_trailing_nul() -> None:
    assert p.parse_get_err_text_ret(b"no such file\x00") == "no such file"


def test_parse_get_message_text_ret() -> None:
    # flags=NEWLINE|ERROR=0x09
    msg = p.parse_get_message_text_ret(b"\x09halt\x00")
    assert msg.flags == (MsgFlag.NEWLINE | MsgFlag.ERROR)
    assert msg.text == "halt"


def test_decode_conditions() -> None:
    assert p.decode_conditions(Cond.BREAK | Cond.STOP) == ["BREAK", "STOP"]
    assert p.decode_conditions(0) == []
    assert p.decode_conditions(Cond.RUNNING) == ["RUNNING"]


def test_decode_load_flags() -> None:
    assert p.decode_load_flags(LoadFlag.IS_BIG | LoadFlag.IS_PROT) == ["IS_BIG", "IS_PROT"]


def test_decode_msg_flags() -> None:
    assert p.decode_msg_flags(MsgFlag.WARNING) == ["WARNING"]


def test_arch_and_os_names_fall_back_on_unknown() -> None:
    assert "unknown" in p.arch_name(99)
    assert "unknown" in p.os_name(99)
