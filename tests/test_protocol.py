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


def test_pack_suspend_and_resume_req_shape() -> None:
    assert p.pack_suspend_req() == b"\x02"
    assert p.pack_resume_req() == b"\x03"


def test_get_supplementary_service_round_trip() -> None:
    assert p.pack_get_supplementary_service_req("files") == b"\x04files\x00"
    result = p.parse_get_supplementary_service_ret(b"\x00\x00\x00\x00\x34\x12\x00\x00")
    assert result == p.SupplementaryServiceResult(err=0, shandle=0x1234)


def test_perform_supplementary_service_req_shape() -> None:
    req = p.pack_perform_supplementary_service_req(0x11223344, b"\xaa\xbb")
    assert req == b"\x05\x44\x33\x22\x11\xaa\xbb"


def test_pack_map_addr_req_and_parse_reply() -> None:
    req = p.pack_map_addr_req(Addr48(offset=0x12345678, segment=0x9ABC), 0x01020304)
    assert req == b"\x07\x78\x56\x34\x12\xbc\x9a\x04\x03\x02\x01"
    reply = b"\x00\x10\x00\x00\x23\x00\x11\x11\x11\x11\x22\x22\x22\x22"
    result = p.parse_map_addr_ret(reply)
    assert result.out_addr == Addr48(offset=0x1000, segment=0x0023)
    assert result.lo_bound == 0x11111111
    assert result.hi_bound == 0x22222222


def test_map_flat_selector_constants() -> None:
    assert p.MAP_FLAT_CODE_SELECTOR == 0xFFFF
    assert p.MAP_FLAT_DATA_SELECTOR == 0xFFFE


def test_pack_checksum_mem_req_and_parse_reply() -> None:
    req = p.pack_checksum_mem_req(Addr48(offset=0x1000, segment=0x0023), 0x0040)
    assert req == b"\x08\x00\x10\x00\x00\x23\x00\x40\x00"
    assert p.parse_checksum_mem_ret(b"\xef\xbe\xad\xde") == 0xDEADBEEF


def test_pack_read_io_req_and_write_io_round_trip() -> None:
    assert p.pack_read_io_req(0x3F8, 4) == b"\x0b\xf8\x03\x00\x00\x04"
    assert p.pack_write_io_req(0x3F8, b"\xaa\x55") == b"\x0c\xf8\x03\x00\x00\xaa\x55"
    assert p.parse_write_io_ret(b"\x02") == 2


def test_pack_set_watch_and_clear_watch_round_trip() -> None:
    set_req = p.pack_set_watch_req(Addr48(offset=0x2000, segment=0x0023), 4)
    clear_req = p.pack_clear_watch_req(Addr48(offset=0x2000, segment=0x0023), 4)
    assert set_req == b"\x11\x00\x20\x00\x00\x23\x00\x04"
    assert clear_req == b"\x12\x00\x20\x00\x00\x23\x00\x04"
    result = p.parse_set_watch_ret(b"\x01\x00\x00\x00\x04\x00\x00\x00")
    assert result == p.SetWatchResult(err=1, multiplier=4)


def test_alias_screen_keyboard_lib_redirect_split_and_machine_data_round_trip() -> None:
    assert p.pack_get_next_alias_req(0x1234) == b"\x15\x34\x12"
    assert p.parse_get_next_alias_ret(b"\x34\x12\x78\x56") == p.AliasResult(0x1234, 0x5678)
    assert p.pack_set_user_screen_req() == b"\x16"
    assert p.pack_set_debug_screen_req() == b"\x17"
    assert p.pack_read_user_keyboard_req(250) == b"\x18\xfa\x00"
    assert p.parse_read_user_keyboard_ret(b"A") == 0x41
    assert p.pack_get_lib_name_req(0x1234) == b"\x19\x34\x12\x00\x00"
    assert p.parse_get_lib_name_ret(b"\x78\x56\x00\x00watcom.dll\x00") == p.LibNameResult(
        mod_handle=0x5678, name="watcom.dll"
    )
    assert p.pack_redirect_stdin_req("input.txt") == b"\x1cinput.txt\x00"
    assert p.pack_redirect_stdout_req("output.txt") == b"\x1doutput.txt\x00"
    assert p.parse_redirect_stdio_ret(b"\x05\x00\x00\x00") == 5
    assert p.pack_split_cmd_req("prog arg") == b"\x1eprog arg\x00"
    assert p.parse_split_cmd_ret(b"\x04\x00\x05\x00") == p.SplitCmdResult(4, 5)
    assert p.pack_machine_data_req(2, Addr48(offset=0x3000, segment=0x0023), b"\xaa") == (
        b"\x21\x02\x00\x30\x00\x00\x23\x00\xaa"
    )
    assert p.parse_machine_data_ret(b"\x00\x10\x00\x00\x00\x20\x00\x00\xde\xad") == (
        p.MachineDataResult(cache_start=0x1000, cache_end=0x2000, extra=b"\xde\xad")
    )


def test_supplementary_file_env_overlay_and_async_round_trip() -> None:
    assert p.pack_supplementary_req(0x1234, p.FileReq.GET_CONFIG) == b"\x05\x34\x12\x00\x00\x00"
    assert p.parse_file_get_config_ret(b".:\\/\r\n;") == p.FileComponents(
        ".", ":", "\\/", "\r\n", ";"
    )
    assert p.pack_file_open_req(0x1234, 2, "autoexec.bat") == (
        b"\x05\x34\x12\x00\x00\x01\x02autoexec.bat\x00"
    )
    assert p.parse_file_open_ret(b"\x00\x00\x00\x00" + b"\x78\x56\x34\x12\x00\x00\x00\x00") == (
        p.FileOpenResult(err=0, handle=0x12345678)
    )
    assert p.parse_file_read_ret(b"\x00\x00\x00\x00abc") == p.FileReadResult(err=0, data=b"abc")
    assert p.parse_env_get_var_ret(b"\x00\x00\x00\x00PATH=C:\\OW2\x00") == p.StringResult(
        err=0, value="PATH=C:\\OW2"
    )
    ovl = p.OvlAddress(mach=Addr48(offset=0x1000, segment=0x23), sect_id=7)
    assert p.pack_ovl_trans_vect_addr_req(0x55, ovl) == (
        b"\x05\x55\x00\x00\x00\x04\x00\x10\x00\x00\x23\x00\x07\x00"
    )
    assert p.parse_ovl_get_remap_entry_ret(
        b"\x01\x78\x56\x34\x12\x9a\x00\x05\x00"
    ) == p.OvlRemapEntryResult(
        remapped=True,
        ovl_addr=p.OvlAddress(mach=Addr48(offset=0x12345678, segment=0x009A), sect_id=5),
    )
    assert p.parse_async_ret(
        b"\x44\x33\x22\x11\x01\x00\x88\x77\x66\x55\x02\x00\x80\x20"
    ) == p.ProgGoResult(
        stack_pointer=Addr48(offset=0x11223344, segment=1),
        program_counter=Addr48(offset=0x55667788, segment=2),
        conditions=p.Cond.BREAK | p.Cond.STOP,
    )


def test_thread_runthread_rfx_and_capability_round_trip() -> None:
    assert p.parse_thread_get_next_ret(b"\x34\x12\x00\x00\x01") == p.ThreadGetNextResult(
        thread=0x1234, state=p.ThreadState.FROZEN
    )
    assert p.parse_run_thread_info_ret(b"\x03\x10\x00CS:EIP\x00") == p.RunThreadInfoResult(
        info=p.RunThreadInfoType.CS_EIP, width=16, header="CS:EIP"
    )
    assert p.parse_run_thread_get_runtime_ret(b"\x00\x1b\x00\x78\x56\x34\x12ready\x00") == (
        p.RunThreadRuntimeResult(state=0, cs=0x001B, eip=0x12345678, extra="ready")
    )
    find = p.parse_rfx_find(
        b"\x00" * 21 + b"\x20" + b"\x34\x12" + b"\x78\x56" + b"\xef\xcd\xab\x89" + b"kernel.exe\x00"
    )
    assert find.attr == 0x20
    assert find.time == 0x1234
    assert find.date == 0x5678
    assert find.size == 0x89ABCDEF
    assert find.name == "kernel.exe"
    assert p.parse_capabilities_get_exact_bp_ret(b"\x00\x00\x00\x00\x01") == (
        p.ExactBreakpointSupport(err=0, status=1)
    )


@pytest.mark.parametrize(
    ("parser", "payload", "label"),
    [
        (p.parse_get_supplementary_service_ret, b"\x00" * 7, "get_supplementary_service_ret"),
        (p.parse_map_addr_ret, b"\x00" * 13, "map_addr_ret"),
        (p.parse_checksum_mem_ret, b"\x00" * 3, "checksum_mem_ret"),
        (p.parse_write_io_ret, b"", "write_io_ret"),
        (p.parse_set_watch_ret, b"\x00" * 7, "set_watch_ret"),
        (p.parse_get_next_alias_ret, b"\x00" * 3, "get_next_alias_ret"),
        (p.parse_read_user_keyboard_ret, b"", "read_user_keyboard_ret"),
        (p.parse_get_lib_name_ret, b"\x00" * 3, "get_lib_name_ret"),
        (p.parse_redirect_stdio_ret, b"\x00" * 3, "redirect_stdio_ret"),
        (p.parse_split_cmd_ret, b"\x00" * 3, "split_cmd_ret"),
        (p.parse_machine_data_ret, b"\x00" * 7, "machine_data_ret"),
    ],
)
def test_new_parsers_reject_short_replies(parser: object, payload: bytes, label: str) -> None:
    with pytest.raises(ProtocolError, match=label):
        parser(payload)  # type: ignore[misc]


def test_read_io_length_validation() -> None:
    with pytest.raises(ValueError, match="READ_IO length"):
        p.pack_read_io_req(0x3F8, 256)


def test_write_io_length_validation() -> None:
    with pytest.raises(ValueError, match="WRITE_IO data length"):
        p.pack_write_io_req(0x3F8, b"\x00" * 256)


def test_watch_size_validation() -> None:
    with pytest.raises(ValueError, match="watch size"):
        p.pack_set_watch_req(Addr48(offset=0, segment=0), 3)
    with pytest.raises(ValueError, match="watch size"):
        p.pack_clear_watch_req(Addr48(offset=0, segment=0), 8)


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
