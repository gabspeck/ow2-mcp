from __future__ import annotations

import pytest

from ow2_mcp import protocol as p
from ow2_mcp import server


class _FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object, object]] = []

    async def prog_load(self, argv: list[str], true_argv: bool = False) -> p.ProgLoadResult:
        self.calls.append(("load", list(argv), true_argv))
        return p.ProgLoadResult(
            err=0,
            task_id=0x1234,
            mod_handle=0x5678,
            flags=int(p.LoadFlag.IS_STARTED),
        )

    async def prog_attach(self, pid: int, hex_format: bool = True) -> p.ProgLoadResult:
        self.calls.append(("attach", pid, hex_format))
        return p.ProgLoadResult(
            err=0,
            task_id=0xABCD,
            mod_handle=0x2468,
            flags=int(p.LoadFlag.IS_STARTED),
        )

    async def prog_go(self, timeout: float | None = None) -> p.ProgGoResult:
        self.calls.append(("go", timeout, None))
        return p.ProgGoResult(
            stack_pointer=p.Addr48(offset=0x1111, segment=0x22),
            program_counter=p.Addr48(offset=0x3333, segment=0x44),
            conditions=int(p.Cond.BREAK | p.Cond.STOP),
        )


async def test_trap_prog_load_validates_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient()
    monkeypatch.setattr(server, "_client", fake)

    result = await server.trap_prog_load([])

    assert result["ok"] is False
    assert result["error"]["code"] == "protocol_error"
    assert "argv must not be empty" in result["error"]["message"]
    assert fake.calls == []


async def test_trap_prog_load_forwards_argv_and_returns_load_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeClient()
    monkeypatch.setattr(server, "_client", fake)

    result = await server.trap_prog_load(["hello.exe", "arg1", "arg2"], true_argv=True)

    assert result == {
        "ok": True,
        "err": 0,
        "task_id": 0x1234,
        "mod_handle": 0x5678,
        "flags": int(p.LoadFlag.IS_STARTED),
        "load_flag_names": ["IS_STARTED"],
    }
    assert fake.calls == [("load", ["hello.exe", "arg1", "arg2"], True)]


async def test_trap_prog_attach_returns_same_shape_as_prog_load(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeClient()
    monkeypatch.setattr(server, "_client", fake)

    result = await server.trap_prog_attach(0xFFF09CBF)

    assert result == {
        "ok": True,
        "err": 0,
        "task_id": 0xABCD,
        "mod_handle": 0x2468,
        "flags": int(p.LoadFlag.IS_STARTED),
        "load_flag_names": ["IS_STARTED"],
    }
    assert fake.calls == [("attach", 0xFFF09CBF, True)]


async def test_trap_prog_attach_accepts_hex_string_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeClient()
    monkeypatch.setattr(server, "_client", fake)

    result = await server.trap_prog_attach("FFFE9DD7")

    assert result["ok"] is True
    assert fake.calls == [("attach", 0xFFFE9DD7, True)]


async def test_trap_prog_attach_accepts_prefixed_hex_string_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeClient()
    monkeypatch.setattr(server, "_client", fake)

    result = await server.trap_prog_attach("#FFFE9DD7")

    assert result["ok"] is True
    assert fake.calls == [("attach", 0xFFFE9DD7, True)]


async def test_trap_prog_attach_rejects_invalid_pid_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeClient()
    monkeypatch.setattr(server, "_client", fake)

    result = await server.trap_prog_attach("xyz")

    assert result["ok"] is False
    assert result["error"]["code"] == "protocol_error"
    assert "invalid pid" in result["error"]["message"]
    assert fake.calls == []


async def test_trap_prog_go_forwards_timeout_ms(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient()
    monkeypatch.setattr(server, "_client", fake)

    result = await server.trap_prog_go(timeout_ms=250)

    assert result["ok"] is True
    assert result["conditions"] == ["BREAK", "STOP"]
    assert fake.calls == [("go", 0.25, None)]


async def test_trap_prog_go_rejects_non_positive_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient()
    monkeypatch.setattr(server, "_client", fake)

    result = await server.trap_prog_go(timeout_ms=0)

    assert result["ok"] is False
    assert result["error"]["code"] == "protocol_error"
    assert "timeout_ms must be > 0 or None" in result["error"]["message"]
    assert fake.calls == []
