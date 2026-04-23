# ow2-mcp

MCP server that speaks the **OpenWatcom TRAP protocol** over TCP, letting an
LLM drive a remote OW debugger Debug Server (`tcpserv` / `tcpservw`): connect,
load a program, read/write memory and registers, set breakpoints, step,
continue.

No OW2 tree, debugger, or GDB is required — this is a standalone client of the
TRAP wire protocol.

## Requirements

- Python 3.12+
- [`uv`](https://docs.astral.sh/uv/) for packaging
- A running `tcpserv` somewhere reachable — built from the OW2 source tree
  (`bld/trap/tcp/`) or the binary shipped with an OW install. `tcpserv` is not
  part of this project; you supply it.

## Install

```bash
uv sync
```

## Running `tcpserv`

`tcpserv` listens on TCP port 3563 (0x0DEB) by default. On Linux:

```bash
tcpserv                    # foreground, port 3563
tcpserv -p 4000            # custom port
```

On DOS / Windows you run the matching `tcpserv` / `tcpservw` binary.

## Wiring into Claude Code

Add to `~/.claude/mcp.json`:

```json
{
  "mcpServers": {
    "ow2": {
      "command": "uv",
      "args": ["--directory", "/home/gabriels/projetos/ow2-mcp", "run", "ow2-mcp"]
    }
  }
}
```

## Tool surface

| Tool | Purpose |
|---|---|
| `trap_connect(host, port=3563, force=False)` | Open TCP + perform handshake |
| `trap_disconnect` | Send DISCONNECT + close socket |
| `trap_get_sys_config` | Query target CPU/FPU/OS/arch |
| `trap_read_mem(offset, length, segment=0)` | Read memory (auto-chunked) |
| `trap_write_mem(offset, data_hex, segment=0)` | Write memory (auto-chunked) |
| `trap_read_regs` | Read full register block (hex) |
| `trap_write_regs(data_hex)` | Write full register block (requires prior read) |
| `trap_set_break(offset, segment=0)` | Set breakpoint, returns `old` |
| `trap_clear_break(offset, old, segment=0)` | Clear breakpoint using saved `old` |
| `trap_prog_go(timeout_ms?)` | Run until stop/break/exception, optionally with a timeout |
| `trap_prog_step` | Single-step |
| `trap_prog_load(argv, true_argv=False)` | Load an executable or send an attach token |
| `trap_prog_attach(pid, hex_format=True)` | Attach to an existing process by integer or PID string |
| `trap_prog_kill(task_id?)` | Kill loaded task (defaults to last loaded) |
| `trap_get_err_text(error)` | Resolve TRAP error code to string |
| `trap_get_message_text` | Pull queued server message |

Binary payloads surface as lowercase hex strings. Hex input tolerates `0x`
prefixes, whitespace, underscores, and newlines.

## Canonical session

```text
trap_connect(host="10.0.0.5") →
trap_get_sys_config →
trap_prog_load(argv=["hello.exe"]) →
trap_read_mem(<entry>, 16) →
trap_set_break(<addr>)            # save returned `old`
trap_prog_go                      # expect conditions: ["BREAK"]
trap_read_regs
trap_clear_break(<addr>, <old>)
trap_prog_kill
trap_disconnect
```

For explicit argv mode, use `trap_prog_load(argv=["hello.exe", "arg1", "arg2"], true_argv=True)`.
For attach, use `trap_prog_attach(pid=0xFFF09CBF)` or `trap_prog_attach(pid="FFFE9DD7")`
instead of manually building `#PID`.
That attach token belongs in the first trailing `PROG_LOAD` field, not the old `args` slot.

## Development

```bash
uv run pytest                                            # unit tests (fast, no network)
uv run python scripts/smoke.py <host> [port]             # manual connect → sys_config → disconnect
OW2_MCP_TEST_HOST=10.0.0.5 uv run pytest tests/test_integration.py
```

## Error shape

Every tool returns either `{ok: true, ...}` or:

```json
{"ok": false, "error": {"code": "<code>", "message": "...", "trap_err_code": 0}}
```

Codes: `transport_error`, `protocol_error`, `not_connected`, `already_connected`,
`trap_error`. `prog_load` and `prog_kill` inline their server-side `err` field
— a `{"ok": true, "err": <nonzero>}` is a successful RPC for a failed operation.

## Non-goals (v1)

Supplementary services, watchpoints, IO read/write, screen toggling, stdio
redirect, `MAP_ADDR`, `GET_NEXT_ALIAS`, `SPLIT_CMD`, `CHECKSUM_MEM`,
`READ_USER_KEYBOARD`, `GET_LIB_NAME`, `MACHINE_DATA`, `SUSPEND`/`RESUME`,
register decoding, auto-reconnect, TLS/auth, building `tcpserv`.

## Protocol reference

- Wire framing — `bld/trap/tcp/c/tcplink.c:267-325` (RemoteGet/RemotePut)
- Core structs — `bld/dig/h/trpcore.h`, codes in `bld/dig/h/_trpreq.h`
- Client flows — `bld/wv/c/remcore.c`, `bld/wv/c/dbgprog.c`, `bld/wv/c/remmisc.c`
- Condition flags — `bld/wv/doc/trap.gml:1041-1056`
