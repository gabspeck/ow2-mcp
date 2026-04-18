"""Entry point: ``python -m ow2_mcp`` / ``ow2-mcp`` both run the MCP server."""

from __future__ import annotations

from .server import mcp


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
