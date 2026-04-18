"""OpenWatcom TRAP protocol client and MCP server."""

from __future__ import annotations

from .client import ConnectResult, LoadedProgram, TrapClient
from .errors import (
    AlreadyConnectedError,
    NotConnectedError,
    ProtocolError,
    TransportError,
    TrapError,
    TrapServerError,
)

__version__ = "0.1.0"

__all__ = [
    "AlreadyConnectedError",
    "ConnectResult",
    "LoadedProgram",
    "NotConnectedError",
    "ProtocolError",
    "TransportError",
    "TrapClient",
    "TrapError",
    "TrapServerError",
    "__version__",
]
