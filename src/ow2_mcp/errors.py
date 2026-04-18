"""Exception hierarchy for the TRAP client."""

from __future__ import annotations


class TrapError(Exception):
    """Base class for every TRAP-level failure surfaced to callers."""


class TransportError(TrapError):
    """Socket-level failure: connect failed, short read, timeout, peer closed."""


class ProtocolError(TrapError):
    """Reply malformed: packet too large, payload shorter than the declared struct."""


class NotConnectedError(TrapError):
    """A request was issued before `connect()` or after the socket was torn down."""


class AlreadyConnectedError(TrapError):
    """A second `connect()` was issued without `force=True`."""


class TrapServerError(TrapError):
    """The server refused the CONNECT handshake with a non-empty error string."""

    def __init__(self, message: str, trap_err_code: int | None = None) -> None:
        super().__init__(message)
        self.trap_err_code = trap_err_code
