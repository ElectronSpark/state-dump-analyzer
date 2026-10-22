"""Application-local Windows socket cleanup compatibility for the web runner.

CPython's Proactor socket transport calls shutdown before close/server detach.
A peer reset from shutdown interrupts that cleanup. Keep its existing cleanup
and IOCP/subprocess implementation, but treat that reset as already shut down.
The two transport-construction hooks are private CPython compatibility points;
the focused Windows tests exercise both plain and TLS socket ownership.
"""

from __future__ import annotations

import asyncio
import socket
import sys
from typing import Any, cast


class _ResetSafeSocket(socket.socket):
    __slots__ = ()

    def shutdown(self, how: int) -> None:
        try:
            super().shutdown(how)
        except ConnectionResetError:
            if how != socket.SHUT_RDWR:
                raise


def _reset_safe_socket(sock: socket.socket) -> _ResetSafeSocket:
    if isinstance(sock, _ResetSafeSocket):
        return sock
    if type(sock) is not socket.socket:
        raise TypeError("Windows server transport requires a plain socket")
    if sock.fileno() < 0:
        raise ValueError("cannot adapt a closed socket")
    # IOCP registration belongs to this object, not just its descriptor. Moving
    # the descriptor to another socket would attempt a second registration.
    # A slot-compatible, instance-local class change preserves both owners.
    sock.__class__ = _ResetSafeSocket
    return cast(_ResetSafeSocket, sock)


def new_event_loop() -> asyncio.AbstractEventLoop:
    """Create the server's IOCP loop without changing asyncio's global policy."""
    if sys.platform != "win32":
        raise RuntimeError("the Windows server loop requires Windows")

    class ResetSafeProactorEventLoop(asyncio.ProactorEventLoop):
        def _make_socket_transport(
            self, sock: socket.socket, *args: Any, **kwargs: Any
        ) -> Any:
            owned = _reset_safe_socket(sock)
            try:
                return super()._make_socket_transport(owned, *args, **kwargs)
            except BaseException:
                owned.close()
                raise

        def _make_ssl_transport(
            self, sock: socket.socket, *args: Any, **kwargs: Any
        ) -> Any:
            owned = _reset_safe_socket(sock)
            try:
                return super()._make_ssl_transport(owned, *args, **kwargs)
            except BaseException:
                owned.close()
                raise

    return ResetSafeProactorEventLoop()
