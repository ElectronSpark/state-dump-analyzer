import asyncio
import socket

class _ResetSafeSocket(socket.socket):
    def shutdown(self, how: int) -> None: ...

def new_event_loop() -> asyncio.AbstractEventLoop: ...
