import asyncio
from typing import Optional, Annotated, Callable, TypeAlias
from pydantic import Field

TCPPort: TypeAlias = Annotated[int, Field(ge=0, le=65535)]

class TCPConnection:
    def __init__(self, dst: tuple[str, TCPPort], src: tuple[str, TCPPort], *, handler: Optional["TCPHandler"] = None, protocol: Optional["TCPProtocol"] = None):
        self.dst = dst
        self.src = src
        self.handler = handler
        self.protocol = protocol

    async def connect(self):
        ...

    async def close(self, half_close: bool = False):
        ...

    async def send(self, data: bytes):
        ...

    async def receive(self, n: int = -1) -> bytes:
        ...

class TCPHandler:
    def __init__(self, on_connection: Optional[Callable] = None, on_close: Optional[Callable] = None):
        self.on_connection = on_connection  # (connection: TCPConnection) -> None
        self.on_close = on_close            # (connection: TCPConnection) -> None

class TCPProtocol(asyncio.Protocol):
    def __init__(self, src: Optional[tuple[str, TCPPort]] = None, handler: Optional[TCPHandler] = None):
        self.src = src
        self.handler = handler
        self.connections: dict[tuple[str, TCPPort], TCPConnection] = {}
    ...
