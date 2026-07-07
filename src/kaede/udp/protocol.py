import asyncio
from typing import Optional, Annotated, Callable, TypeAlias
from pydantic import Field

UDPPort: TypeAlias = Annotated[int, Field(ge=0, le=65535)]

class UDPConnection:
    def __init__(self, src: tuple[str, UDPPort], dst: tuple[str, UDPPort], *, handler: Optional["UDPHandler"] = None, protocol: Optional["UDPProtocol"] = None):
        self.src = src
        self.dst = dst
        self.handler = handler
        self.protocol = protocol

    async def send(self, data: bytes):
        ...

    async def receive(self, n: int = -1) -> bytes:
        ...

class UDPHandler:
    def __init__(self, on_connection: Optional[Callable] = None):
        self.on_connection = on_connection  # (connection: UDPConnection) -> None

class UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, src: Optional[tuple[str, UDPPort]] = None, handler: Optional[UDPHandler] = None):
        self.src = src
        self.handler = handler
        self.connections: dict[tuple[str, UDPPort], UDPConnection] = {}
    ...
