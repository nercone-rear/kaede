import asyncio
from typing import Optional, Dict, Tuple, TYPE_CHECKING

from .models import TCPPort

if TYPE_CHECKING:
    from .api.server import TCPHandler

class TCPConnection:
    def __init__(self, dst: Tuple[str, TCPPort], src: Tuple[str, TCPPort], *, handler: Optional[TCPHandler] = None, protocol: Optional["TCPProtocol"] = None):
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

class TCPProtocol(asyncio.Protocol):
    def __init__(self, src: Optional[Tuple[str, TCPPort]] = None, handler: Optional[TCPHandler] = None):
        self.src = src
        self.handler = handler
        self.connections: Dict[Tuple[str, TCPPort], TCPConnection] = {}
    ...
