import asyncio
from typing import Optional, Dict, Tuple, TYPE_CHECKING
from pydantic import Field

from .models import UDPPort

if TYPE_CHECKING:
    from .api.server import UDPHandler

class UDPConnection:
    def __init__(self, src: Tuple[str, UDPPort], dst: Tuple[str, UDPPort], *, handler: Optional[UDPHandler] = None, protocol: Optional["UDPProtocol"] = None):
        self.src = src
        self.dst = dst
        self.handler = handler
        self.protocol = protocol

    async def send(self, data: bytes):
        raise NotImplementedError()

    async def receive(self, n: int = -1) -> bytes:
        raise NotImplementedError()

class UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, src: Optional[Tuple[str, UDPPort]] = None, handler: Optional[UDPHandler] = None):
        self.src = src
        self.handler = handler
        self.connections: Dict[Tuple[str, UDPPort], UDPConnection] = {}
    ...
