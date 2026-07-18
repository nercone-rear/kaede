from typing import Optional, Callable, Tuple, List
from dataclasses import dataclass, field

from ...protocol import ServerLimits
from ..models import UDPPort

@dataclass
class UDPServerLimits(ServerLimits):
    pass

@dataclass
class UDPServerConfig:
    limits: UDPServerLimits = field(default_factory=lambda: UDPServerLimits())

class UDPHandler:
    def __init__(self, on_connection: Optional[Callable] = None):
        self.on_connection = on_connection  # (connection: UDPConnection) -> None

class UDPServer:
    def __init__(self, config: Optional[UDPServerConfig] = None):
        self.config = config or UDPServerConfig()

    def run(self, handler: UDPHandler, workers: int = 4, ports: Optional[List[Tuple[str, UDPPort]]] = None):
        raise NotImplementedError()

    async def serve(self, handler: UDPHandler, ports: Optional[List[Tuple[str, UDPPort]]] = None):
        raise NotImplementedError()
