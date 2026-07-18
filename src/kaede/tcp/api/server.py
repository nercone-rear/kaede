from typing import Optional, List, Tuple, Callable
from dataclasses import dataclass, field

from ...protocol import ServerLimits
from ..models import TCPPort

@dataclass
class TCPServerLimits(ServerLimits):
    pass

@dataclass
class TCPServerConfig:
    limits: TCPServerLimits = field(default_factory=lambda: TCPServerLimits())

class TCPHandler:
    def __init__(self, on_connection: Optional[Callable] = None):
        self.on_connection = on_connection  # (connection: TCPConnection) -> None

class TCPServer:
    def __init__(self, config: Optional[TCPServerConfig] = None):
        self.config = config or TCPServerConfig()

    def run(self, handler: TCPHandler, workers: int = 4, ports: List[Tuple[str, TCPPort]] = []):
        ...

    async def serve(self, handler: TCPHandler, workers: int = 4, ports: List[Tuple[str, TCPPort]] = []):
        ...
