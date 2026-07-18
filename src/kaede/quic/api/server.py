from typing import Optional, Callable, Tuple, List
from dataclasses import dataclass, field

from ...udp import UDPPort
from ...protocol import ServerLimits

@dataclass
class QUICServerLimits(ServerLimits):
    pass

@dataclass
class QUICServerConfig:
    limits: QUICServerLimits = field(default_factory=lambda: QUICServerLimits())

class QUICHandler:
    def __init__(self, on_connection: Optional[Callable] = None):
        self.on_connection = on_connection  # (connection: QUICConnection) -> None

class QUICServer:
    def __init__(self, config: Optional[QUICServerConfig] = None):
        self.config = config or QUICServerConfig()

    def run(self, handler: QUICHandler, workers: int = 4, ports: List[Tuple[str, UDPPort]] = []):
        raise NotImplementedError()

    async def serve(self, handler: QUICHandler, ports: List[Tuple[str, UDPPort]] = []):
        raise NotImplementedError()
