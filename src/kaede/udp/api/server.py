from typing import Optional, Callable, Tuple, List
from dataclasses import dataclass

from ...protocol import ServerLimits
from ..models import UDPPort

@dataclass
class UDPServerLimits(ServerLimits):
    pass

class UDPHandler:
    def __init__(self, on_connection: Optional[Callable] = None):
        self.on_connection = on_connection  # (connection: UDPConnection) -> None

class UDPServer:
    def __init__(self):
        pass

    def run(self, handler: UDPHandler, workers: int = 4, ports: List[Tuple[str, UDPPort]] = [("0.0.0.0", 8080)]):
        ...

    async def serve(self, handler: UDPHandler, ports: List[Tuple[str, UDPPort]] = [("0.0.0.0", 8080)]):
        ...
