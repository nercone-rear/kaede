from typing import Optional, List, Tuple, Callable
from dataclasses import dataclass

from ...protocol import ServerLimits
from ..models import TCPPort

@dataclass
class TCPServerLimits(ServerLimits):
    pass

class TCPHandler:
    def __init__(self, on_connection: Optional[Callable] = None, on_close: Optional[Callable] = None):
        self.on_connection = on_connection  # (connection: TCPConnection) -> None
        self.on_close = on_close            # (connection: TCPConnection) -> None

class TCPServer:
    def __init__(self):
        pass

    def run(self, handler: TCPHandler, workers: int = 4, ports: List[Tuple[str, TCPPort]] = [("0.0.0.0", 8080)]):
        ...

    async def serve(self, handler: TCPHandler, ports: List[Tuple[str, TCPPort]] = [("0.0.0.0", 8080)]):
        ...
