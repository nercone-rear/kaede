from typing import Optional, Callable, Tuple, List

from ..models import UDPPort

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
