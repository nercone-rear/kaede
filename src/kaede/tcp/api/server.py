from typing import Optional, List, Tuple, Callable

from ..models import TCPPort

class TCPHandler:
    def __init__(self, on_connection: Optional[Callable] = None, on_close: Optional[Callable] = None):
        self.on_connection = on_connection  # (connection: TCPConnection) -> None
        self.on_close = on_close            # (connection: TCPConnection) -> None

class TCPServer:
    def __init__(self):
        pass

    def run(self, ports: List[Tuple[str, TCPPort]] = [("0.0.0.0", 8080)]):
        ...

    async def serve(self, ports: List[Tuple[str, TCPPort]] = [("0.0.0.0", 8080)]):
        ...
