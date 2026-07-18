from typing import Optional, Callable, Tuple, List
from dataclasses import dataclass, field

from ...protocol import ServerLimits
from ..models import DNSPort

@dataclass
class DNSServerLimits(ServerLimits):
    pass

@dataclass
class DNSServerConfig:
    limits: DNSServerLimits = field(default_factory=lambda: DNSServerLimits())

class DNSHandler:
    def __init__(self, on_connection: Optional[Callable] = None):
        self.on_connection = on_connection # (connection: DNSConnection) -> None

class DNSServer:
    def __init__(self, *, config: Optional[DNSServerConfig] = None):
        self.config = config or DNSServerConfig()

    def run(self, handler: DNSHandler, workers: int = 4, ports: Optional[List[Tuple[str, DNSPort]]] = None):
        raise NotImplementedError()

    async def serve(self, handler: DNSHandler, ports: Optional[List[Tuple[str, DNSPort]]] = None):
        raise NotImplementedError()
