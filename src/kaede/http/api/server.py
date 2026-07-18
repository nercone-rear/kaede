from typing import Optional, Callable, Union, Literal, Tuple, List, Dict
from dataclasses import dataclass, field

from ...tls import TLSConfig
from ...protocol import ServerLimits
from ..models import HTTPVersion, HTTPRole, HTTPPort, HTTPLimits

@dataclass
class HTTPServerLimits(ServerLimits, HTTPLimits):
    pass

@dataclass
class HTTPServerConfig:
    protocols: List[Union[HTTPVersion, Literal["WebSocket"]]] = ["HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0", "WebSocket"]

    limits: HTTPServerLimits = field(default_factory=lambda: HTTPServerLimits())

    tls: Union[TLSConfig, Dict[str, TLSConfig]] = field(default_factory=lambda: TLSConfig()) # TLSConfig or {hostname: TLSConfig, ...}

class HTTPHandler:
    def __init__(self, on_connection: Optional[Callable] = None, on_websocket: Optional[Callable] = None):
        self.on_connection = on_connection # (connection: HTTPConnection) -> None
        self.on_websocket = on_websocket   # (websocket: WSConnection) -> None

class HTTPServer:
    def __init__(self, *, role: HTTPRole = HTTPRole.ORIGIN, config: Optional[HTTPServerConfig] = None):
        self.role = role
        self.config = config or HTTPServerConfig()

    def run(self, handler: HTTPHandler, workers: int = 4, ports: List[Tuple[str, HTTPPort]] = [("0.0.0.0", HTTPPort(type="tcp", value=8080, secure=False))]):
        ...

    async def serve(self, handler: HTTPHandler, ports: List[Tuple[str, HTTPPort]] = [("0.0.0.0", HTTPPort(type="tcp", value=8080, secure=False))]):
        ...
