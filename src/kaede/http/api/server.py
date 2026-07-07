from typing import Optional, Literal, List, Tuple, Union, Callable
from dataclasses import dataclass, field

from ...tls import TLSConfig
from ..models import HTTPVersion, HTTPRole, HTTPPort

class Handler:
    def __init__(self, on_request: Optional[Callable] = None, on_websocket: Optional[Callable] = None):
        self.on_request = on_request      # (request: Request) -> Response
        self.on_websocket = on_websocket  # (websocket: WSConnection) -> None

@dataclass
class HTTPServerConfig:
    protocols: List[Union[HTTPVersion, Literal["WebSocket"]]] = ["HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0", "WebSocket"]
    tls: TLSConfig = field(default_factory=lambda: TLSConfig())

class HTTPServer:
    def __init__(self, config: Optional[HTTPServerConfig] = None, role: HTTPRole = HTTPRole.ORIGIN):
        self.role = role
        self.config = config or HTTPServerConfig()

    def run(self, ports: List[Tuple[str, HTTPPort]] = [("0.0.0.0", HTTPPort(type="tcp", value=8080, secure=False))]):
        ...

    async def serve(self, ports: List[Tuple[str, HTTPPort]] = [("0.0.0.0", HTTPPort(type="tcp", value=8080, secure=False))]):
        ...
