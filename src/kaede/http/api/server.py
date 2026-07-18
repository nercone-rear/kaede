from typing import Optional, Union, Tuple, List, Dict
from dataclasses import dataclass, field

from ...tls import TLSConfig
from ...protocol import ServerLimits
from ..models import HTTPVersion, HTTPRole, HTTPPort, HTTPLimits, HTTPHeaders, HTTPHeaderCase,  HTTPResponse
from ..protocol import HTTPState, HTTPConnection
from ..finalizer import finalize_response
from ..websocket import WSConnection

@dataclass
class HTTPServerLimits(ServerLimits, HTTPLimits):
    pass

@dataclass
class HTTPServerConfig:
    versions: List[HTTPVersion] = field(default_factory=lambda: ["HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0"])

    limits: HTTPServerLimits = field(default_factory=lambda: HTTPServerLimits())

    tls: Union[TLSConfig, Dict[str, TLSConfig]] = field(default_factory=lambda: TLSConfig()) # TLSConfig or {hostname: TLSConfig, ...}

class HTTPHandler:
    def on_connection(self, connection: HTTPConnection):
        connection.accept()
        connection.wait(HTTPState.RECEIVED)
        connection.send(finalize_response(HTTPResponse(version=connection.version, body=b"This is Default Response from Kaede.")))
        connection.close()

    def on_websocket(self, connection: WSConnection):
        connection.close(1011, "WebSocket not configured.")

class HTTPServer:
    def __init__(self, *, role: HTTPRole = HTTPRole.ORIGIN, config: Optional[HTTPServerConfig] = None):
        self.role = role
        self.config = config or HTTPServerConfig()

    def run(self, handler: HTTPHandler, workers: int = 4, ports: Optional[List[Tuple[str, HTTPPort]]] = None):
        raise NotImplementedError()

    async def serve(self, handler: HTTPHandler, ports: Optional[List[Tuple[str, HTTPPort]]] = None):
        raise NotImplementedError()
