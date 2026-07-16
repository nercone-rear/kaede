from typing import Optional, Callable, Union, Literal, Tuple, List, Dict
from dataclasses import dataclass, field

from ...tls import TLSConfig
from ..models import HTTPVersion, HTTPRole, HTTPPort

@dataclass
class HTTPServerConfig:
    protocols: List[Union[HTTPVersion, Literal["WebSocket"]]] = ["HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0", "WebSocket"]

    tls: Union[TLSConfig, Dict[str, TLSConfig]] = field(default_factory=lambda: TLSConfig()) # TLSConfig or {hostname: TLSConfig, ...}

    max_connection_nums: int = 16384 # per worker
    max_connection_rate: List[Tuple[float, int]] = [(1, 25), (5, 50), (60, 75)] # [(period in sec, nums), ...]

    max_message_size: int = 1073741824 # in bytes, The total size of the HTTP message allowed for reception.
    max_message_offload_size: int = 98304 # in bytes, The total size of an HTTP message that can be held in memory.

    max_message_body_size: int = 1073741824 # in bytes, The size of the HTTP message body allowed for reception.
    max_message_body_offload_size: int = 65536 # in bytes, The size of the HTTP message body that can be held in memory.

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
