from typing import Literal, Optional, List, Dict, Tuple, Union
from dataclasses import dataclass, field

from ...url import URL
from ...tls import TLSConfig
from ..models import HTTPVersion, HTTPMethod, HTTPRole, HTTPHeaders, HTTPConnection
from ..websocket import WSConnection

@dataclass
class HTTPClientConfig:
    protocols: List[Union[HTTPVersion, Literal["WebSocket"]]] = ["HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0", "WebSocket"]

    tls: Union[TLSConfig, Dict[str, TLSConfig]] = field(default_factory=lambda: TLSConfig()) # TLSConfig or {hostname: TLSConfig, ...}

    max_message_size: int = 1073741824 # in bytes, The total size of the HTTP message allowed for reception.
    max_message_offload_size: int = 98304 # in bytes, The total size of an HTTP message that can be held in memory.

    max_message_body_size: int = 1073741824 # in bytes, The size of the HTTP message body allowed for reception.
    max_message_body_offload_size: int = 65536 # in bytes, The size of the HTTP message body that can be held in memory.

class HTTPClient:
    def __init__(self, *, role: HTTPRole = HTTPRole.USER_AGENT, config: Optional[HTTPClientConfig] = None):
        self.role = role
        self.config = config or HTTPClientConfig()

    async def request(self, method: HTTPMethod, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float], stream: bool = False) -> HTTPConnection:
        ...

    async def get(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float], stream: bool = False) -> HTTPConnection:
        ...

    async def head(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float], stream: bool = False) -> HTTPConnection:
        ...

    async def post(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float], stream: bool = False) -> HTTPConnection:
        ...

    async def put(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float], stream: bool = False) -> HTTPConnection:
        ...

    async def delete(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float], stream: bool = False) -> HTTPConnection:
        ...

    async def connect(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float], stream: bool = False) -> HTTPConnection:
        ...

    async def options(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float], stream: bool = False) -> HTTPConnection:
        ...

    async def trace(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float], stream: bool = False) -> HTTPConnection:
        ...

    async def patch(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float], stream: bool = False) -> HTTPConnection:
        ...

    async def websocket(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float], stream: bool = False) -> WSConnection:
        ...
