from typing import Literal, Optional, List, Dict, Tuple, Union
from dataclasses import dataclass, field

from ...url import URL
from ...tls import TLSConfig
from ..models import HTTPVersion, HTTPMethod, HTTPRole, HTTPHeaders, HTTPLimits
from ..protocol import HTTPConnection
from ..websocket import WSConnection

@dataclass
class HTTPClientConfig:
    protocols: List[Union[HTTPVersion, Literal["WebSocket"]]] = ["HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0", "WebSocket"]

    limits: HTTPLimits = field(lambda: HTTPLimits())

    tls: Union[TLSConfig, Dict[str, TLSConfig]] = field(default_factory=lambda: TLSConfig()) # TLSConfig or {hostname: TLSConfig, ...}

class HTTPClient:
    def __init__(self, *, role: HTTPRole = HTTPRole.USER_AGENT, config: Optional[HTTPClientConfig] = None):
        self.role = role
        self.config = config or HTTPClientConfig()

    async def request(self, method: HTTPMethod, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float]) -> HTTPConnection:
        ...

    async def get(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float]) -> HTTPConnection:
        ...

    async def head(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float]) -> HTTPConnection:
        ...

    async def post(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float]) -> HTTPConnection:
        ...

    async def put(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float]) -> HTTPConnection:
        ...

    async def delete(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float]) -> HTTPConnection:
        ...

    async def connect(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float]) -> HTTPConnection:
        ...

    async def options(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float]) -> HTTPConnection:
        ...

    async def trace(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float]) -> HTTPConnection:
        ...

    async def patch(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float]) -> HTTPConnection:
        ...

    async def websocket(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float]) -> WSConnection:
        ...
