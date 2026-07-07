from typing import Literal, Optional, List, Dict, Tuple, Union
from dataclasses import dataclass, field

from ...url import URL
from ...tls import TLSConfig
from ..models import HTTPVersion, HTTPMethod, HTTPRole, HTTPHeaders, HTTPResponse
from ..websocket import WSConnection

@dataclass
class HTTPClientConfig:
    protocols: List[Union[HTTPVersion, Literal["WebSocket"]]] = ["HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0", "WebSocket"]
    tls: Union[TLSConfig, Dict[str, TLSConfig]] = field(default_factory=lambda: TLSConfig()) # config or {hostname/domain: config}

class HTTPClient:
    def __init__(self, config: Optional[HTTPClientConfig] = None, role: HTTPRole = HTTPRole.USER_AGENT):
        self.config = config or HTTPClientConfig()
        self.role = role

    async def request(self, method: HTTPMethod, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float], stream: bool = False) -> HTTPResponse:
        ...

    async def get(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float], stream: bool = False) -> HTTPResponse:
        ...

    async def head(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float], stream: bool = False) -> HTTPResponse:
        ...

    async def post(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float], stream: bool = False) -> HTTPResponse:
        ...

    async def put(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float], stream: bool = False) -> HTTPResponse:
        ...

    async def delete(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float], stream: bool = False) -> HTTPResponse:
        ...

    async def connect(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float], stream: bool = False) -> HTTPResponse:
        ...

    async def options(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float], stream: bool = False) -> HTTPResponse:
        ...

    async def trace(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float], stream: bool = False) -> HTTPResponse:
        ...

    async def patch(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float], stream: bool = False) -> HTTPResponse:
        ...

    async def websocket(self, url: Union[URL, str], *, headers: Optional[Union[HTTPHeaders, Dict[str, str], List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]]], cookies: Optional[Dict[str, str]], timeout: Optional[float], stream: bool = False) -> WSConnection:
        ...
