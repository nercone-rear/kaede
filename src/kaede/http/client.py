from typing import Literal, Optional, Union
from dataclasses import dataclass, field

from ..url import URL
from ..tls import TLSConfig
from .models import HTTPVersion, HTTPRole, HTTPHeaders, HTTPResponse
from .websocket import WSConnection

@dataclass
class HTTPClientConfig:
    protocols: list[Union[HTTPVersion, Literal["WebSocket"]]] = ["HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0", "WebSocket"]
    tls: TLSConfig = field(default_factory=lambda: TLSConfig())

class HTTPClient:
    def __init__(self, config: Optional[HTTPClientConfig] = None, role: HTTPRole = HTTPRole.USER_AGENT):
        self.config = config or HTTPClientConfig()
        self.role = role

    async def request(self, method: Literal["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"], url: Union[URL, str], headers: Optional[Union[HTTPHeaders, dict[str, str], list[tuple[str, list[str]]]]], cookies: Optional[dict[str, str]], timeout: Optional[float]) -> HTTPResponse:
        ...

    async def get(self, url: Union[URL, str], headers: Optional[Union[HTTPHeaders, dict[str, str], list[tuple[str, list[str]]]]], cookies: Optional[dict[str, str]], timeout: Optional[float]) -> HTTPResponse:
        ...

    async def head(self, url: Union[URL, str], headers: Optional[Union[HTTPHeaders, dict[str, str], list[tuple[str, list[str]]]]], cookies: Optional[dict[str, str]], timeout: Optional[float]) -> HTTPResponse:
        ...

    async def post(self, url: Union[URL, str], headers: Optional[Union[HTTPHeaders, dict[str, str], list[tuple[str, list[str]]]]], cookies: Optional[dict[str, str]], timeout: Optional[float]) -> HTTPResponse:
        ...

    async def put(self, url: Union[URL, str], headers: Optional[Union[HTTPHeaders, dict[str, str], list[tuple[str, list[str]]]]], cookies: Optional[dict[str, str]], timeout: Optional[float]) -> HTTPResponse:
        ...

    async def delete(self, url: Union[URL, str], headers: Optional[Union[HTTPHeaders, dict[str, str], list[tuple[str, list[str]]]]], cookies: Optional[dict[str, str]], timeout: Optional[float]) -> HTTPResponse:
        ...

    async def connect(self, url: Union[URL, str], headers: Optional[Union[HTTPHeaders, dict[str, str], list[tuple[str, list[str]]]]], cookies: Optional[dict[str, str]], timeout: Optional[float]) -> HTTPResponse:
        ...

    async def options(self, url: Union[URL, str], headers: Optional[Union[HTTPHeaders, dict[str, str], list[tuple[str, list[str]]]]], cookies: Optional[dict[str, str]], timeout: Optional[float]) -> HTTPResponse:
        ...

    async def trace(self, url: Union[URL, str], headers: Optional[Union[HTTPHeaders, dict[str, str], list[tuple[str, list[str]]]]], cookies: Optional[dict[str, str]], timeout: Optional[float]) -> HTTPResponse:
        ...

    async def patch(self, url: Union[URL, str], headers: Optional[Union[HTTPHeaders, dict[str, str], list[tuple[str, list[str]]]]], cookies: Optional[dict[str, str]], timeout: Optional[float]) -> HTTPResponse:
        ...

    async def websocket(self, url: Union[URL, str], headers: Optional[Union[HTTPHeaders, dict[str, str], list[tuple[str, list[str]]]]], cookies: Optional[dict[str, str]], timeout: Optional[float]) -> WSConnection:
        ...

    async def close(self):
        ...
