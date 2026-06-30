from typing import Literal, Optional, Union
from dataclasses import dataclass, field

from ..url import URL
from ..tls import TLSClientConfig
from .models import HTTPVersion, HTTPHeaders, HTTPResponse
from .websocket import WSConnection

@dataclass
class HTTPClientConfig:
    versions: list[HTTPVersion] = ["HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0"]

    tls: TLSClientConfig = field(default_factory=lambda: TLSClientConfig())

class HTTPClient:
    def __init__(self, config: Optional[HTTPClientConfig] = None):
        self.config = config or HTTPClientConfig()

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
