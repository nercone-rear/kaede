import os
import json
import gzip
import zlib
import rjsmin
import rcssmin
import ipaddress
import zstandard
import brotlicffi
import minify_html
from enum import Enum
from scour import scour
from typing import Any, Optional, Literal, Union, TypeVar, TypeAlias
from importlib.metadata import version
from dataclasses import dataclass, field
from collections.abc import AsyncIterator

from ..url import URL
from .headers import ContentType

T = TypeVar("T")

HTTPVersion: TypeAlias = Literal["HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0"]

class HTTPHeaderCase(Enum):
    TITLECASE = "Title-Case" # for HTTP/1
    LOWERCASE = "lower-case" # for HTTP/2/3

class HTTPHeaders:
    def __init__(self, value: Union[str, bytes, list[tuple[str, list[str]]]], case: Optional[HTTPHeaderCase] = None):
        self.case = case
        if isinstance(value, (str, bytes)):
            self.raw = HTTPHeaders.parse(value).raw
        elif isinstance(value, list):
            self.raw = value

    def __getitem__(self, key: str) -> Optional[list[str]]:
        ...

    def __setitem__(self, key: str, value: Union[str, list[str]]):
        ...

    def __contains__(self, item: str):
        ...

    def items(self) -> list[tuple[str, str]]:
        ...

    def get(self, key: str, default: Optional[T] = None) -> Optional[Union[str, T]]:
        ...

    def set(self, key: str, value: Union[str, list[str]], override: bool = True):
        ...

    def append(self, key: str, value: str):
        ...

    def remove(self, key: str):
        ...

    @classmethod
    def parse(cls, value: Union[str, bytes]) -> "HTTPHeaders":
        ...

    def build(self) -> str:
        ...

@dataclass
class HTTPMessage:
    client: tuple[Union[ipaddress.IPv4Address, ipaddress.IPv6Address], int] = field(default_factory=lambda: (ipaddress.IPv4Address("0.0.0.0"), 0))

    protocol: Literal["HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0"] = "HTTP/1.1"

    headers: HTTPHeaders = field(default_factory=lambda: HTTPHeaders({}))
    trailers: Optional[HTTPHeaders] = None

    body: Optional[Union[bytes, AsyncIterator[bytes], os.PathLike]] = None

    scheme: Literal["http", "https"] = "http"
    secure: bool = False

    early_data: bool = False

    compression: bool = True
    minification: bool = False

    compressed: Optional[Union[bytes, AsyncIterator[bytes]]] = None
    minified: Optional[Union[bytes, AsyncIterator[bytes]]] = None

    @property
    def text(self) -> str:
        return self.body.decode()

    @property
    def json(self) -> Any:
        return json.loads(self.text)

    @property
    def has_real_body(self) -> bool:
        return self.body is not None and isinstance(self.body, bytes)

    def compress(self, encoding: Optional[str] = None):
        if not (self.compression and self.body is not None and self.compressed is not None):
            return

        if encoding == "zstd":
            self.compressed = zstandard.ZstdCompressor(level=3).compress(self.body)
        elif encoding == "br":
            self.compressed = brotlicffi.compress(self.body, quality=4)
        elif encoding == "gzip":
            self.compressed = gzip.compress(self.body, compresslevel=6)
        elif encoding == "deflate":
            self.compressed = zlib.compress(self.body, level=6)

        self.headers.set("Content-Encoding", encoding)

    def decompress(self, encoding: Optional[str] = None):
        ...

    def minify(self):
        if not (self.minification and self.has_real_body):
            return

        content_type = ContentType(self.headers.get("Content-Type") or "")

        try:
            if content_type.essence.startswith("text/html"):
                self.body = minify_html.minify(self.body.decode("utf-8", errors="replace"), minify_js=True, minify_css=True, keep_comments=True, keep_html_and_head_opening_tags=True).encode("utf-8")
            elif content_type.essence.startswith("text/css"):
                self.body = rcssmin.cssmin(self.body.decode("utf-8", errors="replace")).encode("utf-8")
            elif content_type.essence.startswith(("text/javascript", "application/javascript")):
                self.body = rjsmin.jsmin(self.body.decode("utf-8", errors="replace")).encode("utf-8")
            elif content_type.essence.startswith("image/svg"):
                options = scour.generateDefaultOptions()
                options.newlines = False
                options.shorten_ids = True
                options.strip_comments = True
                self.body = scour.scourString(self.body.decode("utf-8", errors="replace"), options).encode("utf-8")
        except Exception:
            pass

@dataclass
class HTTPRequest(HTTPMessage):
    method: Literal["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]
    target: str

    scheme: Literal["http", "https"] = "http"
    secure: bool = False

    headers: HTTPHeaders = field(default_factory=lambda: HTTPHeaders({"User-Agent": f"Kaede/{version('nercone-kaede')} (+https://github.com/nercone-rear/kaede/)"}))

    url: URL = field(init=False, repr=False)

    def __post_init__(self):
        authority = self.headers.get("Host") or ""
        self.url = URL.from_target(self.target, self.scheme, authority)

@dataclass
class HTTPResponse(HTTPMessage):
    status_code: int = 200

    headers: HTTPHeaders = field(default_factory=lambda: HTTPHeaders({"Server": "Kaede"}))

    range: Optional[tuple[int, int]] = field(default=None)
