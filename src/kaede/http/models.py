import os
import json
import gzip
import zlib
import xxhash
import ipaddress
import zstandard
import brotlicffi
from enum import Enum
from typing import Any, Optional, Literal, List, Dict, Tuple, Union, TypeVar
from dataclasses import dataclass, field
from collections.abc import AsyncIterator

from ..url import URL
from ..tcp import TCPPort
from ..udp import UDPPort
from .headers import CommaHeader, AcceptEncoding, ETag, Cookie, SetCookie

T = TypeVar("T")

HTTPVersion = Literal["HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0"]
HTTPMethod  = Literal["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]

class HTTPBroadRole(Enum):
    CLIENT = "Client"
    SERVER = "Server"

    def vaild(self, specific: "HTTPRole") -> bool:
        if specific == HTTPRole.USER_AGENT:
            return self == HTTPBroadRole.CLIENT
        elif specific != HTTPRole.USER_AGENT:
            return self == HTTPBroadRole.SERVER

    @staticmethod
    def from_specific(specific: "HTTPRole") -> "HTTPBroadRole":
        return HTTPBroadRole.CLIENT if specific == HTTPRole.USER_AGENT else HTTPBroadRole.SERVER

class HTTPRole(Enum):
    USER_AGENT = "User Agent"
    ORIGIN     = "Origin"
    PROXY      = "Proxy"
    GATEWAY    = "Gateway"
    TUNNEL     = "Tunnel"

    def vaild(self, broad: "HTTPBroadRole") -> bool:
        if broad == HTTPBroadRole.CLIENT:
            return self == HTTPRole.USER_AGENT
        elif broad == HTTPBroadRole.SERVER:
            return self != HTTPRole.USER_AGENT

    @staticmethod
    def from_broad(broad: "HTTPBroadRole", server_default: Optional["HTTPRole"]) -> "HTTPRole":
        return HTTPRole.USER_AGENT if broad == HTTPBroadRole.CLIENT else (server_default or HTTPRole.ORIGIN)

@dataclass
class HTTPPort:
    type: Literal["uds", "tcp", "quic"] = "tcp"
    value: Union[str, int, TCPPort, UDPPort] = TCPPort(80)
    secure: bool = False

    @property
    def vaild(self) -> bool:
        if self.type == "uds":
            return isinstance(self.value, str)
        elif self.type == "tcp":
            return isinstance(self.value, TCPPort) or (isinstance(self.value, int) and 0 <= self.value < 65536)
        elif self.type == "quic":
            return (isinstance(self.value, UDPPort) or (isinstance(self.value, int) and 0 <= self.value < 65536)) and self.secure

class HTTPHeaderCase(Enum):
    TITLECASE = "Title-Case" # for HTTP/1.0
    LOWERCASE = "lower-case" # for HTTP/2.0/3.0

    def apply(self, name: str) -> str:
        if self == HTTPHeaderCase.TITLECASE:
            return name.title()
        elif self == HTTPHeaderCase.LOWERCASE:
            return name.lower()

    @staticmethod
    def from_version(version: HTTPVersion) -> "HTTPHeaderCase":
        return HTTPHeaderCase.TITLECASE if version in ("HTTP/1.0", "HTTP/1.1") else HTTPHeaderCase.LOWERCASE

class HTTPHeaders:
    def __init__(self, value: Union[str, bytes, List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]], case: Optional[HTTPHeaderCase] = None):
        ...

    def __getitem__(self, key: str) -> Optional[List[str]]:
        ...

    def __setitem__(self, key: str, value: Union[str, List, Dict, Tuple[str]]):
        ...

    def __contains__(self, item: str):
        ...

    def items(self) -> List[Tuple[str, str]]:
        ...

    def get(self, key: str, default: Optional[T] = None) -> Optional[Union[str, T]]:
        ...

    def set(self, key: str, value: Union[str, List, Dict, Tuple[str]], override: bool = True):
        ...

    def append(self, key: str, value: str):
        ...

    def remove(self, key: str):
        ...

    @classmethod
    def parse(cls, value: Union[str, bytes], version: HTTPVersion) -> "HTTPHeaders":
        ...

    def build(self) -> str:
        ...

@dataclass
class HTTPMessage:
    client: Tuple[Union[ipaddress.IPv4Address, ipaddress.IPv6Address], int] = field(default_factory=lambda: (ipaddress.IPv4Address("0.0.0.0"), 0))

    protocol: HTTPVersion = "HTTP/1.1"

    headers: HTTPHeaders = field(default_factory=lambda: HTTPHeaders({}))
    trailers: Optional[HTTPHeaders] = None

    body: Optional[Union[bytes, AsyncIterator[bytes], os.PathLike]] = None

    scheme: Literal["http", "https"] = "http"
    secure: bool = False

    early_data: bool = False

    compression: bool = True
    minification: bool = False

    compressed: bool = False
    minified: bool = False

    @property
    def text(self) -> str:
        return self.body.decode()

    @property
    def json(self) -> Any:
        return json.loads(self.text)

    @property
    def has_real_body(self) -> bool:
        return self.body is not None and isinstance(self.body, bytes)

    def compress(self, accept_encoding: str, *, max_offload_filesize: int = 32768):
        if self.compression and not self.compressed and accept_encoding and isinstance(self.body, (bytes, str, os.PathLike)):
            preference = ["zstd", "br", "gzip", "deflate"]
            accept = AcceptEncoding.parse(accept_encoding)
            acceptable = {c for c, q in accept.raw if q > 0}
            wildcard_ok = any(c == "*" and q > 0 for c, q in accept.raw)

            best = next((c for c in preference if c in acceptable or (wildcard_ok and c not in {c2 for c2, q in accept.raw if q == 0})), None)

            if best is not None:
                self.compress_with([best], max_offload_filesize=max_offload_filesize)

    def compress_with(self, encodings: Optional[str] = None, *, max_offload_filesize: int = 32768):
        if not (self.compression and not self.compressed and self.body is not None):
            return

        content_encoding = CommaHeader(self.headers.get("Content-Encoding", ""))

        if isinstance(self.body, bytes):
            for encoding in encodings:
                if encoding == "zstd":
                    self.body = zstandard.ZstdCompressor(level=3).compress(self.body)
                elif encoding == "br":
                    self.body = brotlicffi.compress(self.body, quality=4)
                elif encoding == "gzip":
                    self.body = gzip.compress(self.body, compresslevel=6)
                elif encoding == "deflate":
                    self.body = zlib.compress(self.body, level=6)
                else:
                    continue

                content_encoding.append(encoding)
                self.compressed = True

            self.headers.set("Content-Encoding", str(content_encoding))

        elif isinstance(self.body, (str, os.PathLike)):
            filepath = self.body
            filesize = os.stat(filepath).st_size

            if 0 < filesize <= max_offload_filesize:
                with open(filepath, "rb") as f:
                    self.body = f.read()

                self.compress_with(encodings, max_offload_filesize=max_offload_filesize)

    def decompress(self, *, max_offload_filesize: int = 32768):
        if not (self.compression and self.compressed and self.body is not None):
            return

        content_encoding = CommaHeader(self.headers.get("Content-Encoding", ""))

        if isinstance(self.body, bytes):
            for encoding in reversed(content_encoding.raw):
                if encoding == "zstd":
                    self.body = zstandard.ZstdDecompressor().decompress(self.body)
                elif encoding == "br":
                    self.body = brotlicffi.decompress(self.body)
                elif encoding == "gzip":
                    self.body = gzip.decompress(self.body)
                elif encoding == "deflate":
                    try:
                        self.body = zlib.decompress(self.body)
                    except zlib.error:
                        self.body = zlib.decompress(self.body, -zlib.MAX_WBITS)
                else:
                    break

            self.headers.remove("Content-Encoding")
            self.compressed = False

        elif isinstance(self.body, (str, os.PathLike)):
            filepath = self.body
            filesize = os.stat(filepath).st_size

            if 0 < filesize <= max_offload_filesize:
                with open(filepath, "rb") as f:
                    self.body = f.read()

                self.decompress()

@dataclass
class HTTPRequest(HTTPMessage):
    method: HTTPMethod
    target: str

    url: URL = field(init=False, repr=False)

    def __post_init__(self):
        authority = self.headers.get("Host", "")
        self.url = URL.from_target(self.target, self.scheme, authority)

    @property
    def cookies(self) -> Cookie:
        return Cookie(self.headers.get("Cookie", ""))

    @property
    def is_websocket_upgrade(self) -> bool:
        upgrade = self.headers.get("Upgrade", "").lower().strip()
        connection_tokens = CommaHeader(self.headers.get("Connection", "")).raw

        return (self.method == "GET") and (upgrade == "websocket") and any(t.strip().lower() == "upgrade" for t in connection_tokens)

@dataclass
class HTTPResponse(HTTPMessage):
    status_code: int = 200

    range: Optional[Tuple[int, int]] = field(default=None)

    @property
    def etag(self) -> ETag:
        if isinstance(self.body, bytes):
            return ETag(f'"{xxhash.xxh3_128(self.body).hexdigest()}"')

        elif isinstance(self.body, (str, os.PathLike)):
            stat = os.stat(self.body)
            return ETag(f'"{int(stat.st_mtime_ns):x}-{stat.st_size:x}"')

    def set_cookie(self, name: str, value: str, *, expires: Optional[str] = None, max_age: Optional[int] = None, domain: Optional[str] = None, path: Optional[str] = "/", secure: bool = False, httponly: bool = False, samesite: Optional[Literal["Strict", "Lax", "None"]] = None):
        self.headers.append("Set-Cookie", str(SetCookie(name, value, expires=expires, max_age=max_age, domain=domain, path=path, secure=secure, httponly=httponly, samesite=samesite)))

    def delete_cookie(self, name: str, *, domain: Optional[str] = None, path: Optional[str] = "/", secure: bool = False, httponly: bool = False, samesite: Optional[Literal["Strict", "Lax", "None"]] = None):
        self.set_cookie(name, "", max_age=0, domain=domain, path=path, secure=secure, httponly=httponly, samesite=samesite)
