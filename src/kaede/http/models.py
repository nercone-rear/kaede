import os
import json
import xxhash
import ipaddress
from enum import Enum
from typing import Any, Optional, Literal, List, Dict, Tuple, Union, TypeVar
from dataclasses import dataclass, field
from collections.abc import AsyncIterator

from ..url import URL
from ..tcp import TCPPort
from ..udp import UDPPort
from ..protocol import Limits
from .headers import CommaHeader, ETag, Cookie, SetCookie

T = TypeVar("T")

HTTPVersion = Literal["HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0"]
HTTPMethod  = Literal["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]

class HTTPBroadRole(Enum):
    CLIENT = "Client"
    SERVER = "Server"

    def valid(self, specific: "HTTPRole") -> bool:
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

    def valid(self, broad: "HTTPBroadRole") -> bool:
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
    def valid(self) -> bool:
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
        if version in ("HTTP/1.0", "HTTP/1.1"):
            return HTTPHeaderCase.TITLECASE
        elif version in ("HTTP/2.0", "HTTP/3.0"):
            return HTTPHeaderCase.LOWERCASE

class HTTPHeaders:
    def __init__(self, value: Union[str, bytes, List, Dict, Tuple[Tuple[str, List, Dict, Tuple[str]]]], case: Optional[HTTPHeaderCase] = None):
        raise NotImplementedError()

    def __getitem__(self, key: str) -> Optional[List[str]]:
        raise NotImplementedError()

    def __setitem__(self, key: str, value: Union[str, List, Dict, Tuple[str]]):
        raise NotImplementedError()

    def __contains__(self, item: str):
        raise NotImplementedError()

    def items(self) -> List[Tuple[str, str]]:
        raise NotImplementedError()

    def get(self, key: str, default: Optional[T] = None) -> Optional[Union[str, T]]:
        raise NotImplementedError()

    def set(self, key: str, value: Union[str, List, Dict, Tuple[str]], override: bool = True):
        raise NotImplementedError()

    def append(self, key: str, value: str):
        raise NotImplementedError()

    def remove(self, key: str):
        raise NotImplementedError()

    @classmethod
    def parse(cls, value: Union[str, bytes], version: HTTPVersion) -> "HTTPHeaders":
        raise NotImplementedError()

    def build(self) -> str:
        raise NotImplementedError()

@dataclass
class HTTPLimits(Limits):
    max_message_size: int = 1073741824 # in bytes, The total size of the HTTP message allowed for reception.
    max_message_offload_size: int = 98304 # in bytes, The total size of an HTTP message that can be held in memory.

    max_message_body_size: int = 1073741824 # in bytes, The size of the HTTP message body allowed for reception.
    max_message_body_offload_size: int = 65536 # in bytes, The size of the HTTP message body that can be held in memory.

@dataclass
class HTTPMessage:
    version: HTTPVersion = "HTTP/1.1"

    headers: Optional[HTTPHeaders] = None
    trailers: Optional[HTTPHeaders] = None

    body: Optional[Union[str, bytes, AsyncIterator[bytes]]] = None

    secure: bool = False

    early_data: bool = False

    compression: bool = True
    compressed:  bool = False

    @property
    def text(self) -> str:
        return self.body.decode()

    @property
    def json(self) -> Any:
        return json.loads(self.text)

    def offload(self, limits: HTTPLimits) -> Optional[bytes]:
        if isinstance(self.body, str):
            filepath = self.body
            filesize = os.stat(filepath).st_size

            if 0 < filesize <= limits.max_message_body_offload_size:
                with open(filepath, "rb") as f:
                    self.body = f.read()

        if isinstance(self.body, bytes):
            return self.body

@dataclass
class HTTPRequest(HTTPMessage):
    client: Tuple[Union[ipaddress.IPv4Address, ipaddress.IPv6Address], int] = field(default_factory=lambda: (ipaddress.IPv4Address("0.0.0.0"), 0))

    method: HTTPMethod = "GET"
    target: str = "/"

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
