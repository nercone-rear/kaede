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
from ..constants import Characters
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
    TOKEN = frozenset("!#$%&'*+-.^_`|~") | Characters.DIGIT | Characters.LOWER | Characters.UPPER

    UNTRAILABLE = frozenset({
        "transfer-encoding", "content-length", "content-encoding", "content-type", "content-range",
        "host", "cache-control", "expect", "max-forwards", "te", "trailer",
        "authorization", "proxy-authorization", "set-cookie", "cookie",
    })

    def __init__(self, value: Union[str, bytes, "HTTPHeaders", List, Dict, Tuple] = (), case: Optional[HTTPHeaderCase] = None):
        self.case = case
        self.fields: List[Tuple[str, str]] = []

        if isinstance(value, (str, bytes)):
            self.fields = HTTPHeaders.parse(value, "HTTP/1.1").fields
        elif isinstance(value, HTTPHeaders):
            self.fields = list(value.fields)
        elif isinstance(value, dict):
            for name, entry in value.items():
                self.set(name, entry)
        else:
            for name, entry in value:
                self.append(name, entry)

    def __getitem__(self, key: str) -> Optional[List[str]]:
        found = [value for name, value in self.fields if name.lower() == key.lower()]

        return found or None

    def __setitem__(self, key: str, value: Union[str, List, Dict, Tuple[str]]):
        self.set(key, value)

    def __contains__(self, item: str) -> bool:
        return any(name.lower() == item.lower() for name, _ in self.fields)

    def __iter__(self):
        return iter(self.fields)

    def __len__(self) -> int:
        return len(self.fields)

    def __eq__(self, other) -> bool:
        return isinstance(other, HTTPHeaders) and self.fields == other.fields

    def __repr__(self) -> str:
        return f"HTTPHeaders({self.fields!r})"

    def items(self) -> List[Tuple[str, str]]:
        return list(self.fields)

    def get(self, key: str, default: Optional[T] = None) -> Optional[Union[str, T]]:
        for name, value in self.fields:
            if name.lower() == key.lower():
                return value

        return default

    def values(self, key: str) -> List[str]:
        return [value for name, value in self.fields if name.lower() == key.lower()]

    def set(self, key: str, value: Union[str, List, Dict, Tuple[str]], override: bool = True):
        if not override and key in self:
            return

        entries = value if isinstance(value, (list, tuple)) else [value]

        self.remove(key)

        for entry in entries:
            self.append(key, entry)

    def append(self, key: str, value: str):
        self.fields.append((HTTPHeaders.token(key), HTTPHeaders.clean(key, value)))

    def remove(self, key: str):
        self.fields = [(name, value) for name, value in self.fields if name.lower() != key.lower()]

    @staticmethod
    def token(name: str) -> str:
        if not name or any(character not in HTTPHeaders.TOKEN for character in name):
            raise ValueError(f"{name!r} is not a valid header field name.")

        return name

    def trailing(self) -> Optional[str]:
        return next((name for name, _ in self.fields if name.startswith(":") or name.lower() in HTTPHeaders.UNTRAILABLE), None)

    @staticmethod
    def spaced(value: str) -> bool:
        return isinstance(value, str) and value != value.strip(" \t")

    @staticmethod
    def clean(name: str, value: str) -> str:
        text = value if isinstance(value, str) else str(value)
        text = text.strip(" \t")

        for character in text:
            point = ord(character)

            if point == 0x7F or (point < 0x20 and character not in "\t"):
                raise ValueError(f"The value of the {name!r} header carries the control character {point:#04x}.")

        return text

    @classmethod
    def parse(cls, value: Union[str, bytes], version: HTTPVersion) -> "HTTPHeaders":
        text = value.decode("latin-1") if isinstance(value, (bytes, bytearray)) else value
        headers = cls(case=HTTPHeaderCase.from_version(version))

        for line in text.split("\r\n"):
            if not line:
                continue

            if line[0] in " \t":
                raise ValueError("A header field uses obsolete line folding.")

            name, colon, entry = line.partition(":")

            if not colon:
                raise ValueError(f"The header line {line!r} has no colon.")

            if name != name.rstrip():
                raise ValueError(f"The header field {name!r} has whitespace before its colon.")

            headers.append(name, entry.strip(" \t"))

        return headers

    def build(self) -> str:
        case = self.case or HTTPHeaderCase.TITLECASE

        return "".join(f"{case.apply(name)}: {value}\r\n" for name, value in self.fields)

@dataclass
class HTTPLimits(Limits):
    max_message_size: int = 1073741824    # in bytes, The total size of the HTTP message allowed for reception.
    max_message_offload_size: int = 98304 # in bytes, The total size of an HTTP message that can be held in memory.

    max_message_body_size: int = 1073741824    # in bytes, The size of the HTTP message body allowed for reception.
    max_message_body_offload_size: int = 65536 # in bytes, The size of the HTTP message body that can be held in memory.

    max_startline_size: int = 8192  # in bytes, the request/status line ceiling
    max_headers_size:   int = 65536 # in bytes, the whole header (or trailer) block
    max_header_count:   int = 128   # the number of header fields allowed in one block
    max_chunk_ext_size: int = 4096  # in bytes, one chunk size line with its extensions

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
        if isinstance(self.body, bytes):
            return self.body.decode()

        return self.body if isinstance(self.body, str) else ""

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
        if self.headers is None:
            self.headers = HTTPHeaders()

        self.refresh()

    def refresh(self):
        self.url = URL.from_target(self.target, self.scheme, self.headers.get("Host", ""))

    @property
    def scheme(self) -> str:
        return "https" if self.secure else "http"

    @property
    def cookies(self) -> Cookie:
        return Cookie("; ".join(self.headers.values("Cookie")))

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
