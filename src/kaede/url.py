import urllib.parse
from typing import Optional, List, Dict
from dataclasses import dataclass

from .ip import IPVersion
from .constants import Characters

LITERAL    = frozenset("0123456789abcdefABCDEF:.")
REGISTERED = frozenset("-._~%!$&'()*+,;=") | Characters.DIGIT | Characters.LOWER | Characters.UPPER

@dataclass
class URL:
    scheme: str
    host: str
    port: Optional[int]
    path: str
    query: str
    fragment: str

    def __str__(self) -> str:
        out = self.netloc

        if self.scheme:
            out = f"{self.scheme}://" + out

        if self.path:
            out += self.path

        if self.query:
            out += f"?{self.query}"

        if self.fragment:
            out += f"#{self.fragment}"

        return out

    @property
    def netloc(self) -> str:
        if IPVersion.from_address(self.host) == IPVersion.IPv6:
            return f"[{self.host}]" if self.port is None else f"[{self.host}]:{self.port}"

        return f"{self.host}" if self.port is None else f"{self.host}:{self.port}"

    @property
    def params(self) -> Dict[str, List[str]]:
        found: Dict[str, List[str]] = {}

        for part in self.query.split("&"):
            if not part:
                continue

            key, _, value = part.partition("=")
            found.setdefault(urllib.parse.unquote(key), []).append(urllib.parse.unquote(value))

        return found

    @staticmethod
    def authority(value: str) -> bool:
        if value.startswith("["):
            host, bracket, rest = value[1:].partition("]")

            if not bracket or not host or not LITERAL.issuperset(host):
                return False

            return not rest or (rest.startswith(":") and Characters.DIGIT.issuperset(rest[1:]))

        host, colon, port = value.partition(":")

        if not REGISTERED.issuperset(host):
            return False

        return not colon or Characters.DIGIT.issuperset(port)

    @classmethod
    def parse(cls, *, target: str, scheme: str, authority: str) -> "URL":
        if target.startswith("/"):
            return URL.parse_origin(target=target, scheme=scheme, authority=authority)

        if target == "*":
            return URL.parse_asterisk(scheme=scheme, authority=authority)

        if "://" in target:
            return URL.parse_absolute(target=target)

        return URL.parse_authority(target=target, scheme=scheme)

    @classmethod
    def parse_origin(cls, *, target: str, scheme: str, authority: str) -> "URL":
        location = urllib.parse.urlsplit(f"//{authority}")
        path, _, query = target.partition("?")
        return cls(scheme=scheme, host=location.hostname or "", port=location.port, path=path, query=query, fragment="")

    @classmethod
    def parse_asterisk(cls, *, scheme: str, authority: str) -> "URL":
        location = urllib.parse.urlsplit(f"//{authority}")
        return cls(scheme=scheme, host=location.hostname or "", port=location.port, path="*", query="", fragment="")

    @classmethod
    def parse_absolute(cls, *, target: str) -> "URL":
        parts = urllib.parse.urlsplit(target)
        return cls(scheme=parts.scheme, host=parts.hostname or "", port=parts.port, path=parts.path, query=parts.query, fragment=parts.fragment)

    @classmethod
    def parse_authority(cls, *, target: str, scheme: str) -> "URL":
        peer = urllib.parse.urlsplit(f"//{target}")
        return cls(scheme=scheme, host=peer.hostname or "", port=peer.port, path="", query="", fragment="")
