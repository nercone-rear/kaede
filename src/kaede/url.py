import urllib.parse
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass

from .constants import Characters

@dataclass
class URL:
    scheme: str
    host: str
    port: Optional[int]
    path: str
    query: str
    fragment: str

    DEFAULT_PORTS = {"http": 80, "ws": 80, "https": 443, "wss": 443, "dns": 53, "ftp": 21}

    LITERAL    = frozenset("0123456789abcdefABCDEF:.")
    REGISTERED = frozenset("-._~%!$&'()*+,;=") | Characters.DIGIT | Characters.LOWER | Characters.UPPER

    def __str__(self) -> str:
        location = self.netloc
        value = f"{self.scheme}://{location}" if self.scheme else location
        value += self.path or ("/" if location else "")

        if self.query:
            value += f"?{self.query}"

        if self.fragment:
            value += f"#{self.fragment}"

        return value

    @property
    def params(self) -> Dict[str, List[str]]:
        found: Dict[str, List[str]] = {}

        for part in self.query.split("&"):
            if not part:
                continue

            name, _, value = part.partition("=")
            found.setdefault(urllib.parse.unquote(name), []).append(urllib.parse.unquote(value))

        return found

    @property
    def netloc(self) -> str:
        location = f"[{self.host}]" if ":" in self.host else self.host

        if self.port is not None and URL.DEFAULT_PORTS.get(self.scheme) != self.port:
            location += f":{self.port}"

        return location

    @staticmethod
    def authority(value: str) -> bool:
        if value.startswith("["):
            host, bracket, rest = value[1:].partition("]")

            if not bracket or not host or not URL.LITERAL.issuperset(host):
                return False

            return not rest or (rest.startswith(":") and Characters.DIGIT.issuperset(rest[1:]))

        host, colon, port = value.partition(":")

        if not URL.REGISTERED.issuperset(host):
            return False

        return not colon or Characters.DIGIT.issuperset(port)

    @classmethod
    def parse(cls, value: str) -> "URL":
        parts = urllib.parse.urlsplit(value)

        return cls(scheme=parts.scheme, host=parts.hostname or "", port=parts.port, path=parts.path, query=parts.query, fragment=parts.fragment)

    @classmethod
    def from_target(cls, target: str, scheme: str, authority: str) -> "URL":
        location = urllib.parse.urlsplit(f"//{authority}")

        if target.startswith("/"): # origin-form: absolute-path [ "?" query ]
            # RFC 9112 section 3.2.1 makes the whole target a literal path, so it
            # must not be run through urlsplit: a target of "//host/path" would
            # otherwise have "host" read as an authority and silently dropped,
            # leaving url.path disagreeing with the target on the wire.
            path, _, query = target.partition("?")
            return cls(scheme=scheme, host=location.hostname or "", port=location.port, path=path, query=query, fragment="")

        if target == "*": # asterisk-form
            return cls(scheme=scheme, host=location.hostname or "", port=location.port, path="*", query="", fragment="")

        if "://" in target: # absolute-form
            # The scheme in an absolute-form target is meaningful (a forward
            # proxy uses it to reach the origin), so it is kept as written; the
            # transport's own scheme is available separately as request.secure.
            return cls.parse(target)

        peer = urllib.parse.urlsplit(f"//{target}") # authority-form
        return cls(scheme=scheme, host=peer.hostname or "", port=peer.port, path="", query="", fragment="")
