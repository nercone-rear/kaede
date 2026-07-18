import time
from typing import Optional, Dict, Tuple
from dataclasses import dataclass

@dataclass
class HSTSPolicy:
    max_age: int = 31536000 # in seconds
    include_subdomains: bool = False
    preload: bool = False

    def build(self) -> str:
        value = f"max-age={self.max_age}"

        if self.include_subdomains:
            value += "; includeSubDomains"

        if self.preload:
            value += "; preload"

        return value

    @classmethod
    def parse(cls, value: str) -> "HSTSPolicy":
        policy = cls(max_age=0)

        for directive in value.split(";"):
            name, _, raw = directive.partition("=")
            name = name.strip().lower()

            if name == "max-age":
                digits = raw.strip().strip('"')
                policy.max_age = int(digits) if digits.isdigit() else 0
            elif name == "includesubdomains":
                policy.include_subdomains = True
            elif name == "preload":
                policy.preload = True

        return policy

class HSTSStore:
    def __init__(self):
        self.entries: Dict[str, Tuple[float, bool]] = {}

    def remember(self, host: str, policy: HSTSPolicy, now: Optional[float] = None):
        host = host.lower().rstrip(".")

        if policy.max_age <= 0:
            self.entries.pop(host, None)
            return

        self.entries[host] = ((time.monotonic() if now is None else now) + policy.max_age, policy.include_subdomains)

    def learn(self, host: str, header: str, *, secure: bool = True, now: Optional[float] = None):
        if secure:
            self.remember(host, HSTSPolicy.parse(header), now)

    def secure(self, host: str, now: Optional[float] = None) -> bool:
        host = host.lower().rstrip(".")
        moment = time.monotonic() if now is None else now

        for name, (expires, subdomains) in list(self.entries.items()):
            if expires <= moment:
                del self.entries[name]
                continue

            if host == name or (subdomains and host.endswith("." + name)):
                return True

        return False
