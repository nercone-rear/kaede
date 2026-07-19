import time
import ipaddress
from typing import Optional, Dict, Tuple
from dataclasses import dataclass

from ...constants import Digits

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
    def parse(cls, value: str) -> Optional["HSTSPolicy"]:
        policy = cls(max_age=-1)
        seen = set()

        for directive in value.split(";"):
            name, equals, raw = directive.partition("=")
            name = name.strip().lower()

            if not name:
                continue

            if name in seen:
                return None

            seen.add(name)

            if name == "max-age":
                digits = raw.strip()
                digits = digits[1:-1] if len(digits) >= 2 and digits.startswith('"') and digits.endswith('"') else digits
                age = Digits.decimal(digits) if equals else None

                if age is None:
                    return None

                policy.max_age = age

            elif name == "includesubdomains":
                policy.include_subdomains = True

            elif name == "preload":
                policy.preload = True

        return policy if policy.max_age >= 0 else None

class HSTSStore:
    def __init__(self):
        self.entries: Dict[str, Tuple[float, bool]] = {}

    def normalize(self, host: str) -> Optional[str]:
        host = host.strip().strip("[]").rstrip(".")

        if not host:
            return None

        try:
            ipaddress.ip_address(host)
            return None

        except ValueError:
            pass

        try:
            return host.encode("idna").decode("ascii").lower()

        except UnicodeError:
            return host.lower()

    def remember(self, host: str, policy: HSTSPolicy, now: Optional[float] = None):
        name = self.normalize(host)

        if name is None:
            return

        if policy.max_age <= 0:
            self.entries.pop(name, None)
            return

        self.entries[name] = ((time.monotonic() if now is None else now) + policy.max_age, policy.include_subdomains)

    def learn(self, host: str, header: str, *, secure: bool = True, now: Optional[float] = None):
        if not secure:
            return

        policy = HSTSPolicy.parse(header)

        if policy is not None:
            self.remember(host, policy, now)

    def secure(self, host: str, now: Optional[float] = None) -> bool:
        name = self.normalize(host)

        if name is None:
            return False

        moment = time.monotonic() if now is None else now

        for stored, (expires, subdomains) in list(self.entries.items()):
            if expires <= moment:
                del self.entries[stored]
                continue

            if name == stored or (subdomains and name.endswith("." + stored)):
                return True

        return False
