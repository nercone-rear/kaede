from dataclasses import dataclass

from ...models import Limits, Config

@dataclass
class DNSLimits(Limits):
    pass

@dataclass
class DNSConfig(Config):
    pass
