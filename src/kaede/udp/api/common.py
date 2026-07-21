from dataclasses import dataclass

from ...models import Limits, Config

@dataclass
class UDPLimits(Limits):
    pass

@dataclass
class UDPConfig(Config):
    pass
