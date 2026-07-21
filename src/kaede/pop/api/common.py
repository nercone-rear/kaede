from dataclasses import dataclass

from ...models import Limits, Config

@dataclass
class POPLimits(Limits):
    pass

@dataclass
class POPConfig(Config):
    pass
