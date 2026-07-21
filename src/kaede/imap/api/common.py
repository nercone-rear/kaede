from dataclasses import dataclass

from ...models import Limits, Config

@dataclass
class IMAPLimits(Limits):
    pass

@dataclass
class IMAPConfig(Config):
    pass
