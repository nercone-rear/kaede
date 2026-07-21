from dataclasses import dataclass

from ...models import Limits, Config

@dataclass
class SMTPLimits(Limits):
    pass

@dataclass
class SMTPConfig(Config):
    pass
