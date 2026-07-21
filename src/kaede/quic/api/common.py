from typing import Optional
from dataclasses import dataclass

from ...models import Limits, Config

@dataclass
class QUICLimits(Limits):
    close_timeout: Optional[float] = 5.0

@dataclass
class QUICConfig(Config):
    pass
