from dataclasses import dataclass

from ...models import ServerLimits
from .common import POPLimits

@dataclass
class POPServerLimits(POPLimits, ServerLimits):
    pass
