from dataclasses import dataclass

from ...models import ServerLimits
from .common import IMAPLimits

@dataclass
class IMAPServerLimits(IMAPLimits, ServerLimits):
    pass
