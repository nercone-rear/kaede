from dataclasses import dataclass

from ...models import ServerLimits
from .common import SMTPLimits

@dataclass
class SMTPServerLimits(SMTPLimits, ServerLimits):
    pass
