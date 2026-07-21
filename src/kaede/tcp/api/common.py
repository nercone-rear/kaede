from dataclasses import dataclass

from ...models import Limits, Config

@dataclass
class TCPLimits(Limits):
    max_buffer_size: int = 65536

@dataclass
class TCPConfig(Config):
    pass
