from dataclasses import dataclass

from ...models import Limits, Config

@dataclass
class UDSLimits(Limits):
    max_buffer_size: int = 65536

@dataclass
class UDSConfig(Config):
    pass
