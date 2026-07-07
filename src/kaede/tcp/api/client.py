import random
from typing import Optional, Tuple

from ..models import TCPPort

class TCPClient:
    def __init__(self, dst: Tuple[str, TCPPort], src: Optional[TCPPort] = None):
        self.dst = dst
        self.src = src or random.randint(0, 65535)

    async def open(self, dst: Optional[Tuple[str, TCPPort]] = None, src: Optional[TCPPort] = None):
        ...

    async def close(self):
        ...
