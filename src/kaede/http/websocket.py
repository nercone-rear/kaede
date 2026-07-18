from typing import Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from .models import HTTPPort
    from .protocol import HTTPConnection

class WSConnection:
    def __init__(self, src: Tuple[str, "HTTPPort"], dst: Tuple[str, "HTTPPort"], *, transport: "HTTPConnection"):
        self.src = src
        self.dst = dst

        self.transport = transport

    async def read(self, size: int = -1) -> Optional[bytes]:
        raise NotImplementedError()

    async def write(self, data: bytes):
        raise NotImplementedError()

    def ping(self, payload: bytes = b""):
        raise NotImplementedError()

    def close(self, code: int = 1000, reason: str = ""):
        raise NotImplementedError()
