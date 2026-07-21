from typing import Optional, Union, List, Tuple
from dataclasses import dataclass, field

from ...models import ClientLimits, ClientConfig
from ...tls.openssl import TLSContext
from ..models import TCPPort
from ..protocol import TCPConnection
from ..tls import TLSConnection
from .common import TCPLimits, TCPConfig

@dataclass
class TCPClientLimits(TCPLimits, ClientLimits):
    pass

@dataclass
class TCPClientConfig(TCPConfig, ClientConfig):
    limits: TCPClientLimits = field(default_factory=lambda: TCPClientLimits())

    hostname: Optional[str] = None
    ech: Optional[bytes] = None

class TCPClient:
    def __init__(self, dst: Tuple[str, TCPPort], src: Optional[TCPPort] = None, *, config: Optional[TCPClientConfig] = None):
        self.dst = dst
        self.src = TCPPort(0) if src is None else TCPPort(src)
        self.config = config or TCPClientConfig()

        self.context = TLSContext(self.config.tls, server=False, alpn=self.config.alpn) if self.config.tls is not None else None
        self.connections: List[Union[TCPConnection, TLSConnection]] = []

    async def __aenter__(self) -> Union[TCPConnection, TLSConnection]:
        return await self.open()

    async def __aexit__(self, *_):
        await self.close()

    async def open(self, dst: Optional[Tuple[str, TCPPort]] = None, src: Optional[TCPPort] = None, *, hostname: Optional[str] = None, ech: Optional[bytes] = None) -> Union[TCPConnection, TLSConnection]:
        dst = self.dst if dst is None else dst
        src = self.src if src is None else TCPPort(src)

        connection = TCPConnection(("", src), (dst[0], TCPPort(dst[1])), limits=self.config.limits)
        await connection.connect(self.config.limits.timeout_connection)

        if self.context is not None:
            try:
                connection = await TLSConnection.connect(connection, hostname=hostname or self.config.hostname or dst[0], ech=ech or self.config.ech, timeout=self.config.limits.timeout_connection, context=self.context)

            except BaseException:
                await connection.close()
                raise

        self.connections = [kept for kept in self.connections if not kept.closed]
        self.connections.append(connection)

        while len(self.connections) > self.config.limits.max_connection_keep:
            await self.connections.pop(0).close()

        return connection

    async def close(self):
        connections, self.connections = self.connections, []

        for connection in connections:
            await connection.close()
