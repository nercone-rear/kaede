from typing import Optional, Union, List, Tuple
from dataclasses import dataclass, field

from ...models import ClientLimits, ClientConfig
from ...tls.openssl import TLSContext
from ..models import UDPPort
from ..protocol import UDPConnection
from ..tls import DTLSConnection
from .common import UDPLimits, UDPConfig

@dataclass
class UDPClientLimits(UDPLimits, ClientLimits):
    pass

@dataclass
class UDPClientConfig(UDPConfig, ClientConfig):
    limits: UDPClientLimits = field(default_factory=lambda: UDPClientLimits())

    hostname: Optional[str] = None

class UDPClient:
    def __init__(self, dst: Tuple[str, UDPPort], src: Optional[UDPPort] = None, *, config: Optional[UDPClientConfig] = None):
        self.dst = dst
        self.src = UDPPort(0) if src is None else UDPPort(src)
        self.config = config or UDPClientConfig()

        self.context = TLSContext(self.config.tls, server=False, alpn=self.config.alpn, datagram=True) if self.config.tls is not None else None
        self.connections: List[Union[UDPConnection, DTLSConnection]] = []

    async def __aenter__(self) -> Union[UDPConnection, DTLSConnection]:
        return await self.open()

    async def __aexit__(self, *_):
        await self.close()

    async def open(self, dst: Optional[Tuple[str, UDPPort]] = None, src: Optional[UDPPort] = None, *, hostname: Optional[str] = None) -> Union[UDPConnection, DTLSConnection]:
        dst = self.dst if dst is None else dst
        src = self.src if src is None else UDPPort(src)

        connection = UDPConnection(("", src), (dst[0], UDPPort(dst[1])))
        await connection.connect(self.config.limits.timeout_connection)

        if self.context is not None:
            try:
                connection = await DTLSConnection.connect(connection, hostname=hostname or self.config.hostname or dst[0], timeout=self.config.limits.timeout_connection, context=self.context)

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
