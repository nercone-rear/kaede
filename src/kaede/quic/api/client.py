from typing import Optional, List, Tuple
from dataclasses import dataclass, field

from ...models import ClientLimits, ClientConfig
from ...tls import TLSConfig
from ...udp.models import UDPPort
from ...udp.protocol import UDPConnection
from ..tls import QUICContext
from ..protocol import QUICConnection
from .common import QUICLimits, QUICConfig

@dataclass
class QUICClientLimits(QUICLimits, ClientLimits):
    pass

@dataclass
class QUICClientConfig(QUICConfig, ClientConfig):
    limits: QUICClientLimits = field(default_factory=lambda: QUICClientLimits())

    hostname: Optional[str] = None
    ech: Optional[bytes] = None

class QUICClient:
    def __init__(self, dst: Tuple[str, UDPPort], src: Optional[UDPPort] = None, *, config: Optional[QUICClientConfig] = None):
        self.dst = dst
        self.src = UDPPort(0) if src is None else UDPPort(src)
        self.config = config or QUICClientConfig()

        self.context = QUICContext(self.config.tls or TLSConfig(), server=False, alpn=self.config.alpn)
        self.connections: List[QUICConnection] = []

    async def __aenter__(self) -> QUICConnection:
        return await self.open()

    async def __aexit__(self, *_):
        await self.close()

    async def open(self, dst: Optional[Tuple[str, UDPPort]] = None, src: Optional[UDPPort] = None, *, hostname: Optional[str] = None, ech: Optional[bytes] = None) -> QUICConnection:
        dst = self.dst if dst is None else dst
        src = self.src if src is None else UDPPort(src)

        transport = UDPConnection(("", src), (dst[0], UDPPort(dst[1])))
        await transport.connect(self.config.limits.timeout_connection)

        try:
            connection = await QUICConnection.connect(transport, hostname=hostname or self.config.hostname or dst[0], ech=ech or self.config.ech, timeout=self.config.limits.timeout_connection, context=self.context)

        except BaseException:
            await transport.close()
            raise

        self.connections = [kept for kept in self.connections if not kept.closed]
        self.connections.append(connection)

        while len(self.connections) > self.config.limits.max_connection_keep:
            kept = self.connections.pop(0)
            await kept.close(timeout=self.config.limits.close_timeout)
            await kept.endpoint.close()

        return connection

    async def close(self):
        connections, self.connections = self.connections, []

        for connection in connections:
            await connection.close(timeout=self.config.limits.close_timeout)
            await connection.endpoint.close()
