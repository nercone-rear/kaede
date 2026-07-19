from typing import Optional, List, Tuple
from dataclasses import dataclass

from ...tls import TLSConfig
from ...udp.models import UDPPort
from ...udp.protocol import UDPConnection
from ..tls import QUICContext
from ..protocol import QUICConnection

@dataclass
class QUICClientConfig:
    connect_timeout: Optional[float] = 30.0

    tls: Optional[TLSConfig] = None

    alpn: Optional[List[str]] = None
    hostname: Optional[str] = None

class QUICClient:
    def __init__(self, dst: Tuple[str, UDPPort], src: Optional[UDPPort] = None, *, config: Optional[QUICClientConfig] = None):
        self.dst = dst
        self.src = UDPPort(0) if src is None else UDPPort(src) # 0 lets the OS assign an ephemeral port.
        self.config = config or QUICClientConfig()

        self.context = QUICContext(self.config.tls or TLSConfig(), server=False, alpn=self.config.alpn)
        self.connections: List[QUICConnection] = []

    async def __aenter__(self) -> QUICConnection:
        return await self.open()

    async def __aexit__(self, *_):
        await self.close()

    async def open(self, dst: Optional[Tuple[str, UDPPort]] = None, src: Optional[UDPPort] = None, *, hostname: Optional[str] = None) -> QUICConnection:
        dst = self.dst if dst is None else dst
        src = self.src if src is None else UDPPort(src)

        transport = UDPConnection(("", src), (dst[0], UDPPort(dst[1])))
        await transport.connect(self.config.connect_timeout)

        try:
            connection = await QUICConnection.connect(transport, hostname=hostname or self.config.hostname or dst[0], timeout=self.config.connect_timeout, context=self.context)

        except BaseException:
            await transport.close()
            raise

        self.connections.append(connection)
        return connection

    async def close(self):
        connections, self.connections = self.connections, []

        for connection in connections:
            await connection.close()
            await connection.endpoint.close()
