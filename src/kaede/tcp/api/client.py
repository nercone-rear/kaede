from typing import Optional, Union, List, Tuple
from dataclasses import dataclass

from ...tls import TLSConfig
from ...tls.openssl import TLSContext
from ..models import TCPPort
from ..protocol import TCPConnection
from ..tls import TLSConnection

@dataclass
class TCPClientConfig:
    connect_timeout: Optional[float] = 30.0

    tls: Optional[TLSConfig] = None
    alpn: Optional[List[str]] = None
    hostname: Optional[str] = None

class TCPClient:
    def __init__(self, dst: Tuple[str, TCPPort], src: Optional[TCPPort] = None, *, config: Optional[TCPClientConfig] = None):
        self.dst = dst
        self.src = TCPPort(0) if src is None else TCPPort(src) # 0 lets the OS assign an ephemeral port.
        self.config = config or TCPClientConfig()

        self.context = TLSContext(self.config.tls, server=False, alpn=self.config.alpn) if self.config.tls is not None else None
        self.connections: List[Union[TCPConnection, TLSConnection]] = []

    async def __aenter__(self) -> Union[TCPConnection, TLSConnection]:
        return await self.open()

    async def __aexit__(self, *_):
        await self.close()

    async def open(self, dst: Optional[Tuple[str, TCPPort]] = None, src: Optional[TCPPort] = None, *, hostname: Optional[str] = None) -> Union[TCPConnection, TLSConnection]:
        dst = self.dst if dst is None else dst
        src = self.src if src is None else TCPPort(src)

        connection = TCPConnection(("", src), (dst[0], TCPPort(dst[1])))
        await connection.connect(self.config.connect_timeout)

        if self.context is not None:
            try:
                connection = await TLSConnection.connect(connection, hostname=hostname or self.config.hostname or dst[0], timeout=self.config.connect_timeout, context=self.context)

            except BaseException:
                await connection.close()
                raise

        self.connections.append(connection)
        return connection

    async def close(self):
        connections, self.connections = self.connections, []

        for connection in connections:
            await connection.close()
