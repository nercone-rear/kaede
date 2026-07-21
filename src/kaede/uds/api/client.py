from typing import Optional, List
from dataclasses import dataclass, field

from ...models import ClientLimits
from ..models import UDSPort
from ..protocol import UDSConnection
from .common import UDSLimits, UDSConfig

@dataclass
class UDSClientLimits(UDSLimits, ClientLimits):
    pass

@dataclass
class UDSClientConfig(UDSConfig):
    limits: UDSClientLimits = field(default_factory=lambda: UDSClientLimits())

class UDSClient:
    def __init__(self, dst: UDSPort, *, config: Optional[UDSClientConfig] = None):
        self.dst = UDSPort(dst)
        self.config = config or UDSClientConfig()

        self.connections: List[UDSConnection] = []

    async def __aenter__(self) -> UDSConnection:
        return await self.open()

    async def __aexit__(self, *_):
        await self.close()

    async def open(self, dst: Optional[UDSPort] = None) -> UDSConnection:
        connection = UDSConnection(UDSPort(""), self.dst if dst is None else UDSPort(dst), limits=self.config.limits)
        await connection.connect(self.config.limits.timeout_connection)

        self.connections = [kept for kept in self.connections if not kept.closed]
        self.connections.append(connection)

        while len(self.connections) > self.config.limits.max_connection_keep:
            await self.connections.pop(0).close()

        return connection

    async def close(self):
        connections, self.connections = self.connections, []

        for connection in connections:
            await connection.close()
