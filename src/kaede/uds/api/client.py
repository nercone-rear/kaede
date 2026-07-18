from typing import Optional, List
from dataclasses import dataclass

from ..models import UDSAddress
from ..protocol import UDSConnection

@dataclass
class UDSClientConfig:
    connect_timeout: Optional[float] = 30.0

class UDSClient:
    def __init__(self, dst: UDSAddress, *, config: Optional[UDSClientConfig] = None):
        self.dst = UDSAddress(dst)
        self.config = config or UDSClientConfig()

        self.connections: List[UDSConnection] = []

    async def __aenter__(self) -> UDSConnection:
        return await self.open()

    async def __aexit__(self, *_):
        await self.close()

    async def open(self, dst: Optional[UDSAddress] = None) -> UDSConnection:
        dst = self.dst if dst is None else UDSAddress(dst)

        connection = UDSConnection(UDSAddress(""), dst)
        await connection.connect(self.config.connect_timeout)

        self.connections.append(connection)
        return connection

    async def close(self):
        connections, self.connections = self.connections, []

        for connection in connections:
            await connection.close()
