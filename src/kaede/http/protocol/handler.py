from typing import Optional

from ...uds import UDSHandler
from ...tcp import TCPHandler
from ...quic import QUICHandler

class HUHandler(UDSHandler):
    def __init__(self, server: "object"):
        super().__init__(self.handle)
        self.server = server

    async def handle(self, connection):
        await self.server.serve_stream(connection, secure=False)

class HTHandler(TCPHandler):
    def __init__(self, server: "object", *, secure: bool = False):
        super().__init__(self.handle)
        self.server = server
        self.secure = secure

    async def handle(self, connection):
        await self.server.serve_stream(connection, secure=self.secure)

class HQHandler(QUICHandler):
    def __init__(self, server: "object"):
        super().__init__(self.handle)
        self.server = server

    async def handle(self, connection):
        await self.server.serve_quic(connection)
