
from ...uds import UDSHandler
from ...tcp import TCPHandler
from ...quic import QUICHandler

class HTTPUDSHandler(UDSHandler):
    def __init__(self, server: "object"):
        super().__init__(self.handle)
        self.server = server

    async def handle(self, connection):
        await self.server.serve_stream(connection)

class HTTPTCPHandler(TCPHandler):
    def __init__(self, server: "object"):
        super().__init__(self.handle)
        self.server = server

    async def handle(self, connection):
        await self.server.serve_stream(connection)

class HTTPQUICHandler(QUICHandler):
    def __init__(self, server: "object"):
        super().__init__(self.handle)
        self.server = server

    async def handle(self, connection):
        await self.server.serve_quic(connection)
