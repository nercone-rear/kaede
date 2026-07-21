import asyncio

from ...udp import UDPHandler
from ...tcp import TCPHandler
from ...quic import QUICHandler
from ...quic.errors import QUICError
from ..models import DNSMessage
from ..errors import DNSError
from .udp import DNSUDPConnection
from .tcp import DNSTCPConnection
from .tls import DNSTLSConnection
from .quic import DNSQUICConnection

class DNSUDPHandler(UDPHandler):
    def __init__(self, server: "object"):
        super().__init__(self.handle)
        self.server = server

    async def handle(self, connection):
        await self.server.converse(DNSUDPConnection(connection, server=True))

class DNSTCPHandler(TCPHandler):
    def __init__(self, server: "object"):
        super().__init__(self.handle)
        self.server = server

    async def handle(self, connection):
        await self.server.converse(DNSTCPConnection(connection, server=True))

class DNSTLSHandler(TCPHandler):
    def __init__(self, server: "object"):
        super().__init__(self.handle)
        self.server = server

    async def handle(self, connection):
        await self.server.converse(DNSTLSConnection(connection, server=True))

class DNSQUICHandler(QUICHandler):
    def __init__(self, server: "object"):
        super().__init__(self.handle)
        self.server = server

    async def handle(self, connection):
        tasks = set()

        try:
            while True:
                stream = await connection.accept(timeout=self.server.config.limits.idle_timeout)

                task = asyncio.ensure_future(self.server.confer(DNSQUICConnection(connection, stream, server=True)))
                tasks.add(task)
                task.add_done_callback(tasks.discard)

        except QUICError:
            pass

        finally:
            for task in set(tasks):
                task.cancel()

class DNSHTTPSHandler:
    MEDIA = "application/dns-message"

    def __init__(self, server: "object"):
        self.server = server

    async def on_connection(self, connection):
        import base64
        from ...http.models import HTTPResponse, HTTPHeaders
        from ...http.errors import HTTPError
        from ...http.finalizer import finalize_response

        request = await connection.receive()

        try:
            wire = self.extract(request, base64)

        except HTTPError as e:
            await connection.send(await finalize_response(HTTPResponse(status_code=e.code, headers=HTTPHeaders(), body=(e.message or "").encode(), compression=False)))
            return

        try:
            query = DNSMessage.unpack(wire)
            answer = self.server.resolve(query)

            if hasattr(answer, "__await__"):
                answer = await answer

        except DNSError:
            answer = DNSMessage(response=True, rcode=1)

        headers = HTTPHeaders([("Content-Type", DNSHTTPSHandler.MEDIA)])
        await connection.send(await finalize_response(HTTPResponse(status_code=200, headers=headers, body=answer.pack(), compression=False)))

    def extract(self, request, base64) -> bytes:
        from ...http.errors import HTTPError

        if request.method == "POST":
            if request.headers.get("Content-Type", "").split(";")[0].strip().lower() != DNSHTTPSHandler.MEDIA:
                raise HTTPError(415, "Unsupported Media Type")

            return request.body if isinstance(request.body, bytes) else b""

        if request.method == "GET":
            encoded = request.url.params.get("dns", [""])[0]

            if not encoded:
                raise HTTPError(400, "Bad Request")

            try:
                return base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))

            except (ValueError, TypeError):
                raise HTTPError(400, "Bad Request")

        raise HTTPError(405, "Method Not Allowed")

    async def on_websocket(self, connection):
        await connection.close(1011, "WebSocket is not part of DoH.")
