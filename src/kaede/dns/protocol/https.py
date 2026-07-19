from typing import Optional, Callable, Tuple

from ...tls import TLSConfig
from ..models import DNSMessage
from ..errors import DNSError, DNSFormatError, DNSConnectionError, DNSServerError, DNSTimeoutError
from .handler import DNSTransport

class DNSHTTPSTransport(DNSTransport):
    def __init__(self, dst: Tuple[str, int], *, path: str = "/dns-query", tls: Optional[TLSConfig] = None, hostname: Optional[str] = None, connect_timeout: float = 5.0):
        from ...http.api.client import HTTPClient, HTTPClientConfig

        self.host = hostname or dst[0]
        self.url = f"https://{self.host}{'' if dst[1] == 443 else f':{dst[1]}'}{path}"

        self.client = HTTPClient(config=HTTPClientConfig(versions=["HTTP/2.0", "HTTP/1.1"], tls=tls or TLSConfig(), connect_timeout=connect_timeout))

    async def query(self, message: DNSMessage, *, timeout: float = 3.0) -> DNSMessage:
        message.id = 0

        from ...http.errors import HTTPError

        try:
            connection = await self.client.post(
                self.url,
                headers={"Accept": "application/dns-message", "Content-Type": "application/dns-message"},
                body=message.pack(),
                timeout=timeout
            )
            response = await connection.receive()

        except HTTPError as e:
            raise DNSConnectionError(f"The DoH exchange with {self.host} failed: {e}") from e

        if response.status_code != 200:
            raise DNSServerError(f"{self.host} answered the DoH query with HTTP {response.status_code}.")

        if not isinstance(response.body, bytes):
            raise DNSFormatError(f"{self.host} answered the DoH query without a message body.")

        answer = DNSMessage.unpack(response.body)

        if answer.id != 0:
            raise DNSFormatError(f"{self.host} answered over DoH with the message ID {answer.id} rather than 0.")

        if not message.matches(answer):
            raise DNSFormatError(f"{self.host} answered over DoH with a message that does not match the query.")

        return answer

    async def close(self):
        await self.client.close()

class DNSHTTPSHandler:
    MEDIA = "application/dns-message"

    def __init__(self, resolve: Callable):
        self.resolve = resolve # (query: DNSMessage) -> DNSMessage (may be async)

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
            answer = self.resolve(query)

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

            return base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))

        raise HTTPError(405, "Method Not Allowed")

    async def on_websocket(self, connection):
        await connection.close(1011, "WebSocket is not part of DoH.")
