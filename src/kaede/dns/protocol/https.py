from typing import Optional, Tuple, TYPE_CHECKING

from ...tls import TLSConfig
from ..models import DNSMessage
from ..errors import DNSFormatError, DNSConnectionError, DNSServerError, DNSClosedError
from .base import DNSConnection, DNSProtocol

if TYPE_CHECKING:
    from ..api.client import DNSClientLimits

class DNSHTTPSConnection(DNSConnection):
    def __init__(self, query: bytes, client: Tuple[str, int] = ("", 0)):
        super().__init__(None, stream=True, server=True)

        self.incoming = bytearray(len(query).to_bytes(2, "big") + query)
        self.reply: Optional[bytes] = None
        self.dst = client

    @property
    def client(self) -> Tuple[str, int]:
        return self.dst

    @property
    def closed(self) -> bool:
        return self.reply is not None

    async def framed(self) -> bytes:
        header = await self.pull(2)

        return await self.pull(int.from_bytes(header, "big"))

    async def pull(self, n: int) -> bytes:
        if len(self.incoming) < n:
            raise DNSClosedError("A DoH exchange carries a single query.")

        chunk = bytes(self.incoming[:n])
        del self.incoming[:n]

        return chunk

    async def deliver(self, wire: bytes):
        self.reply = wire[2:]

    async def close(self):
        return

class DNSHTTPSProtocol(DNSProtocol):
    def __init__(self, dst: Tuple[str, int], *, path: str = "/dns-query", tls: Optional[TLSConfig] = None, hostname: Optional[str] = None, limits: Optional["DNSClientLimits"] = None):
        from ...http.api.client import HTTPClient, HTTPClientConfig, HTTPClientLimits
        from ..api.client import DNSClientLimits

        self.limits = limits or DNSClientLimits()

        self.host = hostname or dst[0]
        self.url = f"https://{self.host}{'' if dst[1] == 443 else f':{dst[1]}'}{path}"

        self.client = HTTPClient(config=HTTPClientConfig(versions=["HTTP/2.0", "HTTP/1.1"], tls=tls or TLSConfig(), limits=HTTPClientLimits(timeout_connection=self.limits.timeout_connection)))

    async def query(self, message: DNSMessage, *, timeout: Optional[float] = None) -> DNSMessage:
        timeout = self.limits.timeout_query if timeout is None else timeout
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
