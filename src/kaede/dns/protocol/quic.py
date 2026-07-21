import asyncio
from typing import Optional, Tuple, TYPE_CHECKING

from ...tls import TLSConfig
from ...tls.errors import TLSError
from ...udp import UDPPort
from ...udp.errors import UDPError
from ...quic import QUICClient, QUICClientConfig, QUICClientLimits, QUICConnection, QUICStream
from ...quic.errors import QUICError, QUICTimeoutError
from ..models import DNSMessage
from ..errors import DNSError, DNSFormatError, DNSConnectionError, DNSTimeoutError
from .base import DNSConnection, DNSProtocol

if TYPE_CHECKING:
    from ..api.client import DNSClientLimits

class DNSQUICConnection(DNSConnection):
    def __init__(self, connection: QUICConnection, stream: QUICStream, *, server: bool = False):
        super().__init__(stream, stream=True, server=server)
        self.connection = connection

    @property
    def client(self) -> Tuple[str, int]:
        return (self.connection.dst[0], int(self.connection.dst[1]))

    @property
    def closed(self) -> bool:
        return self.transport.pointer is None or self.transport.finished

    def conclude(self):
        self.transport.conclude()

class DNSQUICProtocol(DNSProtocol):
    def __init__(self, dst: Tuple[str, int], *, tls: Optional[TLSConfig] = None, hostname: Optional[str] = None, limits: Optional["DNSClientLimits"] = None):
        from ..api.client import DNSClientLimits

        self.dst = dst
        self.limits = limits or DNSClientLimits()

        self.client = QUICClient((dst[0], UDPPort(dst[1])), config=QUICClientConfig(limits=QUICClientLimits(timeout_connection=self.limits.timeout_connection), tls=tls or TLSConfig(), alpn=["doq"], hostname=hostname))

        self.connection: Optional[QUICConnection] = None
        self.lock = asyncio.Lock()

    async def establish(self) -> QUICConnection:
        try:
            return await self.client.open()

        except (QUICError, TLSError, UDPError) as e:
            raise DNSConnectionError(f"Could not reach {self.dst[0]}:{self.dst[1]} over QUIC: {e}") from e

    async def query(self, message: DNSMessage, *, timeout: Optional[float] = None) -> DNSMessage:
        timeout = self.limits.timeout_query if timeout is None else timeout
        message.id = 0

        async with self.lock:
            for retry in (False, True):
                reused = self.connection is not None

                if not reused:
                    self.connection = await self.establish()

                try:
                    return await self.exchange(message, timeout)

                except DNSTimeoutError:
                    raise

                except DNSError:
                    await self.drop()

                    if reused and not retry:
                        continue

                    raise

    async def exchange(self, message: DNSMessage, timeout: float) -> DNSMessage:
        try:
            stream = await self.connection.open(timeout=timeout)

        except QUICError as e:
            raise DNSConnectionError(f"Could not open a DoQ stream to {self.dst[0]}: {e}") from e

        carried = DNSQUICConnection(self.connection, stream)

        try:
            await carried.send(message)
            carried.conclude()

            response = await carried.receive(timeout=timeout)

        except DNSTimeoutError:
            raise DNSTimeoutError(f"{self.dst[0]} did not answer over QUIC within {timeout} seconds.")

        except QUICTimeoutError:
            raise DNSTimeoutError(f"{self.dst[0]} did not answer over QUIC within {timeout} seconds.")

        except QUICError as e:
            raise DNSConnectionError(f"The DoQ exchange with {self.dst[0]} failed: {e}") from e

        finally:
            await carried.close()

        if response.id != 0:
            raise DNSFormatError(f"{self.dst[0]} answered over DoQ with the message ID {response.id} rather than 0.")

        if not message.matches(response):
            raise DNSFormatError(f"{self.dst[0]} answered over DoQ with a message that does not match the query.")

        return response

    async def drop(self):
        self.connection = None

        try:
            await self.client.close()

        except (QUICError, UDPError):
            pass

    async def close(self):
        await self.drop()
