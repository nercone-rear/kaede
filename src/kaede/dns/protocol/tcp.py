import asyncio
import secrets
from typing import Optional, Tuple, TYPE_CHECKING

from ...tcp import TCPPort, TCPConnection
from ...tcp.errors import TCPError
from ...tls.errors import TLSError
from ..models import DNSMessage
from ..errors import DNSError, DNSFormatError, DNSConnectionError, DNSClosedError
from .base import DNSConnection, DNSProtocol

if TYPE_CHECKING:
    from ..api.client import DNSClientLimits

class DNSTCPConnection(DNSConnection):
    def __init__(self, transport, *, server: bool = False):
        super().__init__(transport, stream=True, server=server)

class DNSTCPProtocol(DNSProtocol):
    carrier = DNSTCPConnection

    def __init__(self, dst: Tuple[str, int], *, limits: Optional["DNSClientLimits"] = None):
        from ..api.client import DNSClientLimits

        self.dst = dst
        self.limits = limits or DNSClientLimits()

        self.connection: Optional[DNSConnection] = None
        self.lock = asyncio.Lock()

    async def open(self):
        connection = TCPConnection(("", TCPPort(0)), (self.dst[0], TCPPort(self.dst[1])))
        await connection.connect(self.limits.timeout_connection)

        return connection

    async def establish(self) -> DNSConnection:
        try:
            return self.carrier(await self.open())

        except (TCPError, TLSError) as e:
            raise DNSConnectionError(f"Could not reach {self.dst[0]}:{self.dst[1]}: {e}") from e

    async def query(self, message: DNSMessage, *, timeout: Optional[float] = None) -> DNSMessage:
        timeout = self.limits.timeout_query if timeout is None else timeout
        message.id = secrets.randbits(16)

        async with self.lock:
            for retry in (False, True):
                reused = self.connection is not None and not self.connection.closed

                if not reused:
                    self.connection = await self.establish()

                try:
                    await self.connection.send(message)
                    response = await self.connection.receive(timeout=timeout)

                except (DNSClosedError, DNSFormatError):
                    await self.drop()

                    if reused and not retry:
                        continue

                    raise

                except DNSError:
                    await self.drop()
                    raise

                if not message.matches(response):
                    await self.drop()
                    raise DNSFormatError(f"{self.dst[0]} answered with a message that does not match the query.")

                return response

    async def drop(self):
        connection, self.connection = self.connection, None

        if connection is not None:
            try:
                await connection.close()

            except (DNSError, TCPError, TLSError):
                pass

    async def close(self):
        await self.drop()
