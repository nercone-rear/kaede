import asyncio
import secrets
from typing import Optional, Tuple, Union

from ...tcp import TCPPort, TCPConnection
from ...tcp.errors import TCPError
from ...tls.errors import TLSError
from ..models import DNSMessage
from ..errors import DNSError, DNSFormatError, DNSConnectionError, DNSClosedError
from .handler import DNSConnection
from .udp import DNSUDPTransport

class DNSTCPTransport:
    def __init__(self, dst: Tuple[str, int], *, connect_timeout: float = 5.0):
        self.dst = dst
        self.connect_timeout = connect_timeout

        self.connection: Optional[DNSConnection] = None
        self.lock = asyncio.Lock()

    async def open(self):
        connection = TCPConnection(("", TCPPort(0)), (self.dst[0], TCPPort(self.dst[1])))
        await connection.connect(self.connect_timeout)

        return connection

    async def establish(self) -> DNSConnection:
        try:
            return DNSConnection(await self.open(), stream=True)

        except (TCPError, TLSError) as e:
            raise DNSConnectionError(f"Could not reach {self.dst[0]}:{self.dst[1]}: {e}") from e

    async def query(self, message: DNSMessage, *, timeout: float = 3.0) -> DNSMessage:
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

                if not self.matches(message, response):
                    await self.drop()
                    raise DNSFormatError(f"{self.dst[0]} answered with a message that does not match the query.")

                return response

    def matches(self, query: DNSMessage, response: DNSMessage) -> bool:
        return DNSUDPTransport.matches(query, response)

    async def drop(self):
        connection, self.connection = self.connection, None

        if connection is not None:
            try:
                await connection.close()

            except (DNSError, TCPError, TLSError):
                pass

    async def close(self):
        await self.drop()
