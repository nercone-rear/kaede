import asyncio
from typing import Optional, Tuple

from ...tls import TLSConfig
from ...tls.errors import TLSError
from ...udp import UDPPort
from ...udp.errors import UDPError
from ...quic import QUICClient, QUICClientConfig, QUICConnection, QUICStream
from ...quic.errors import QUICError, QUICTimeoutError
from ..models import DNSMessage
from ..errors import DNSError, DNSFormatError, DNSConnectionError, DNSTimeoutError
from .udp import DNSUDPTransport

class DNSStream:
    def __init__(self, connection: QUICConnection, stream: QUICStream):
        self.connection = connection
        self.stream = stream

    @property
    def dst(self) -> Tuple[str, UDPPort]:
        return self.connection.dst

    @property
    def closed(self) -> bool:
        return self.stream.pointer is None or self.stream.finished

    async def send(self, data: bytes):
        await self.stream.send(data)

    async def receive_exactly(self, n: int) -> bytes:
        return await self.stream.receive_exactly(n)

    async def close(self):
        await self.stream.close()

class DNSQUICTransport:
    def __init__(self, dst: Tuple[str, int], *, tls: Optional[TLSConfig] = None, hostname: Optional[str] = None, connect_timeout: float = 5.0):
        self.dst = dst
        self.connect_timeout = connect_timeout

        self.client = QUICClient((dst[0], UDPPort(dst[1])), config=QUICClientConfig(connect_timeout=connect_timeout, tls=tls or TLSConfig(), alpn=["doq"], hostname=hostname))

        self.connection: Optional[QUICConnection] = None
        self.lock = asyncio.Lock()

    async def establish(self) -> QUICConnection:
        try:
            return await self.client.open()

        except (QUICError, TLSError, UDPError) as e:
            raise DNSConnectionError(f"Could not reach {self.dst[0]}:{self.dst[1]} over QUIC: {e}") from e

    async def query(self, message: DNSMessage, *, timeout: float = 3.0) -> DNSMessage:
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

        try:
            wire = message.pack()

            await stream.send(len(wire).to_bytes(2, "big") + wire)
            stream.conclude()

            header = await stream.receive_exactly(2, timeout=timeout)
            raw = await stream.receive_exactly(int.from_bytes(header, "big"), timeout=timeout)

        except QUICTimeoutError:
            raise DNSTimeoutError(f"{self.dst[0]} did not answer over QUIC within {timeout} seconds.")

        except QUICError as e:
            raise DNSConnectionError(f"The DoQ exchange with {self.dst[0]} failed: {e}") from e

        finally:
            await stream.close()

        response = DNSMessage.unpack(raw)

        if response.id != 0:
            raise DNSFormatError(f"{self.dst[0]} answered over DoQ with the message ID {response.id} rather than 0.")

        if not DNSUDPTransport.matches(message, response):
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
