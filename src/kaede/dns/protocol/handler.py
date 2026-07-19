import asyncio
from typing import Optional, Tuple

from ...tcp.errors import TCPError, TCPClosedError, TCPLostError, TCPTimeoutError
from ...udp.errors import UDPError, UDPClosedError, UDPLostError, UDPTimeoutError
from ...quic.errors import QUICError, QUICClosedError, QUICLostError, QUICStreamError, QUICTimeoutError
from ..models import DNSMessage
from ..errors import DNSError, DNSFormatError, DNSClosedError, DNSTimeoutError

class DNSTransport:
    async def query(self, message: DNSMessage, *, timeout: float = 3.0) -> DNSMessage:
        raise NotImplementedError()

    async def close(self):
        raise NotImplementedError()

class DNSConnection:
    fallback_limit = 512 # in bytes, what a peer without EDNS accepts over UDP

    def __init__(self, transport, *, stream: bool, server: bool = False):
        self.transport = transport
        self.stream = stream
        self.server = server

        self.limit: Optional[int] = None

    @property
    def client(self) -> Tuple[str, int]:
        return (self.transport.dst[0], int(self.transport.dst[1]))

    @property
    def closed(self) -> bool:
        return self.transport.closed

    async def send(self, message: DNSMessage):
        wire = message.pack()

        if self.stream:
            if len(wire) > 65535:
                raise DNSFormatError(f"The message is {len(wire)} bytes, but the stream length prefix carries at most 65535.")

            await self.deliver(len(wire).to_bytes(2, "big") + wire)
            return

        if self.server:
            limit = self.limit or DNSConnection.fallback_limit

            if len(wire) > limit:
                wire = self.shrink(message).pack()

        await self.deliver(wire)

    def shrink(self, message: DNSMessage) -> DNSMessage:
        clipped = message.reply(rcode=message.rcode)

        clipped.response = message.response
        clipped.authoritative = message.authoritative
        clipped.recursion_available = message.recursion_available
        clipped.truncated = True
        clipped.edns = message.edns

        return clipped

    async def receive(self, timeout: Optional[float] = None) -> DNSMessage:
        while True:
            raw = await self.fetch(timeout)

            try:
                message = DNSMessage.unpack(raw)

            except DNSError:
                if not self.server:
                    raise

                await self.refuse(raw)
                continue

            if self.server and not message.response:
                self.limit = max(message.edns.payload_size, DNSConnection.fallback_limit) if message.edns is not None else DNSConnection.fallback_limit

            return message

    async def fetch(self, timeout: Optional[float]) -> bytes:
        try:
            if self.stream:
                return await (self.framed() if timeout is None else asyncio.wait_for(self.framed(), timeout))

            return await self.transport.receive(timeout=timeout)

        except (asyncio.TimeoutError, TCPTimeoutError, UDPTimeoutError, QUICTimeoutError):
            raise DNSTimeoutError(f"No DNS message arrived within {timeout} seconds.")

        except (TCPClosedError, TCPLostError, UDPClosedError, UDPLostError, QUICClosedError, QUICLostError, QUICStreamError) as e:
            raise DNSClosedError(f"The DNS transport ended: {e}") from e

    async def framed(self) -> bytes:
        header = await self.transport.receive_exactly(2)

        return await self.transport.receive_exactly(int.from_bytes(header, "big"))

    async def deliver(self, wire: bytes):
        try:
            await self.transport.send(wire)

        except (TCPClosedError, TCPLostError, UDPClosedError, UDPLostError, QUICClosedError, QUICLostError, QUICStreamError) as e:
            raise DNSClosedError(f"The DNS transport ended: {e}") from e

    async def refuse(self, raw: bytes):
        if len(raw) < 12 or (raw[2] & 0x80):
            return

        try:
            wire = DNSMessage(id=int.from_bytes(raw[0:2], "big"), response=True, rcode=1).pack()

            await self.deliver(len(wire).to_bytes(2, "big") + wire if self.stream else wire)

        except (DNSError, TCPError, UDPError, QUICError):
            pass

    async def close(self):
        await self.transport.close()
