import asyncio
from typing import Optional, List, Tuple

from ..tls.models import TLSConfig
from ..tls.openssl import TLSContext, TLSSession
from ..tls.errors import TLSError, TLSHandshakeError
from .models import UDPPort
from .errors import UDPConnectionError, UDPClosedError, UDPTimeoutError, UDPLimitError
from .protocol import UDPConnection

class DTLSConnection:
    def __init__(self, transport: UDPConnection, session: TLSSession, context: TLSContext):
        self.transport = transport
        self.session = session
        self.context = context

    @property
    def src(self) -> Tuple[str, UDPPort]:
        return self.transport.src

    @property
    def dst(self) -> Tuple[str, UDPPort]:
        return self.transport.dst

    @property
    def closed(self) -> bool:
        return self.transport.closed

    @property
    def active(self) -> float:
        return self.transport.active

    @property
    def version(self) -> Optional[str]:
        return self.session.version

    @property
    def cipher(self) -> Optional[str]:
        return self.session.cipher

    @property
    def group(self) -> Optional[str]:
        return self.session.group

    @property
    def protocol(self) -> Optional[str]:
        return self.session.protocol

    @property
    def servername(self) -> Optional[str]:
        return self.session.servername

    @property
    def verified(self) -> bool:
        return self.session.verified

    @staticmethod
    async def connect(transport: UDPConnection, config: Optional[TLSConfig] = None, *, hostname: Optional[str] = None, alpn: Optional[List[str]] = None, timeout: Optional[float] = None, context: Optional[TLSContext] = None) -> "DTLSConnection":
        context = context or TLSContext(config or TLSConfig(), server=False, alpn=alpn, datagram=True)
        connection = DTLSConnection(transport, context.session(hostname=hostname or transport.dst[0]), context)

        await connection.handshake(timeout)
        return connection

    @staticmethod
    async def accept(transport: UDPConnection, config: Optional[TLSConfig] = None, *, alpn: Optional[List[str]] = None, timeout: Optional[float] = None, context: Optional[TLSContext] = None) -> "DTLSConnection":
        context = context or TLSContext(config or TLSConfig(), server=True, alpn=alpn, datagram=True)
        connection = DTLSConnection(transport, context.session(), context)

        await connection.handshake(timeout)
        return connection

    async def handshake(self, timeout: Optional[float] = None):
        try:
            if timeout is None:
                await self.negotiate()
            else:
                await asyncio.wait_for(self.negotiate(), timeout)

        except asyncio.TimeoutError:
            raise UDPTimeoutError(f"The DTLS handshake with {self.dst[0]} timed out after {timeout} seconds.")

    async def negotiate(self):
        if self.context.cookies is not None:
            await self.verify()

        while True:
            try:
                done = self.session.handshake()

            except TLSError:
                await self.alert()
                raise

            await self.flush()

            if done:
                return

            if not await self.wait():
                raise TLSHandshakeError("The connection ended during the DTLS handshake.")

    async def verify(self):
        peer = f"{self.dst[0]}:{int(self.dst[1])}"

        while True:
            if not await self.fill():
                raise TLSHandshakeError("The connection ended during the DTLS cookie exchange.")

            if self.session.listen(peer):
                return

            await self.flush()

    async def wait(self) -> bool:
        while True:
            remaining = self.session.timeout()

            try:
                return await self.fill(remaining)

            except UDPTimeoutError:
                if not self.session.expire():
                    raise

                await self.flush()

    async def alert(self):
        try:
            await self.flush()

        except Exception:
            pass

    async def flush(self):
        for packet in self.session.packets():
            await self.transport.send(packet)

    async def fill(self, timeout: Optional[float] = None) -> bool:
        data = await self.transport.receive(timeout=timeout)

        if not data:
            return False

        self.session.feed(data)
        return True

    async def send(self, data: bytes):
        if self.session.closed:
            raise UDPClosedError("This DTLS connection is already closed for sending.")

        limit = self.session.limit()

        if limit is not None and len(data) > limit:
            raise UDPLimitError(f"The message is {len(data)} bytes, but one DTLS record here carries at most {limit}.")

        if self.session.write(data) != len(data):
            raise UDPConnectionError(f"The {len(data)} byte datagram could not be written to the DTLS session.")

        await self.flush()

    async def receive(self, n: int = -1, timeout: Optional[float] = None) -> bytes:
        data = await self.decrypt(timeout)

        if not data:
            raise UDPClosedError("This DTLS connection is already closed.")

        return data if n < 0 else data[:n]

    async def decrypt(self, timeout: Optional[float] = None) -> bytes:
        while True:
            data = self.session.read()

            if data:
                return data

            if self.session.closed:
                return b""

            await self.flush()

            if not await self.fill(timeout):
                return b""

    async def close(self):
        if not self.transport.closed and not self.session.closed:
            try:
                self.session.unwrap()
                await self.flush()

            except Exception:
                pass

        await self.transport.close()
