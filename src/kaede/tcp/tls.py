import asyncio
from typing import Optional, List, Tuple

from ..tls.models import TLSConfig
from ..tls.openssl import TLSContext, TLSSession
from ..tls.errors import TLSError, TLSHandshakeError
from .models import TCPPort
from .errors import TCPClosedError, TCPTimeoutError, TCPLimitError
from .protocol import TCPConnection

class TLSConnection:
    def __init__(self, transport: TCPConnection, session: TLSSession, context: TLSContext):
        self.transport = transport
        self.session = session
        self.context = context

        self.buffer = bytearray()

    @property
    def src(self) -> Tuple[str, TCPPort]:
        return self.transport.src

    @property
    def dst(self) -> Tuple[str, TCPPort]:
        return self.transport.dst

    @property
    def closed(self) -> bool:
        return self.transport.closed

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

    @property
    def truncated(self) -> bool:
        return self.session.truncated

    @property
    def ech_status(self):
        return self.session.ech_status

    @property
    def ech_retry_config(self) -> Optional[bytes]:
        return self.session.ech_retry_config

    @staticmethod
    async def connect(transport: TCPConnection, config: Optional[TLSConfig] = None, *, hostname: Optional[str] = None, ech: Optional[bytes] = None, alpn: Optional[List[str]] = None, timeout: Optional[float] = None, context: Optional[TLSContext] = None) -> "TLSConnection":
        context = context or TLSContext(config or TLSConfig(), server=False, alpn=alpn)
        connection = TLSConnection(transport, context.session(hostname=hostname or transport.dst[0], ech=ech), context)

        await connection.handshake(timeout)
        return connection

    @staticmethod
    async def accept(transport: TCPConnection, config: Optional[TLSConfig] = None, *, alpn: Optional[List[str]] = None, timeout: Optional[float] = None, context: Optional[TLSContext] = None) -> "TLSConnection":
        context = context or TLSContext(config or TLSConfig(), server=True, alpn=alpn)
        connection = TLSConnection(transport, context.session(), context)

        await connection.handshake(timeout)
        return connection

    async def handshake(self, timeout: Optional[float] = None):
        try:
            if timeout is None:
                await self.negotiate()
            else:
                await asyncio.wait_for(self.negotiate(), timeout)

        except asyncio.TimeoutError:
            raise TCPTimeoutError(f"The TLS handshake with {self.dst[0]} timed out after {timeout} seconds.")

    async def negotiate(self):
        while True:
            try:
                done = self.session.handshake()

            except TLSError:
                await self.alert()
                raise

            await self.flush()

            if done:
                return

            if not await self.fill():
                raise TLSHandshakeError("The connection ended during the TLS handshake.")

    async def alert(self):
        try:
            await self.flush()

        except Exception:
            pass

    async def flush(self):

        data = self.session.drain()

        if data:
            await self.transport.send(data)

    async def fill(self) -> bool:

        data = await self.transport.receive(16384)

        if not data:
            return False

        self.session.feed(data)
        return True

    async def send(self, data: bytes):
        if self.session.closed:
            raise TCPClosedError("This TLS connection is already closed for sending.")

        sent = 0

        while sent < len(data):
            written = self.session.write(data[sent:])
            await self.flush()

            if written == 0:
                if not await self.fill():
                    raise TCPClosedError("The connection ended while sending.")

            sent += written

    async def receive(self, n: int = -1) -> bytes:
        if n == 0:
            return b""

        if n < 0:
            data = bytearray(self.buffer)
            self.buffer.clear()

            while True:
                chunk = await self.decrypt()

                if not chunk:
                    return bytes(data)

                data += chunk

        while not self.buffer:
            chunk = await self.decrypt()

            if not chunk:
                return b""

            self.buffer += chunk

        return self.take(n)

    async def receive_exactly(self, n: int) -> bytes:
        if n <= 0:
            return b""

        while len(self.buffer) < n:
            chunk = await self.decrypt()

            if not chunk:
                raise TCPClosedError(f"The connection ended after {len(self.buffer)} of the {n} bytes requested.")

            self.buffer += chunk

        return self.take(n)

    async def receive_until(self, separator: bytes = b"\n", limit: Optional[int] = None) -> bytes:
        if not separator:
            raise ValueError("The separator must not be empty.")

        limit = self.transport.limits.max_buffer_size if limit is None else limit
        start = 0

        while True:
            index = self.buffer.find(separator, start)

            if index >= 0:
                return self.take(index + len(separator))

            if len(self.buffer) > limit:
                raise TCPLimitError(f"The separator was not received within {limit} bytes.")

            start = max(0, len(self.buffer) - len(separator) + 1)
            chunk = await self.decrypt()

            if not chunk:
                raise TCPClosedError("The connection ended before the separator was received.")

            self.buffer += chunk

    async def decrypt(self) -> bytes:
        while True:
            data = self.session.read()

            if data:
                return data

            if self.session.closed:
                return b""

            await self.flush()

            if not await self.fill():
                self.session.eof()
                return self.session.read()

    def take(self, n: int) -> bytes:
        data = bytes(self.buffer[:n])
        del self.buffer[:n]

        return data

    async def close(self, half_close: bool = False):
        if not self.transport.closed and not self.session.closed:
            try:
                self.session.unwrap()
                await self.flush()

            except Exception:
                pass

        try:
            await self.transport.close(half_close)

        finally:
            if not half_close:
                self.session.free()
