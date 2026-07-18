import asyncio
from typing import Optional, Tuple, TYPE_CHECKING

from .models import TCPPort
from .errors import TCPConnectionError, TCPClosedError, TCPLostError, TCPTimeoutError, TCPBusyError, TCPLimitError

if TYPE_CHECKING:
    from .api.server import TCPHandler

class TCPConnection:
    buffer_limit = 65536 # in bytes, the amount of received data to buffer before the peer is paused.

    def __init__(self, src: Tuple[str, TCPPort], dst: Tuple[str, TCPPort], *, handler: Optional["TCPHandler"] = None, protocol: Optional["TCPProtocol"] = None):
        self.src = src
        self.dst = dst
        self.handler = handler
        self.protocol = protocol

        self.transport: Optional[asyncio.Transport] = None

        self.buffer = bytearray()
        self.need = 0 # the number of bytes the current receiver is waiting for.

        self.eof = False      # the peer has sent FIN.
        self.sent_eof = False # this side has sent FIN.
        self.closed = False
        self.error: Optional[TCPLostError] = None

        self.reading = True # whether the transport is reading.
        self.held = False   # whether the transport is congested.

        self.reader: Optional[asyncio.Future] = None # woken when data, EOF or an error arrives.
        self.writer: Optional[asyncio.Future] = None # woken when the transport is no longer congested.
        self.waiter: Optional[asyncio.Future] = None # woken when the connection is fully closed.

    async def connect(self, timeout: Optional[float] = None):
        if self.transport is not None:
            raise TCPConnectionError("This connection is already established.")

        loop = asyncio.get_running_loop()
        local = (self.src[0], int(self.src[1])) if self.src and (self.src[0] or self.src[1]) else None

        try:
            connect = loop.create_connection(lambda: TCPProtocol(connection=self), self.dst[0], int(self.dst[1]), local_addr=local)
            await (connect if timeout is None else asyncio.wait_for(connect, timeout))

        except asyncio.TimeoutError:
            raise TCPTimeoutError(f"Connecting to {self.dst[0]}:{int(self.dst[1])} timed out after {timeout} seconds.")

        except OSError as e:
            raise TCPConnectionError(f"Could not connect to {self.dst[0]}:{int(self.dst[1])}: {e}") from e

    async def send(self, data: bytes):
        if self.transport is None:
            raise TCPClosedError("This connection is not established.")

        if self.closed:
            raise TCPClosedError("This connection is already closed.")

        if self.sent_eof:
            raise TCPClosedError("This connection is already closed for sending.")

        if self.error is not None:
            raise self.error

        if data:
            self.transport.write(data)

        await self.drain()

    async def receive(self, n: int = -1) -> bytes:
        if n == 0:
            return b""

        if n < 0:
            data = bytearray()

            while not self.eof and self.error is None:
                data += self.take(len(self.buffer))
                await self.wait()

            data += self.take(len(self.buffer))

            if self.error is not None:
                raise self.error

            return bytes(data)

        while not self.buffer and not self.eof and self.error is None:
            await self.wait()

        self.check()
        return self.take(n)

    async def receive_exactly(self, n: int) -> bytes:
        if n <= 0:
            return b""

        while len(self.buffer) < n and not self.eof and self.error is None:
            self.need = n

            try:
                await self.wait()
            finally:
                self.need = 0

        self.check()

        if len(self.buffer) < n:
            raise TCPClosedError(f"The connection ended after {len(self.buffer)} of the {n} bytes requested.")

        return self.take(n)

    async def receive_until(self, separator: bytes = b"\n", limit: Optional[int] = None) -> bytes:
        if not separator:
            raise ValueError("The separator must not be empty.")

        limit = self.buffer_limit if limit is None else limit
        start = 0

        while True:
            index = self.buffer.find(separator, start)

            if index >= 0:
                return self.take(index + len(separator))

            if len(self.buffer) > limit:
                raise TCPLimitError(f"The separator was not received within {limit} bytes.")

            if self.eof or self.error is not None:
                self.check()
                raise TCPClosedError("The connection ended before the separator was received.")

            start = max(0, len(self.buffer) - len(separator) + 1)
            self.need = limit + len(separator)

            try:
                await self.wait()
            finally:
                self.need = 0

    async def close(self, half_close: bool = False):
        if self.transport is None:
            return

        if half_close:
            if not self.sent_eof and not self.closed and self.transport.can_write_eof():
                self.transport.write_eof()
                self.sent_eof = True

            return

        if self.closed:
            return

        self.closed = True
        self.transport.close()

        if self.waiter is None:
            self.waiter = asyncio.get_running_loop().create_future()

        await self.waiter

    async def drain(self):
        if not self.held:
            return

        if self.writer is not None:
            raise TCPBusyError("This connection is already being sent to by another coroutine.")

        self.writer = asyncio.get_running_loop().create_future()

        try:
            await self.writer
        finally:
            self.writer = None

    async def wait(self):
        if self.reader is not None:
            raise TCPBusyError("This connection is already being received from by another coroutine.")

        self.resume()
        self.reader = asyncio.get_running_loop().create_future()

        try:
            await self.reader
        finally:
            self.reader = None

    def check(self):
        if self.error is not None and not self.buffer:
            raise self.error

    def take(self, n: int) -> bytes:
        data = bytes(self.buffer[:n])
        del self.buffer[:n]

        self.resume()
        return data

    def full(self) -> bool:
        return len(self.buffer) >= max(self.buffer_limit, self.need)

    def attach(self, transport: asyncio.Transport):
        self.transport = transport

    def feed(self, data: bytes):
        self.buffer += data

        if self.reading and self.full():
            self.transport.pause_reading()
            self.reading = False

        self.wake()

    def feed_eof(self):
        self.eof = True
        self.wake()

    def resume(self):
        if not self.reading and not self.closed and not self.full():
            self.transport.resume_reading()
            self.reading = True

    def hold(self):
        self.held = True

    def release(self):
        self.held = False

        if self.writer is not None and not self.writer.done():
            self.writer.set_result(None)

    def lost(self, exc: Optional[BaseException]):
        self.closed = True
        self.eof = True
        self.held = False

        if exc is not None and self.error is None:
            self.error = TCPLostError(f"The connection was lost: {exc}")
            self.error.__cause__ = exc

        self.wake()

        for future in (self.writer, self.waiter):
            if future is not None and not future.done():
                future.set_result(None)

    def wake(self):
        if self.reader is not None and not self.reader.done():
            self.reader.set_result(None)

class TCPProtocol(asyncio.Protocol):
    def __init__(self, src: Optional[Tuple[str, TCPPort]] = None, handler: Optional["TCPHandler"] = None, connection: Optional[TCPConnection] = None):
        self.src = src
        self.handler = handler
        self.connection = connection
        self.transport: Optional[asyncio.Transport] = None

    @staticmethod
    def address(value) -> Tuple[str, TCPPort]:
        if not value:
            return ("", TCPPort(0))

        return (str(value[0]), TCPPort(value[1]))

    def connection_made(self, transport: asyncio.Transport):
        self.transport = transport

        src = TCPProtocol.address(transport.get_extra_info("sockname"))
        dst = TCPProtocol.address(transport.get_extra_info("peername"))

        if self.connection is None:
            self.connection = TCPConnection(src, dst, handler=self.handler, protocol=self)
        else:
            self.connection.src = src
            self.connection.dst = dst
            self.connection.protocol = self

        self.connection.attach(transport)

    def data_received(self, data: bytes):
        self.connection.feed(data)

    def eof_received(self) -> bool:
        self.connection.feed_eof()
        return True

    def connection_lost(self, exc: Optional[BaseException]):
        self.connection.lost(exc)

    def pause_writing(self):
        self.connection.hold()

    def resume_writing(self):
        self.connection.release()
