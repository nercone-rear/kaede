import time
import socket
import asyncio
from typing import Optional, Dict, Deque, Tuple, TYPE_CHECKING
from collections import deque

from .models import UDPPort
from .errors import UDPConnectionError, UDPClosedError, UDPLostError, UDPTimeoutError, UDPBusyError

if TYPE_CHECKING:
    from .api.server import UDPHandler

class UDPConnection:
    queue_limit = 256 # the number of received datagrams to hold before further arrivals are dropped.

    def __init__(self, src: Tuple[str, UDPPort], dst: Tuple[str, UDPPort], *, handler: Optional["UDPHandler"] = None, protocol: Optional["UDPProtocol"] = None):
        self.src = src
        self.dst = dst
        self.handler = handler
        self.protocol = protocol

        self.transport: Optional[asyncio.DatagramTransport] = None
        self.socket: Optional[socket.socket] = None

        self.queue: Deque[bytes] = deque()
        self.dropped = 0

        self.connected = False
        self.closed = False
        self.error: Optional[UDPLostError] = None

        self.active = time.monotonic()

        self.reader: Optional[asyncio.Future] = None
        self.waiter: Optional[asyncio.Future] = None

    async def connect(self, timeout: Optional[float] = None):
        if self.transport is not None:
            raise UDPConnectionError("This connection is already established.")

        loop = asyncio.get_running_loop()

        try:
            resolve = loop.getaddrinfo(self.dst[0], int(self.dst[1]), type=socket.SOCK_DGRAM)
            found = await (resolve if timeout is None else asyncio.wait_for(resolve, timeout))

            if not found:
                raise UDPConnectionError(f"Could not resolve {self.dst[0]}:{int(self.dst[1])}.")

            sock = UDPConnection.endpoint(found[0], self.src)

            try:
                connect = loop.create_datagram_endpoint(lambda: UDPProtocol(connection=self, sock=sock), sock=sock)
                await (connect if timeout is None else asyncio.wait_for(connect, timeout))

            except BaseException:
                sock.close()
                raise

        except asyncio.TimeoutError:
            raise UDPTimeoutError(f"Connecting to {self.dst[0]}:{int(self.dst[1])} timed out after {timeout} seconds.")

        except OSError as e:
            raise UDPConnectionError(f"Could not connect to {self.dst[0]}:{int(self.dst[1])}: {e}") from e

        self.connected = True

    @staticmethod
    def endpoint(found, src: Optional[Tuple[str, UDPPort]] = None) -> socket.socket:
        family, kind, proto, _, address = found
        sock = socket.socket(family, kind, proto)

        try:
            sock.setblocking(False)

            if src and (src[0] or src[1]):
                sock.bind((src[0], int(src[1])))

            sock.connect(address)

        except BaseException:
            sock.close()
            raise

        return sock

    async def send(self, data: bytes):
        if self.transport is None:
            raise UDPClosedError("This connection is not established.")

        if self.closed:
            raise UDPClosedError("This connection is already closed.")

        if self.error is not None:
            raise self.error

        self.transmit(data)
        self.active = time.monotonic()

    def transmit(self, data: bytes):
        dst = None if self.connected else (self.dst[0], int(self.dst[1]))

        if data:
            self.transport.sendto(data, dst)
            return

        if self.socket is None:
            return

        try:
            if self.connected:
                self.socket.send(data)
            else:
                self.socket.sendto(data, dst)

        except OSError as e:
            self.fail(e)

    async def receive(self, n: int = -1, timeout: Optional[float] = None) -> bytes:
        while not self.queue and self.error is None and not self.closed:
            await self.wait(timeout)

        if self.queue:
            return self.take(n)

        if self.error is not None:
            raise self.error

        raise UDPClosedError("This connection is already closed.")

    def drop(self) -> bool:
        if self.closed:
            return False

        self.closed = True
        dedicated = self.protocol is not None and self.protocol.connection is self

        if self.protocol is not None:
            self.protocol.forget(self)

        self.wake()
        return dedicated

    async def close(self):
        if not self.drop():
            return

        if self.waiter is None:
            self.waiter = asyncio.get_running_loop().create_future()

        await self.waiter

    async def wait(self, timeout: Optional[float] = None):
        if self.reader is not None:
            raise UDPBusyError("This connection is already being received from by another coroutine.")

        self.reader = asyncio.get_running_loop().create_future()

        try:
            await (self.reader if timeout is None else asyncio.wait_for(self.reader, timeout))

        except asyncio.TimeoutError:
            raise UDPTimeoutError(f"No datagram arrived within {timeout} seconds.")

        finally:
            self.reader = None

    def take(self, n: int) -> bytes:
        data = self.queue.popleft()

        return data if n < 0 else data[:n]

    def full(self) -> bool:
        return len(self.queue) >= self.queue_limit

    def attach(self, transport: asyncio.DatagramTransport, sock: Optional[socket.socket] = None):
        self.transport = transport
        self.socket = sock

    def feed(self, data: bytes):
        if self.closed:
            return

        if self.full():
            self.dropped += 1
            return

        self.queue.append(data)
        self.active = time.monotonic()

        self.wake()

    def fail(self, exc: BaseException):
        if self.error is None:
            self.error = UDPLostError(f"The endpoint reported a failure: {exc}")
            self.error.__cause__ = exc

        self.wake()

    def lost(self, exc: Optional[BaseException]):
        self.closed = True

        if exc is not None and self.error is None:
            self.error = UDPLostError(f"The endpoint was lost: {exc}")
            self.error.__cause__ = exc

        self.wake()

        if self.waiter is not None and not self.waiter.done():
            self.waiter.set_result(None)

    def wake(self):
        if self.reader is not None and not self.reader.done():
            self.reader.set_result(None)

class UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, src: Optional[Tuple[str, UDPPort]] = None, handler: Optional["UDPHandler"] = None, connection: Optional[UDPConnection] = None, sock: Optional[socket.socket] = None):
        self.src = src
        self.handler = handler
        self.connection = connection
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.socket = sock

        self.connections: Dict[Tuple[str, UDPPort], UDPConnection] = {}

    @staticmethod
    def address(value) -> Tuple[str, UDPPort]:
        if not value:
            return ("", UDPPort(0))

        return (str(value[0]), UDPPort(value[1]))

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport
        self.src = UDPProtocol.address(transport.get_extra_info("sockname"))

        if self.connection is None:
            return

        peer = transport.get_extra_info("peername")

        self.connection.src = self.src
        self.connection.dst = UDPProtocol.address(peer) if peer else self.connection.dst
        self.connection.protocol = self

        self.connection.attach(transport, self.socket)

    def dispatch(self, dst: Tuple[str, UDPPort]) -> Optional[UDPConnection]:
        if self.connection is not None:
            return self.connection

        connection = self.connections.get(dst)

        if connection is None:
            connection = UDPConnection(self.src, dst, handler=self.handler, protocol=self)
            connection.attach(self.transport, self.socket)

            if not self.arrive(connection):
                return None

            self.connections[dst] = connection

        return connection

    def arrive(self, connection: UDPConnection) -> bool:
        return True

    def forget(self, connection: UDPConnection):
        if self.connections.get(connection.dst) is connection:
            del self.connections[connection.dst]

        if self.connection is connection and self.transport is not None:
            self.transport.close()

    def datagram_received(self, data: bytes, addr):
        connection = self.dispatch(UDPProtocol.address(addr))

        if connection is not None:
            connection.feed(data)

    def error_received(self, exc: OSError):
        if self.connection is not None:
            self.connection.fail(exc)

    def connection_lost(self, exc: Optional[BaseException]):
        for connection in ([self.connection] if self.connection is not None else list(self.connections.values())):
            connection.lost(exc)
