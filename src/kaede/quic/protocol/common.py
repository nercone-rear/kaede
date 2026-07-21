import time
import ctypes
import asyncio
from typing import Optional, List, Dict, Deque, Tuple
from collections import deque

from ...tls.openssl import Timeval
from ...udp.models import UDPPort
from ...udp.errors import UDPError
from ...udp.protocol import UDPConnection
from ...udp.api.server import UDPServer
from ..tls import QTLS, QUICPair, QUICContext, Stream, Incoming, Listener, Shutdown, ShutdownArgs
from ..errors import QUICConnectionError, QUICClosedError, QUICTimeoutError
from .base import QUICProtocol, QUICConnection

class QUICEndpoint:
    def __init__(self, context: QUICContext, *, server: bool = False):
        self.context = context
        self.qtls: QTLS = context.qtls
        self.library = context.library
        self.server = server

        self.pair: Optional[QUICPair] = None
        self.pointer = None
        self.owned = False
        self.local = None
        self.remote = None

        self.transport: Optional[asyncio.DatagramTransport] = None
        self.socket: Optional[UDPConnection] = None
        self.connected = False

        self.src: Tuple[str, UDPPort] = ("", UDPPort(0))

        self.connections: Dict[Tuple[str, int], "QUICConnection"] = {}
        self.arrivals: Deque["QUICConnection"] = deque()
        self.waiters: List[asyncio.Future] = []

        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.timer: Optional[asyncio.TimerHandle] = None
        self.reader: Optional[asyncio.Future] = None

        self.closed = False

        self.pair = QUICPair(self.qtls)

        self.local = self.library.address_new()
        self.remote = self.library.address_new()

    def adopt(self, socket: UDPConnection):
        if socket.transport is None:
            raise QUICConnectionError("The UDP connection is not established.")

        self.socket = socket
        self.transport = socket.transport
        self.connected = True
        self.src = socket.src
        self.loop = asyncio.get_running_loop()

        self.qtls.remake(self.local, self.src[0] or "0.0.0.0", int(self.src[1]))
        self.reader = asyncio.ensure_future(self.pull(socket))

    def bind(self, transport: asyncio.DatagramTransport, src: Tuple[str, UDPPort]):
        self.transport = transport
        self.connected = False
        self.src = src
        self.loop = asyncio.get_running_loop()

        self.qtls.remake(self.local, self.src[0] or "0.0.0.0", int(self.src[1]))

    def carrier(self, pointer) -> type:
        from .q1 import Q1Connection
        from .q2 import Q2Connection

        value = self.library.get_version(pointer) if pointer else None
        name = value.decode() if value else ""

        for kind in (Q1Connection, Q2Connection):
            if kind.name == name:
                return kind

        return Q1Connection

    def attach(self, pointer):
        self.qtls.up_ref(self.pair.inner)
        self.library.set_bio(pointer, self.pair.inner, self.pair.inner)

        self.qtls.set_blocking(pointer, 0)

    async def pull(self, socket: UDPConnection):
        while not self.closed:
            try:
                data = await socket.receive()

            except UDPError:
                return

            if data:
                self.feed(data, socket.dst)

    def feed(self, data: bytes, address: Tuple[str, int]):
        if self.closed or self.pointer is None:
            return

        if not self.owns(data, address):
            return

        self.take(data, address)

    def owns(self, data: bytes, address: Tuple[str, int]) -> bool:
        return True

    def learn(self, data: bytes, address: Tuple[str, int]):
        return

    def unlearn(self, connection: "QUICConnection"):
        return

    def take(self, data: bytes, address: Tuple[str, int]):
        if self.closed or self.pointer is None:
            return

        self.qtls.remake(self.remote, address[0], int(address[1]))
        self.pair.feed(data, peer=self.remote, local=self.local)

        known = self.connections.get(address)

        if known is not None:
            known.active = time.monotonic()

        self.wake()

    def wake(self):
        if self.closed:
            return

        self.events()

        if self.harvest():
            self.events()

        self.drain()
        self.broadcast()
        self.arm()

    def live(self) -> List:
        found: List = []
        seen = set()

        for pointer in ([self.pointer] if self.pointer else []) + [c.pointer for c in self.connections.values() if c.pointer]:
            if pointer not in seen:
                seen.add(pointer)
                found.append(pointer)

        return found

    def events(self):
        for pointer in self.live():
            self.qtls.events(pointer)

    def harvest(self) -> bool:
        if not self.server or self.pointer is None:
            return False

        found = False

        while True:
            pointer = self.qtls.accept_connection(self.pointer, Listener.ACCEPT_NO_BLOCK)

            if not pointer:
                return found

            connection = self.carrier(pointer)(self, pointer, server=True)
            self.settle(connection)

            if not self.arrive(connection):
                self.refuse(connection)
                continue

            self.connections[connection.dst] = connection
            self.arrivals.append(connection)

            found = True

    def settle(self, connection: "QUICConnection"):
        self.qtls.set_blocking(connection.pointer, 0)
        self.qtls.incoming_streams(connection.pointer, Incoming.ACCEPT, 0)

        if self.qtls.peer_address is not None and self.qtls.peer_address(connection.pointer, self.remote) == 1:
            host, port = self.qtls.where(self.remote)
            connection.dst = (host, UDPPort(port))

    def arrive(self, connection: "QUICConnection") -> bool:
        return True

    def refuse(self, connection: "QUICConnection"):
        arguments = ShutdownArgs(0, b"refused")

        self.qtls.shutdown(connection.pointer, Shutdown.NO_BLOCK | Shutdown.RAPID, ctypes.byref(arguments), ctypes.sizeof(ShutdownArgs))
        self.drain()

        connection.free()
        self.unlearn(connection)

    def drain(self):
        if self.transport is None:
            return

        for data, address in self.pair.packets():
            self.learn(data, address)

            try:
                if self.connected:
                    self.transport.sendto(data)
                else:
                    self.transport.sendto(data, address)

            except OSError:
                continue

    def broadcast(self):
        waiters, self.waiters = self.waiters, []

        for waiter in waiters:
            if not waiter.done():
                waiter.set_result(None)

    def delay(self) -> Optional[float]:
        soonest = None

        for pointer in self.live():
            remaining = Timeval()
            infinite = ctypes.c_int(0)

            if self.qtls.event_timeout(pointer, ctypes.byref(remaining), ctypes.byref(infinite)) != 1 or infinite.value:
                continue

            seconds = max(0.0, remaining.seconds)
            soonest = seconds if soonest is None else min(soonest, seconds)

        return soonest

    def arm(self):
        if self.timer is not None:
            self.timer.cancel()
            self.timer = None

        if self.closed or self.loop is None:
            return

        seconds = self.delay()

        if seconds is not None:
            self.timer = self.loop.call_later(seconds, self.wake)

    async def tick(self, timeout: Optional[float] = None):
        waiter = self.loop.create_future()
        self.waiters.append(waiter)

        try:
            await (waiter if timeout is None else asyncio.wait_for(waiter, timeout))

        except asyncio.TimeoutError:
            raise QUICTimeoutError(f"Nothing happened on the QUIC endpoint within {timeout} seconds.")

        finally:
            if waiter in self.waiters:
                self.waiters.remove(waiter)

    def open(self, *, hostname: Optional[str] = None, ech: Optional[bytes] = None) -> "QUICConnection":
        pointer = self.context.connection()

        self.pointer = pointer
        self.attach(pointer)

        connection = None

        try:
            dst = self.socket.dst
            self.qtls.remake(self.remote, dst[0], int(dst[1]))

            if self.qtls.set_peer_address(pointer, self.remote) != 1:
                raise QUICConnectionError(f"OpenSSL rejected {dst[0]}:{int(dst[1])} as the peer address: {self.library.reason()}")

            self.qtls.default_stream_mode(pointer, Stream.MODE_NONE)
            self.qtls.incoming_streams(pointer, Incoming.ACCEPT, 0)

            connection = self.carrier(pointer)(self, pointer, dst=(dst[0], UDPPort(dst[1])))
            connection.prepare(hostname, ech)

        except BaseException:
            if connection is not None:
                connection.free()
            else:
                self.library.free(pointer)

            self.pointer = None
            raise

        self.connections[connection.dst] = connection
        return connection

    @classmethod
    async def serve(cls, context: QUICContext, src: Tuple[str, UDPPort], *, validate: bool = True, reuse_port: bool = False, sock=None, **arguments) -> "QUICEndpoint":
        if not context.qtls.servable:
            raise QUICConnectionError("This OpenSSL cannot report which peer a connection came from, so it cannot run a QUIC server. OpenSSL 4.0 or newer is required.")

        endpoint = cls(context, server=True, **arguments)

        endpoint.pointer = context.listener(validate=validate)
        endpoint.owned = True
        endpoint.attach(endpoint.pointer)

        if endpoint.qtls.listen(endpoint.pointer) != 1:
            endpoint.free()
            raise QUICConnectionError(f"The QUIC listener would not start: {context.library.reason()}")

        bound = sock or UDPServer.bind(src[0], UDPPort(src[1]), reuse_port=reuse_port)

        try:
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(lambda: QUICProtocol(endpoint, sock=bound), sock=bound)

        except BaseException:
            bound.close()
            endpoint.free()
            raise

        endpoint.arm()
        return endpoint

    async def accept(self, timeout: Optional[float] = None) -> "QUICConnection":
        while not self.arrivals:
            if self.closed:
                raise QUICClosedError("This QUIC endpoint is already closed.")

            await self.tick(timeout)

        return self.arrivals.popleft()

    def lost(self, exc: Optional[BaseException]):
        self.closed = True
        self.broadcast()

    def forget(self, connection: "QUICConnection"):
        if self.connections.get(connection.dst) is connection:
            del self.connections[connection.dst]

        if connection in self.arrivals:
            self.arrivals.remove(connection)

        connection.free()
        self.unlearn(connection)

    def free(self):
        self.closed = True

        if self.timer is not None:
            self.timer.cancel()
            self.timer = None

        if self.reader is not None:
            self.reader.cancel()
            self.reader = None

        for connection in list(self.connections.values()):
            connection.free()

        self.connections.clear()
        self.arrivals.clear()

        if self.pointer and self.owned:
            self.library.free(self.pointer)

        self.pointer = None

        if self.pair is not None:
            self.pair.free()
            self.pair = None

        for name in ("local", "remote"):
            address = getattr(self, name)

            if address:
                self.library.address_free(address)
                setattr(self, name, None)

        self.broadcast()

    async def close(self, timeout: Optional[float] = None):
        socket, self.socket = self.socket, None

        self.free()

        if socket is not None:
            await socket.close()

    def __del__(self):
        self.free()
