import time
import ctypes
import asyncio
from ssl import CERT_NONE
from typing import Optional, List, Dict, Deque, Tuple
from collections import deque

from ..tls.models import TLSConfig
from ..tls.openssl import VOID_P, Control, Timeval, Result, Certificate, TLSSession
from ..tls.errors import TLSConfigError, TLSHandshakeError, TLSVerificationError
from ..udp.models import UDPPort
from ..udp.errors import UDPError
from ..udp.protocol import UDPConnection, UDPProtocol
from ..udp.api.server import UDPServer
from .models import QUICStreamID
from .tls import QTLS, QUICPair, QUICContext, Stream, Incoming, Listener, Shutdown, Close, ShutdownArgs, CloseInfo, ResetArgs
from .errors import QUICError, QUICConnectionError, QUICClosedError, QUICLostError, QUICTimeoutError, QUICStreamError

class QUICProtocol(UDPProtocol):
    def __init__(self, endpoint: "QUICEndpoint", sock=None):
        super().__init__(sock=sock)
        self.endpoint = endpoint

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport
        self.src = UDPProtocol.address(transport.get_extra_info("sockname"))

        self.endpoint.bind(transport, self.src)

    def datagram_received(self, data: bytes, addr):
        self.endpoint.feed(data, UDPProtocol.address(addr))

    def error_received(self, exc: OSError):
        return

    def connection_lost(self, exc: Optional[BaseException]):
        self.endpoint.lost(exc)

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

            connection = QUICConnection(self, pointer, server=True)
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

    def open(self, *, hostname: Optional[str] = None) -> "QUICConnection":
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

            connection = QUICConnection(self, pointer, dst=(dst[0], UDPPort(dst[1])))
            connection.prepare(hostname)

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

class QUICConnection:
    def __init__(self, endpoint: QUICEndpoint, pointer, *, server: bool = False, dst: Optional[Tuple[str, UDPPort]] = None):
        self.endpoint = endpoint
        self.qtls: QTLS = endpoint.qtls
        self.library = endpoint.library
        self.pointer = pointer
        self.server = server

        self.dst = dst or ("", UDPPort(0))

        self.streams: Dict[int, "QUICStream"] = {}
        self.max_streams: Optional[int] = None # the per-connection cap on concurrent remote-initiated bidirectional streams

        self.established = False
        self.closed = False
        self.error: Optional[Exception] = None

        self.active = time.monotonic()

    @property
    def src(self) -> Tuple[str, UDPPort]:
        return self.endpoint.src

    @property
    def version(self) -> Optional[str]:
        value = self.library.get_version(self.pointer)
        return value.decode() if value else None

    @property
    def cipher(self) -> Optional[str]:
        current = self.library.get_cipher(self.pointer)

        if not current:
            return None

        value = self.library.cipher_name(current)
        return value.decode() if value else None

    @property
    def group(self) -> Optional[str]:
        value = self.library.get_group(self.pointer)
        return value.decode() if value else None

    @property
    def protocol(self) -> Optional[str]:
        data = ctypes.POINTER(ctypes.c_ubyte)()
        length = ctypes.c_uint(0)

        self.library.get_alpn(self.pointer, ctypes.byref(data), ctypes.byref(length))

        if not length.value or not data:
            return None

        return bytes(bytearray(data[:length.value])).decode(errors="replace")

    @property
    def servername(self) -> Optional[str]:
        value = self.library.get_servername(self.pointer, Control.NAMETYPE_HOST)
        return value.decode() if value else None

    @property
    def verified(self) -> bool:
        return self.library.get_verify(self.pointer) == 0

    def prepare(self, hostname: Optional[str] = None):
        context = self.endpoint.context
        verify = context.config.verification(context.server)
        host = hostname

        if not host:
            if verify != CERT_NONE:
                raise TLSConfigError("A verifying QUIC client needs a hostname to check the certificate against. Pass a hostname, or set verify_mode to CERT_NONE to connect without checking identity.")

            return

        if host.endswith("."):
            host = host[:-1]

        identity = TLSSession.identity(host)

        if not host.replace(".", "").isdigit() and ":" not in host:
            self.library.ctrl(self.pointer, Control.SET_TLSEXT_HOSTNAME, Control.NAMETYPE_HOST, ctypes.cast(ctypes.c_char_p(identity), VOID_P))

        if verify != CERT_NONE:
            self.library.set_host(self.pointer, identity)

    @staticmethod
    async def connect(transport: UDPConnection, config: Optional[TLSConfig] = None, *, hostname: Optional[str] = None, alpn: Optional[List[str]] = None, timeout: Optional[float] = None, context: Optional[QUICContext] = None) -> "QUICConnection":
        context = context or QUICContext(config or TLSConfig(), server=False, alpn=alpn)
        endpoint = QUICEndpoint(context)

        try:
            endpoint.adopt(transport)
            connection = endpoint.open(hostname=hostname or transport.dst[0])

            await connection.handshake(timeout)

        except BaseException:
            endpoint.free()
            raise

        return connection

    async def handshake(self, timeout: Optional[float] = None):
        try:
            if timeout is None:
                await self.negotiate()
            else:
                await asyncio.wait_for(self.negotiate(), timeout)

        except asyncio.TimeoutError:
            raise QUICTimeoutError(f"The QUIC handshake with {self.dst[0]} timed out after {timeout} seconds.")

    async def negotiate(self):
        while True:
            if self.settled():
                return

            self.status()

            if self.error is not None:
                raise self.error

            self.endpoint.wake()

            if self.settled():
                return

            await self.endpoint.tick()

    def settled(self) -> bool:
        if self.established:
            return True

        if self.server:
            self.established = self.qtls.established(self.pointer) == 1
            return self.established

        self.library.error_clear()
        code = self.library.handshake(self.pointer)

        if code == 1:
            self.established = True
            return True

        result = self.library.get_error(self.pointer, code)

        if result in (Result.WANT_READ, Result.WANT_WRITE):
            return False

        if self.library.get_verify(self.pointer) != 0:
            self.fail("The QUIC handshake failed")

        self.status()

        if self.error is not None:
            raise self.error

        self.fail("The QUIC handshake failed")

    def status(self):
        if self.closed or not self.pointer:
            return

        info = CloseInfo()

        if self.qtls.close_info(self.pointer, ctypes.byref(info), ctypes.sizeof(CloseInfo)) != 1:
            return

        self.closed = True

        if self.error is not None:
            return

        reason = info.reason.decode(errors="replace") if info.reason else ""
        origin = "This side" if info.flags & Close.LOCAL else "The peer"

        if info.flags & Close.TRANSPORT:
            self.error = QUICLostError(f"{origin} closed the connection with the transport error 0x{info.code:x}{': ' + reason if reason else ''}.")
        else:
            self.error = QUICClosedError(f"{origin} closed the connection with the application error 0x{info.code:x}{': ' + reason if reason else ''}.")

    def fail(self, message: str):
        code = self.library.get_verify(self.pointer)
        reason = self.library.reason()

        if code != 0:
            raise TLSVerificationError(f"{message}: {Certificate.reason(code)} ({reason})", code)

        raise TLSHandshakeError(f"{message}: {reason}")

    async def open(self, *, unidirectional: bool = False, timeout: Optional[float] = None) -> "QUICStream":
        flags = Stream.NO_BLOCK | (Stream.UNI if unidirectional else 0)

        while True:
            self.check()

            pointer = self.qtls.new_stream(self.pointer, flags)

            if pointer:
                return self.adopt(pointer)

            await self.endpoint.tick(timeout)

    async def accept(self, timeout: Optional[float] = None) -> "QUICStream":
        while True:
            self.check()

            pointer = self.qtls.accept_stream(self.pointer, Stream.ACCEPT_NO_BLOCK)

            if pointer:
                self.prune()
                stream = self.adopt(pointer)

                # RFC 9000 section 4.6 caps concurrent peer-opened bidirectional streams. OpenSSL exposes no
                # setter for initial_max_streams_bidi, so one past the cap is refused rather than admitted.
                if self.overflowing(stream):
                    stream.reset()
                    self.forget(stream)
                    continue

                return stream

            await self.endpoint.tick(timeout)

    def adopt(self, pointer) -> "QUICStream":
        stream = QUICStream(self, pointer)
        self.streams[int(stream.id)] = stream

        return stream

    def prune(self):
        for stream in [stream for stream in self.streams.values() if stream.spent]:
            self.forget(stream)

    def overflowing(self, stream: "QUICStream") -> bool:
        if self.max_streams is None or stream.local or not (stream.readable and stream.writable):
            return False

        opened = sum(1 for other in self.streams.values() if not other.local and other.readable and other.writable)

        return opened > self.max_streams

    def check(self):
        if self.pointer is None:
            raise QUICClosedError("This QUIC connection is already closed.")

        self.status()

        if self.error is not None:
            raise self.error

    def forget(self, stream: "QUICStream"):
        if self.streams.get(int(stream.id)) is stream:
            del self.streams[int(stream.id)]

        stream.free()

    async def close(self, code: int = 0, reason: str = "", *, timeout: Optional[float] = 5.0):
        if self.pointer is None or self.closed:
            return

        for stream in list(self.streams.values()):
            stream.conclude()

        arguments = ShutdownArgs(code, reason.encode() if reason else None)
        deadline = None if timeout is None else time.monotonic() + timeout

        while True:
            self.library.error_clear()
            done = self.qtls.shutdown(self.pointer, Shutdown.NO_BLOCK, ctypes.byref(arguments), ctypes.sizeof(ShutdownArgs))

            self.endpoint.wake()

            if done != 0:
                break

            if deadline is not None and time.monotonic() >= deadline:
                self.qtls.shutdown(self.pointer, Shutdown.NO_BLOCK | Shutdown.RAPID, ctypes.byref(arguments), ctypes.sizeof(ShutdownArgs))
                self.endpoint.wake()
                break

            try:
                await self.endpoint.tick(0.05)

            except QUICTimeoutError:
                continue

        self.closed = True

    def free(self):
        for stream in list(self.streams.values()):
            stream.free()

        self.streams.clear()

        if self.pointer:
            self.library.free(self.pointer)
            self.pointer = None

        self.closed = True

    def __del__(self):
        self.free()

class QUICStream:
    def __init__(self, connection: QUICConnection, pointer):
        self.connection = connection
        self.qtls: QTLS = connection.qtls
        self.library = connection.library
        self.pointer = pointer

        self.id = QUICStreamID(self.qtls.stream_id(pointer))

        self.buffer = bytearray()
        self.concluded = False

    @property
    def readable(self) -> bool:
        return bool(self.qtls.stream_type(self.pointer) & Stream.TYPE_READ) if self.pointer else False

    @property
    def writable(self) -> bool:
        return bool(self.qtls.stream_type(self.pointer) & Stream.TYPE_WRITE) if self.pointer else False

    @property
    def local(self) -> bool:
        return self.qtls.stream_local(self.pointer) == 1

    @property
    def finished(self) -> bool:
        if self.pointer is None:
            return True

        return not self.buffer and self.qtls.read_state(self.pointer) == Stream.STATE_FINISHED

    @property
    def spent(self) -> bool:
        # A stream is done once we have stopped sending on it and have drained everything the peer sent, so the
        # connection may forget it. Both halves are then closed, so its buffered send data is already with the peer.
        return self.pointer is None or (self.concluded and self.finished)

    async def send(self, data: bytes):
        if self.pointer is None:
            raise QUICClosedError("This QUIC stream is already gone.")

        if self.concluded:
            raise QUICClosedError("This QUIC stream is already closed for sending.")

        if not self.writable:
            raise QUICClosedError(f"The stream {int(self.id)} only receives, so nothing can be sent on it.")

        self.judge(self.qtls.write_state(self.pointer), sending=True)

        sent = 0

        while sent < len(data):
            written = self.write(data[sent:])

            self.connection.endpoint.wake()

            if written == 0:
                await self.connection.endpoint.tick()

            sent += written

    def write(self, data: bytes) -> int:
        self.library.error_clear()
        code = self.library.write(self.pointer, data, len(data))

        if code > 0:
            return code

        result = self.library.get_error(self.pointer, code)

        if result in (Result.WANT_READ, Result.WANT_WRITE):
            return 0

        self.judge(self.qtls.write_state(self.pointer), sending=True)
        raise QUICClosedError(f"The stream {int(self.id)} could not be written to: {self.library.reason()}")

    async def receive(self, n: int = -1, timeout: Optional[float] = None) -> bytes:
        if n == 0:
            return b""

        if n < 0:
            data = bytearray(self.buffer)
            self.buffer.clear()

            while True:
                try:
                    chunk = await self.fetch(timeout)

                except QUICError:
                    if not data:
                        raise

                    return bytes(data)

                if not chunk:
                    return bytes(data)

                data += chunk

        while not self.buffer:
            chunk = await self.fetch(timeout)

            if not chunk:
                return b""

            self.buffer += chunk

        return self.take(n)

    async def receive_exactly(self, n: int, timeout: Optional[float] = None) -> bytes:
        if n <= 0:
            return b""

        while len(self.buffer) < n:
            chunk = await self.fetch(timeout)

            if not chunk:
                raise QUICClosedError(f"The stream ended after {len(self.buffer)} of the {n} bytes requested.")

            self.buffer += chunk

        return self.take(n)

    def take(self, n: int) -> bytes:
        data = bytes(self.buffer[:n])
        del self.buffer[:n]

        return data

    async def fetch(self, timeout: Optional[float] = None) -> bytes:
        while True:
            data = self.read()

            if data:
                return data

            state = self.qtls.read_state(self.pointer)

            if state != Stream.STATE_OK:
                self.judge(state, sending=False)
                return b""

            self.connection.status()

            if self.connection.error is not None:
                raise self.connection.error

            await self.connection.endpoint.tick(timeout)

    def read(self, n: int = 65536) -> bytes:
        if self.pointer is None:
            raise QUICClosedError("This QUIC stream is already gone.")

        if not self.readable:
            raise QUICClosedError(f"The stream {int(self.id)} only sends, so nothing can be received on it.")

        buffer = ctypes.create_string_buffer(n)

        self.library.error_clear()
        code = self.library.read(self.pointer, buffer, n)

        if code > 0:
            return buffer.raw[:code]

        return b""

    def judge(self, state: int, *, sending: bool):
        if state in (Stream.STATE_NONE, Stream.STATE_OK, Stream.STATE_FINISHED):
            return

        if state == Stream.STATE_RESET_REMOTE:
            raise QUICStreamError(f"The peer reset the stream {int(self.id)}.", self.code(sending=sending))

        if state == Stream.STATE_RESET_LOCAL:
            raise QUICStreamError(f"This side reset the stream {int(self.id)}.", self.code(sending=sending))

        if state == Stream.STATE_CONN_CLOSED:
            self.connection.status()
            raise self.connection.error or QUICClosedError("The connection carrying this stream is closed.")

        if state == Stream.STATE_WRONG_DIR:
            raise QUICClosedError(f"The stream {int(self.id)} does not run in that direction.")

    def code(self, *, sending: bool) -> int:
        value = ctypes.c_uint64(0)
        report = self.qtls.write_code if sending else self.qtls.read_code

        if report(self.pointer, ctypes.byref(value)) != 1:
            return 0

        return int(value.value)

    def conclude(self):
        if self.concluded or self.pointer is None or not self.writable:
            return

        self.qtls.conclude(self.pointer, 0)
        self.concluded = True

        self.connection.endpoint.wake()

    def reset(self, code: int = 0):
        if self.pointer is None or not self.writable:
            return

        args = ResetArgs(code)

        self.qtls.reset(self.pointer, ctypes.byref(args), ctypes.sizeof(ResetArgs))
        self.concluded = True

        self.connection.endpoint.wake()

    async def close(self):
        self.conclude()

    def free(self):
        if self.pointer:
            self.library.free(self.pointer)
            self.pointer = None

    def __del__(self):
        self.free()
