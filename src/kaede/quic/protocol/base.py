import time
import ctypes
import asyncio
from ssl import CERT_NONE
from typing import Optional, List, Dict, Tuple, TYPE_CHECKING

from ...tls.models import TLSConfig
from ...tls.openssl import VOID_P, Control, Result, Certificate, TLSSession
from ...tls.errors import TLSConfigError, TLSHandshakeError, TLSVerificationError, TLSECHError
from ...tls.helpers.ech import ECHConfigList, ECHStatus
from ...udp.models import UDPPort
from ...udp.protocol import UDPConnection, UDPProtocol
from ..models import QUICStreamID
from ..tls import QTLS, QUICContext, Stream, Shutdown, Close, ShutdownArgs, CloseInfo, ResetArgs
from ..errors import QUICError, QUICClosedError, QUICLostError, QUICTimeoutError, QUICStreamError

if TYPE_CHECKING:
    from .common import QUICEndpoint

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

class QUICConnection:
    def __init__(self, endpoint: "QUICEndpoint", pointer, *, server: bool = False, dst: Optional[Tuple[str, UDPPort]] = None):
        self.endpoint = endpoint
        self.qtls: QTLS = endpoint.qtls
        self.library = endpoint.library
        self.pointer = pointer
        self.server = server

        self.dst = dst or ("", UDPPort(0))

        self.streams: Dict[int, "QUICStream"] = {}
        self.max_streams: Optional[int] = None

        self.established = False
        self.closed = False
        self.error: Optional[Exception] = None
        self.ech: Optional[bytes] = None

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

    @property
    def ech_status(self) -> Optional[ECHStatus]:
        if self.ech is None or self.library.get_ech_status is None:
            return None

        inner = VOID_P()
        outer = VOID_P()
        code = self.library.get_ech_status(self.pointer, ctypes.byref(inner), ctypes.byref(outer))

        inner_sni = ctypes.cast(inner, ctypes.c_char_p).value.decode() if inner else None
        outer_sni = ctypes.cast(outer, ctypes.c_char_p).value.decode() if outer else None

        if inner:
            self.library.free_pointer(inner, None, 0)

        if outer:
            self.library.free_pointer(outer, None, 0)

        return ECHStatus(code=code, inner_sni=inner_sni, outer_sni=outer_sni)

    @property
    def ech_retry_config(self) -> Optional[bytes]:
        if self.ech is None or self.library.get_ech_retry_config is None:
            return None

        data = ctypes.POINTER(ctypes.c_ubyte)()
        length = ctypes.c_size_t(0)

        if self.library.get_ech_retry_config(self.pointer, ctypes.byref(data), ctypes.byref(length)) != 1 or not length.value:
            return None

        raw = bytes(bytearray(data[:length.value]))
        self.library.free_pointer(data, None, 0)

        return raw

    def prepare(self, hostname: Optional[str] = None, ech: Optional[bytes] = None):
        context = self.endpoint.context
        verify = context.config.verification(context.server)
        host = hostname

        if not host:
            if verify != CERT_NONE:
                raise TLSConfigError("A verifying QUIC client needs a hostname to check the certificate against. Pass a hostname, or set verify_mode to CERT_NONE to connect without checking identity.")

        else:
            if host.endswith("."):
                host = host[:-1]

            identity = TLSSession.identity(host)

            if not host.replace(".", "").isdigit() and ":" not in host:
                self.library.ctrl(self.pointer, Control.SET_TLSEXT_HOSTNAME, Control.NAMETYPE_HOST, ctypes.cast(ctypes.c_char_p(identity), VOID_P))

            if verify != CERT_NONE:
                self.library.set_host(self.pointer, identity)

        if ech is not None:
            ECHConfigList.parse(ech)

            if self.library.set_ech_config_list is None:
                raise TLSConfigError("This OpenSSL does not provide ECH (Encrypted Client Hello): OpenSSL 4.0 or newer is required.")

            if self.library.set_ech_config_list(self.pointer, ech, len(ech)) != 1:
                raise TLSConfigError(f"OpenSSL rejected the ECH configuration: {self.library.reason()}")

        self.ech = ech

    @staticmethod
    async def connect(transport: UDPConnection, config: Optional[TLSConfig] = None, *, hostname: Optional[str] = None, ech: Optional[bytes] = None, alpn: Optional[List[str]] = None, timeout: Optional[float] = None, context: Optional[QUICContext] = None) -> "QUICConnection":
        from .common import QUICEndpoint

        context = context or QUICContext(config or TLSConfig(), server=False, alpn=alpn)
        endpoint = QUICEndpoint(context)

        try:
            endpoint.adopt(transport)
            connection = endpoint.open(hostname=hostname or transport.dst[0], ech=ech)

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
        if self.ech is not None:
            status = self.ech_status

            if status is not None and status.code in (ECHStatus.FAILED_ECH, ECHStatus.FAILED_ECH_BAD_NAME):
                raise TLSECHError(f"{message}: the server rejected Encrypted Client Hello ({self.library.reason()})", status=status, retry_config=self.ech_retry_config)

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
