import os
import time
import shutil
import signal
import socket
import asyncio
import inspect
import tempfile
from typing import Optional, List, Dict, Deque, Tuple, Callable
from collections import deque
from dataclasses import dataclass, field

from ...tls import TLSConfig
from ...tls.errors import TLSError
from ...protocol import ServerLimits
from ...udp.models import UDPPort
from ...udp.api.server import UDPServer
from ..errors import QUICError
from ..models import QUICPacket
from ..tls import QUICContext
from ..protocol import QUICEndpoint, QUICConnection

@dataclass
class QUICServerLimits(ServerLimits):
    max_stream_nums: int = 100 # per connection

@dataclass
class QUICServerConfig:
    limits: QUICServerLimits = field(default_factory=lambda: QUICServerLimits())

    idle_timeout: float = 30.0

    tls: Optional[TLSConfig] = None

    alpn: Optional[List[str]] = None

    validate: bool = True

    handshake_timeout: Optional[float] = 30.0

class QUICHandler:
    def __init__(self, on_connection: Optional[Callable] = None):
        self.on_connection = on_connection  # (connection: QUICConnection) -> None

class QUICGate:
    def __init__(self, limits: QUICServerLimits):
        self.limits = limits
        self.connections = 0
        self.history: Dict[str, Deque[float]] = {}

    @property
    def window(self) -> float:
        return max((period for period, _ in self.limits.max_connection_rate), default=0.0)

    def admit(self, host: str, now: Optional[float] = None) -> bool:
        if self.connections >= self.limits.max_connection_nums:
            return False

        now = time.monotonic() if now is None else now

        if not self.rate(host, now):
            return False

        self.connections += 1
        return True

    def rate(self, host: str, now: float) -> bool:
        record = self.history.get(host)

        if record is None:
            record = self.history[host] = deque()

        while record and now - record[0] > self.window:
            record.popleft()

        for period, nums in self.limits.max_connection_rate:
            if sum(1 for at in record if now - at <= period) >= nums:
                return False

        record.append(now)
        return True

    def release(self):
        self.connections = max(0, self.connections - 1)

    def sweep(self, now: Optional[float] = None):
        now = time.monotonic() if now is None else now

        for host in [host for host, record in self.history.items() if not record or now - record[-1] > self.window]:
            del self.history[host]

class QUICRelay:
    def __init__(self, paths: List[str], index: int, sock: socket.socket):
        self.paths = paths
        self.index = index
        self.socket = sock

        self.transport: Optional[asyncio.DatagramTransport] = None
        self.endpoints: List["QUICServerEndpoint"] = []

    @staticmethod
    def prepare(workers: int) -> Tuple[str, List[str], List[socket.socket]]:
        directory = tempfile.mkdtemp(prefix="kaede-quic-")

        if len(os.path.join(directory, str(workers))) > 100:
            shutil.rmtree(directory, ignore_errors=True)
            directory = tempfile.mkdtemp(prefix="kaede-quic-", dir="/tmp")

        paths: List[str] = []
        sockets: List[socket.socket] = []

        for index in range(workers):
            path = os.path.join(directory, str(index))
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

            try:
                sock.setblocking(False)
                sock.bind(path)

            except BaseException:
                sock.close()

                for opened in sockets:
                    opened.close()

                shutil.rmtree(directory, ignore_errors=True)
                raise

            paths.append(path)
            sockets.append(sock)

        return directory, paths, sockets

    @staticmethod
    def pack(data: bytes, address: Tuple[str, int]) -> bytes:
        host = address[0].encode()

        return bytes([len(host)]) + host + int(address[1]).to_bytes(2, "big") + data

    @staticmethod
    def unpack(message: bytes) -> Optional[Tuple[bytes, Tuple[str, int]]]:
        if len(message) < 3:
            return None

        size = message[0]

        if len(message) < 1 + size + 2:
            return None

        host = message[1:1 + size].decode(errors="replace")
        port = int.from_bytes(message[1 + size:3 + size], "big")

        return (message[3 + size:], (host, port))

    async def open(self, endpoints: List["QUICServerEndpoint"]):
        self.endpoints = endpoints
        self.transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(lambda: QUICRelayProtocol(self), sock=self.socket)

    def spread(self, data: bytes, address: Tuple[str, int]):
        if self.transport is None:
            return

        message = QUICRelay.pack(data, address)

        for index, path in enumerate(self.paths):
            if index == self.index:
                continue

            try:
                self.transport.sendto(message, path)

            except OSError:
                continue

    def arrive(self, message: bytes):
        found = QUICRelay.unpack(message)

        if found is None:
            return

        data, address = found

        for endpoint in self.endpoints:
            if endpoint.mine(data):
                endpoint.take(data, address)
                return

    def close(self):
        if self.transport is not None:
            self.transport.close()
            self.transport = None

class QUICRelayProtocol(asyncio.DatagramProtocol):
    def __init__(self, relay: QUICRelay):
        self.relay = relay

    def datagram_received(self, data: bytes, addr):
        self.relay.arrive(data)

    def error_received(self, exc: OSError):
        return

class QUICServerEndpoint(QUICEndpoint):
    def __init__(self, context: QUICContext, *, server: bool = True, owner: Optional["QUICServer"] = None, relay: Optional[QUICRelay] = None):
        super().__init__(context, server=server)

        self.owner = owner
        self.relay = relay

        self.identifiers: Dict[bytes, Tuple[str, int]] = {}
        self.lengths = set()

    def arrive(self, connection: QUICConnection) -> bool:
        return self.owner.accept(connection) if self.owner is not None else True

    def learn(self, data: bytes, address: Tuple[str, int]):
        packet = QUICPacket.read(data)

        if packet is not None and packet.long and packet.source:
            self.identifiers[packet.source] = address
            self.lengths.add(len(packet.source))

    def unlearn(self, connection: QUICConnection):
        self.identifiers = {source: address for source, address in self.identifiers.items() if address != connection.dst}
        self.lengths = {len(source) for source in self.identifiers}

    def mine(self, data: bytes) -> bool:
        packet = QUICPacket.read(data)

        if packet is not None and packet.long:
            return packet.destination in self.identifiers

        for length in self.lengths:
            packet = QUICPacket.read(data, length)

            if packet is not None and packet.destination in self.identifiers:
                return True

        return False

    def owns(self, data: bytes, address: Tuple[str, int]) -> bool:
        if self.relay is None:
            return True

        packet = QUICPacket.read(data)

        if packet is not None and packet.initial:
            return True

        if self.mine(data):
            return True

        self.relay.spread(data, address)
        return False

class QUICServer:
    def __init__(self, config: Optional[QUICServerConfig] = None):
        self.config = config or QUICServerConfig()

        self.gate = QUICGate(self.config.limits)
        self.handler: Optional[QUICHandler] = None

        self.context = QUICContext(self.config.tls or TLSConfig(), server=True, alpn=self.config.alpn)

        self.endpoints: List[QUICServerEndpoint] = []
        self.connections = set()
        self.tasks = set()

        self.relay: Optional[QUICRelay] = None

        self.sweeper: Optional[asyncio.Future] = None
        self.stopped: Optional[asyncio.Event] = None

    @property
    def ports(self) -> List[Tuple[str, UDPPort]]:
        return [endpoint.src for endpoint in self.endpoints]

    @property
    def interval(self) -> float:
        return max(1.0, self.config.idle_timeout / 4)

    async def listen(self, handler: QUICHandler, ports: Optional[List[Tuple[str, UDPPort]]] = None, *, reuse_port: bool = False, sockets: Optional[List[socket.socket]] = None):
        ports = [("0.0.0.0", UDPPort(0))] if ports is None else ports

        self.handler = handler
        self.stopped = asyncio.Event()

        opened: List[QUICServerEndpoint] = []

        try:
            if sockets:
                for sock in sockets:
                    opened.append(await QUICServerEndpoint.serve(self.context, ("", UDPPort(0)), validate=self.config.validate, sock=sock, owner=self, relay=self.relay))
            else:
                for host, port in ports:
                    opened.append(await QUICServerEndpoint.serve(self.context, (host, UDPPort(port)), validate=self.config.validate, reuse_port=reuse_port, owner=self, relay=self.relay))

            if self.relay is not None:
                await self.relay.open(opened)

        except BaseException:
            for endpoint in opened:
                await endpoint.close()

            raise

        self.endpoints = opened
        self.sweeper = asyncio.ensure_future(self.watch())

    async def serve(self, handler: QUICHandler, ports: Optional[List[Tuple[str, UDPPort]]] = None, *, reuse_port: bool = False, sockets: Optional[List[socket.socket]] = None):
        await self.listen(handler, ports, reuse_port=reuse_port, sockets=sockets)
        await self.stopped.wait()

    @staticmethod
    def bind(host: str, port: UDPPort, *, reuse_port: bool = False) -> socket.socket:
        return UDPServer.bind(host, port, reuse_port=reuse_port)

    def accept(self, connection: QUICConnection) -> bool:
        if not self.gate.admit(connection.dst[0]):
            return False

        self.connections.add(connection)

        task = asyncio.ensure_future(self.dispatch(connection))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

        return True

    async def dispatch(self, connection: QUICConnection):
        try:
            connection.max_streams = self.config.limits.max_stream_nums

            await connection.handshake(self.config.handshake_timeout)

            if self.handler is not None and self.handler.on_connection is not None:
                result = self.handler.on_connection(connection)

                if inspect.isawaitable(result):
                    await result

        except asyncio.CancelledError:
            raise

        except (QUICError, TLSError):
            pass

        except Exception as e:
            asyncio.get_running_loop().call_exception_handler({"message": f"Unhandled exception in the QUIC handler for {connection.dst[0]}:{int(connection.dst[1])}", "exception": e})

        finally:
            endpoint = connection.endpoint

            try:
                await connection.close()

            except Exception:
                pass

            endpoint.forget(connection)
            self.forget(connection)

    def forget(self, connection: QUICConnection):
        if connection in self.connections:
            self.connections.discard(connection)
            self.gate.release()

    async def watch(self):
        while True:
            await asyncio.sleep(self.interval)
            self.expire()

    def expire(self, now: Optional[float] = None):
        now = time.monotonic() if now is None else now

        for connection in [c for c in self.connections if now - c.active > self.config.idle_timeout]:
            asyncio.ensure_future(connection.close(timeout=1.0))

        self.gate.sweep(now)

    async def close(self, timeout: Optional[float] = None):
        if self.sweeper is not None:
            self.sweeper.cancel()
            self.sweeper = None

        for connection in list(self.connections):
            await connection.close(timeout=1.0)

        if self.tasks:
            await asyncio.wait(set(self.tasks), timeout=timeout)

        for task in set(self.tasks):
            task.cancel()

        for endpoint in self.endpoints:
            await endpoint.close()

        if self.relay is not None:
            self.relay.close()

        await asyncio.sleep(0)

        self.endpoints.clear()
        self.connections.clear()

        if self.stopped is not None:
            self.stopped.set()

    def run(self, handler: QUICHandler, workers: int = 4, ports: Optional[List[Tuple[str, UDPPort]]] = None):
        ports = [("0.0.0.0", UDPPort(0))] if ports is None else ports

        if workers <= 1:
            self.start(handler, ports, reuse_port=False)
            return

        directory, paths, sockets = QUICRelay.prepare(workers)
        children: List[int] = []

        try:
            for index in range(workers):
                pid = os.fork()

                if pid == 0:
                    try:
                        for other, sock in enumerate(sockets):
                            if other != index:
                                sock.close()

                        self.relay = QUICRelay(paths, index, sockets[index])
                        self.start(handler, ports, reuse_port=True)

                    finally:
                        os._exit(0)

                children.append(pid)

            for sock in sockets:
                sock.close()

            def stop(signum, frame):
                for pid in children:
                    try:
                        os.kill(pid, signal.SIGTERM)
                    except ProcessLookupError:
                        continue

            previous = [signal.signal(number, stop) for number in (signal.SIGINT, signal.SIGTERM)]

            try:
                for pid in children:
                    os.waitpid(pid, 0)

            finally:
                for number, handle in zip((signal.SIGINT, signal.SIGTERM), previous):
                    signal.signal(number, handle)

        finally:
            shutil.rmtree(directory, ignore_errors=True)

    def start(self, handler: QUICHandler, ports: List[Tuple[str, UDPPort]], *, reuse_port: bool = False):
        try:
            import uvloop
            run = uvloop.run
        except ImportError:
            run = asyncio.run

        try:
            run(self.serve(handler, ports, reuse_port=reuse_port))
        except KeyboardInterrupt:
            pass
