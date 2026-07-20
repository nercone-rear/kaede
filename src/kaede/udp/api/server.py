import os
import time
import signal
import socket
import asyncio
import inspect
from typing import Optional, List, Dict, Deque, Tuple, Callable
from collections import deque
from dataclasses import dataclass, field

from ...tls import TLSConfig
from ...tls.openssl import TLSContext, Cookies
from ...tls.errors import TLSError
from ...protocol import ServerLimits
from ..models import UDPPort
from ..errors import UDPError
from ..protocol import UDPConnection, UDPProtocol
from ..tls import DTLSConnection

@dataclass
class UDPServerLimits(ServerLimits):
    pass

@dataclass
class UDPServerConfig:
    limits: UDPServerLimits = field(default_factory=lambda: UDPServerLimits())

    idle_timeout: float = 30.0

    tls: Optional[TLSConfig] = None
    alpn: Optional[List[str]] = None

    cookies: bool = True

    handshake_timeout: Optional[float] = 30.0

class UDPHandler:
    def __init__(self, on_connection: Optional[Callable] = None):
        self.on_connection = on_connection  # (connection: UDPConnection) -> None

class UDPGate:
    def __init__(self, limits: UDPServerLimits):
        self.limits = limits
        self.connections = 0
        self.history: Dict[str, Deque[float]] = {}
        self.history_limit = max(1024, limits.max_connection_nums)

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

            while len(self.history) > self.history_limit:
                del self.history[next(iter(self.history))]

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

class UDPServerProtocol(UDPProtocol):
    def __init__(self, server: "UDPServer", handler: UDPHandler, sock: Optional[socket.socket] = None):
        super().__init__(handler=handler, sock=sock)
        self.server = server

    def arrive(self, connection: UDPConnection) -> bool:
        return self.server.accept(connection)

class UDPServer:
    def __init__(self, config: Optional[UDPServerConfig] = None):
        self.config = config or UDPServerConfig()

        self.gate = UDPGate(self.config.limits)
        self.handler: Optional[UDPHandler] = None

        self.context = TLSContext(self.config.tls, server=True, alpn=self.config.alpn, datagram=True, cookies=Cookies() if self.config.cookies else None) if self.config.tls is not None else None

        self.sockets: List[socket.socket] = []
        self.endpoints: List[asyncio.DatagramTransport] = []
        self.connections = set()
        self.tasks = set()

        self.sweeper: Optional[asyncio.Future] = None
        self.stopped: Optional[asyncio.Event] = None

    @property
    def ports(self) -> List[Tuple[str, UDPPort]]:
        return [UDPProtocol.address(sock.getsockname()) for sock in self.sockets]

    @property
    def interval(self) -> float:
        return max(1.0, self.config.idle_timeout / 4)

    async def listen(self, handler: UDPHandler, ports: Optional[List[Tuple[str, UDPPort]]] = None, *, reuse_port: bool = False, sockets: Optional[List[socket.socket]] = None):
        ports = [("0.0.0.0", UDPPort(0))] if ports is None else ports

        self.handler = handler
        self.stopped = asyncio.Event()

        loop = asyncio.get_running_loop()

        bound = sockets or [UDPServer.bind(host, port, reuse_port=reuse_port) for host, port in ports]
        endpoints: List[asyncio.DatagramTransport] = []

        try:
            for sock in bound:
                transport, _ = await loop.create_datagram_endpoint(lambda taken=sock: UDPServerProtocol(self, handler, sock=taken), sock=sock)
                endpoints.append(transport)

        except BaseException:
            for transport in endpoints:
                transport.close()

            for sock in bound:
                sock.close()

            raise

        self.sockets = bound
        self.endpoints = endpoints

        self.sweeper = asyncio.ensure_future(self.watch())

    async def serve(self, handler: UDPHandler, ports: Optional[List[Tuple[str, UDPPort]]] = None, *, reuse_port: bool = False, sockets: Optional[List[socket.socket]] = None):
        await self.listen(handler, ports, reuse_port=reuse_port, sockets=sockets)
        await self.stopped.wait()

    @staticmethod
    def bind(host: str, port: UDPPort, *, reuse_port: bool = False) -> socket.socket:
        family, kind, proto, _, address = socket.getaddrinfo(host, int(port), type=socket.SOCK_DGRAM)[0]
        sock = socket.socket(family, kind, proto)

        try:
            sock.setblocking(False)

            if reuse_port:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

            sock.bind(address)

        except BaseException:
            sock.close()
            raise

        return sock

    def accept(self, connection: UDPConnection) -> bool:
        if not self.gate.admit(connection.dst[0]):
            return False

        self.connections.add(connection)

        task = asyncio.ensure_future(self.dispatch(connection))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

        return True

    async def dispatch(self, connection: UDPConnection):
        served = connection

        try:
            if self.context is not None:
                served = await DTLSConnection.accept(connection, timeout=self.config.handshake_timeout, context=self.context)

            if self.handler is not None and self.handler.on_connection is not None:
                result = self.handler.on_connection(served)

                if inspect.isawaitable(result):
                    await result

        except asyncio.CancelledError:
            raise

        except (UDPError, TLSError):
            pass

        except Exception as e:
            asyncio.get_running_loop().call_exception_handler({"message": f"Unhandled exception in the UDP handler for {connection.dst[0]}:{int(connection.dst[1])}", "exception": e})

        finally:
            await served.close()
            self.forget(connection)

    def forget(self, connection: UDPConnection):
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
            connection.drop()

        self.gate.sweep(now)

    async def close(self, timeout: Optional[float] = None):
        if self.sweeper is not None:
            self.sweeper.cancel()
            self.sweeper = None

        for connection in list(self.connections):
            connection.drop()

        if self.tasks:
            await asyncio.wait(set(self.tasks), timeout=timeout)

        pending = set(self.tasks)

        for task in pending:
            task.cancel()

        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

        for transport in self.endpoints:
            transport.close()

        await asyncio.sleep(0)

        self.endpoints.clear()
        self.connections.clear()
        self.sockets.clear()

        if self.stopped is not None:
            self.stopped.set()

    def run(self, handler: UDPHandler, workers: int = 4, ports: Optional[List[Tuple[str, UDPPort]]] = None):
        ports = [("0.0.0.0", UDPPort(0))] if ports is None else ports

        if workers <= 1:
            self.start(handler, ports, reuse_port=False)
            return

        children: List[int] = []

        for _ in range(workers):
            pid = os.fork()

            if pid == 0:
                try:
                    self.start(handler, ports, reuse_port=True)
                finally:
                    os._exit(0)

            children.append(pid)

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

    def start(self, handler: UDPHandler, ports: List[Tuple[str, UDPPort]], *, reuse_port: bool = False):
        try:
            import uvloop
            run = uvloop.run
        except ImportError:
            run = asyncio.run

        try:
            run(self.serve(handler, ports, reuse_port=reuse_port))
        except KeyboardInterrupt:
            pass
