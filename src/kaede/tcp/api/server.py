import os
import time
import signal
import asyncio
import inspect
from typing import Optional, List, Dict, Deque, Tuple, Callable
from collections import deque
from dataclasses import dataclass, field

from ...tls import TLSConfig
from ...tls.openssl import TLSContext
from ...tls.errors import TLSError
from ...protocol import ServerLimits
from ..models import TCPPort
from ..errors import TCPError
from ..protocol import TCPConnection, TCPProtocol
from ..tls import TLSConnection

@dataclass
class TCPServerLimits(ServerLimits):
    pass

@dataclass
class TCPServerConfig:
    limits: TCPServerLimits = field(default_factory=lambda: TCPServerLimits())

    tls: Optional[TLSConfig] = None
    alpn: Optional[List[str]] = None

    handshake_timeout: Optional[float] = 30.0

class TCPHandler:
    def __init__(self, on_connection: Optional[Callable] = None):
        self.on_connection = on_connection  # (connection: TCPConnection) -> None

class TCPGate:
    def __init__(self, limits: TCPServerLimits):
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

class TCPServerProtocol(TCPProtocol):
    def __init__(self, server: "TCPServer", handler: TCPHandler):
        super().__init__(handler=handler)
        self.server = server

    def connection_made(self, transport: asyncio.Transport):
        super().connection_made(transport)
        self.server.accept(self.connection)

    def connection_lost(self, exc: Optional[BaseException]):
        super().connection_lost(exc)
        self.server.forget(self.connection)

class TCPServer:
    def __init__(self, config: Optional[TCPServerConfig] = None):
        self.config = config or TCPServerConfig()

        self.gate = TCPGate(self.config.limits)
        self.handler: Optional[TCPHandler] = None

        self.context = TLSContext(self.config.tls, server=True, alpn=self.config.alpn) if self.config.tls is not None else None

        self.servers: List[asyncio.AbstractServer] = []
        self.connections = set()
        self.tasks = set()

        self.sweeper: Optional[asyncio.Future] = None
        self.stopped: Optional[asyncio.Event] = None

    @property
    def ports(self) -> List[Tuple[str, TCPPort]]:
        return [TCPProtocol.address(sock.getsockname()) for server in self.servers for sock in (server.sockets or ())]

    @property
    def interval(self) -> float:
        return max(1.0, self.gate.window)

    async def listen(self, handler: TCPHandler, ports: Optional[List[Tuple[str, TCPPort]]] = None, *, reuse_port: bool = False):
        ports = [("0.0.0.0", TCPPort(0))] if ports is None else ports

        self.handler = handler
        self.stopped = asyncio.Event()

        loop = asyncio.get_running_loop()

        servers: List[asyncio.AbstractServer] = []

        try:
            for host, port in ports:
                servers.append(await loop.create_server(lambda: TCPServerProtocol(self, handler), host, int(port), reuse_port=reuse_port))

        except BaseException:
            for server in servers:
                server.close()

            raise

        self.servers = servers

        self.sweeper = asyncio.ensure_future(self.watch())

    async def serve(self, handler: TCPHandler, ports: Optional[List[Tuple[str, TCPPort]]] = None, *, reuse_port: bool = False):
        await self.listen(handler, ports, reuse_port=reuse_port)
        await self.stopped.wait()

    def accept(self, connection: TCPConnection):
        if not self.gate.admit(connection.dst[0]):
            connection.transport.abort()
            return

        self.connections.add(connection)

        task = asyncio.ensure_future(self.dispatch(connection))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def dispatch(self, connection: TCPConnection):
        try:
            if self.context is not None:
                connection = await TLSConnection.accept(connection, timeout=self.config.handshake_timeout, context=self.context)

            if self.handler is not None and self.handler.on_connection is not None:
                result = self.handler.on_connection(connection)

                if inspect.isawaitable(result):
                    await result

        except asyncio.CancelledError:
            raise

        except (TCPError, TLSError):
            pass

        except Exception as e:
            asyncio.get_running_loop().call_exception_handler({"message": f"Unhandled exception in the TCP handler for {connection.dst[0]}:{int(connection.dst[1])}", "exception": e})

        finally:
            await connection.close()

    def forget(self, connection: TCPConnection):
        if connection in self.connections:
            self.connections.discard(connection)
            self.gate.release()

    async def watch(self):
        while True:
            await asyncio.sleep(self.interval)
            self.expire()

    def expire(self, now: Optional[float] = None):
        self.gate.sweep(now)

    async def close(self, timeout: Optional[float] = None):
        if self.sweeper is not None:
            self.sweeper.cancel()
            self.sweeper = None

        for server in self.servers:
            server.close()

        if self.tasks:
            await asyncio.wait(set(self.tasks), timeout=timeout)

        for task in set(self.tasks):
            task.cancel()

        for connection in list(self.connections):
            await connection.close()

        for server in self.servers:
            await server.wait_closed()

        self.servers.clear()
        self.connections.clear()

        if self.stopped is not None:
            self.stopped.set()

    def run(self, handler: TCPHandler, workers: int = 4, ports: Optional[List[Tuple[str, TCPPort]]] = None):
        ports = [("0.0.0.0", TCPPort(0))] if ports is None else ports

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

    def start(self, handler: TCPHandler, ports: List[Tuple[str, TCPPort]], *, reuse_port: bool = False):
        try:
            import uvloop
            run = uvloop.run
        except ImportError:
            run = asyncio.run

        try:
            run(self.serve(handler, ports, reuse_port=reuse_port))
        except KeyboardInterrupt:
            pass
