import os
import time
import signal
import socket
import asyncio
import inspect
from typing import Optional, List, Deque, Callable
from collections import deque
from dataclasses import dataclass, field

from ...models import ServerLimits
from ..models import UDSPort
from ..errors import UDSError
from ..protocol import UDSConnection, UDSProtocol
from .common import UDSLimits, UDSConfig

@dataclass
class UDSServerLimits(UDSLimits, ServerLimits):
    idle_timeout: Optional[float] = None

@dataclass
class UDSServerConfig(UDSConfig):
    limits: UDSServerLimits = field(default_factory=lambda: UDSServerLimits())

    mode: Optional[int] = None # permission bits applied to each bound socket file, e.g. 0o600.

class UDSHandler:
    def __init__(self, on_connection: Optional[Callable] = None):
        self.on_connection = on_connection # (connection: UDSConnection) -> None

class UDSGate:
    def __init__(self, limits: UDSServerLimits):
        self.limits = limits
        self.connections = 0
        self.history: Deque[float] = deque()

    @property
    def window(self) -> float:
        return max((period for period, _ in self.limits.max_connection_rate), default=0.0)

    def admit(self, now: Optional[float] = None) -> bool:
        if self.connections >= self.limits.max_connection_nums:
            return False

        now = time.monotonic() if now is None else now

        if not self.rate(now):
            return False

        self.connections += 1
        return True

    def rate(self, now: float) -> bool:
        while self.history and now - self.history[0] > self.window:
            self.history.popleft()

        for period, nums in self.limits.max_connection_rate:
            if sum(1 for at in self.history if now - at <= period) >= nums:
                return False

        self.history.append(now)
        return True

    def release(self):
        self.connections = max(0, self.connections - 1)

class UDSServerProtocol(UDSProtocol):
    def __init__(self, server: "UDSServer", handler: UDSHandler):
        super().__init__(handler=handler, limits=server.config.limits)
        self.server = server

    def connection_made(self, transport: asyncio.Transport):
        super().connection_made(transport)
        self.server.accept(self.connection)

    def connection_lost(self, exc: Optional[BaseException]):
        super().connection_lost(exc)
        self.server.forget(self.connection)

class UDSServer:
    def __init__(self, config: Optional[UDSServerConfig] = None):
        self.config = config or UDSServerConfig()

        self.gate = UDSGate(self.config.limits)
        self.handler: Optional[UDSHandler] = None

        self.servers: List[asyncio.AbstractServer] = []
        self.connections = set()
        self.tasks = set()

        self.sweeper: Optional[asyncio.Future] = None
        self.stopped: Optional[asyncio.Event] = None

    @property
    def paths(self) -> List[UDSPort]:
        return [UDSProtocol.address(sock.getsockname()) for server in self.servers for sock in (server.sockets or ())]

    @property
    def interval(self) -> float:
        return max(1.0, self.config.limits.idle_timeout / 4) if self.config.limits.idle_timeout else max(1.0, self.gate.window)

    async def listen(self, handler: UDSHandler, paths: Optional[List[UDSPort]] = None, *, sockets: Optional[List[socket.socket]] = None):
        if not paths and not sockets:
            raise ValueError("At least one UDS path must be provided.")

        self.handler = handler
        self.stopped = asyncio.Event()

        loop = asyncio.get_running_loop()

        bound = sockets or [self.bind(path) for path in paths]
        servers: List[asyncio.AbstractServer] = []

        try:
            for sock in bound:
                servers.append(await loop.create_unix_server(lambda: UDSServerProtocol(self, handler), sock=sock))

        except BaseException:
            bound_paths = [UDSProtocol.address(sock.getsockname()) for sock in bound]

            for server in servers:
                server.close()

            for sock in bound[len(servers):]:
                sock.close()

            for path in bound_paths:
                self.unlink(path)

            raise

        self.servers = servers

        self.sweeper = asyncio.ensure_future(self.watch())

    async def serve(self, handler: UDSHandler, paths: Optional[List[UDSPort]] = None, *, sockets: Optional[List[socket.socket]] = None):
        await self.listen(handler, paths, sockets=sockets)
        await self.stopped.wait()

    def bind(self, path: UDSPort) -> socket.socket:
        self.unlink(path)

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        if self.config.mode is not None and not path.abstract:
            previous = os.umask(0o777 & ~self.config.mode)

            try:
                sock.bind(str(path))
            finally:
                os.umask(previous)

            os.chmod(str(path), self.config.mode)

        else:
            sock.bind(str(path))

        sock.listen(100)

        return sock

    def unlink(self, path: UDSPort):
        if not path or path.abstract:
            return

        try:
            os.unlink(str(path))
        except FileNotFoundError:
            pass

    def accept(self, connection: UDSConnection):
        if not self.gate.admit():
            connection.transport.abort()
            return

        self.connections.add(connection)

        task = asyncio.ensure_future(self.dispatch(connection))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def dispatch(self, connection: UDSConnection):
        try:
            if self.handler is not None and self.handler.on_connection is not None:
                result = self.handler.on_connection(connection)

                if inspect.isawaitable(result):
                    await result

        except asyncio.CancelledError:
            raise

        except UDSError:
            pass

        except Exception as e:
            asyncio.get_running_loop().call_exception_handler({"message": f"Unhandled exception in the UDS handler for {connection.dst}", "exception": e})

        finally:
            await connection.close()

    def forget(self, connection: UDSConnection):
        if connection in self.connections:
            self.connections.discard(connection)
            self.gate.release()

    async def watch(self):
        while True:
            await asyncio.sleep(self.interval)
            self.expire()

    def expire(self, now: Optional[float] = None):
        if self.config.limits.idle_timeout is None:
            return

        now = time.monotonic() if now is None else now

        for connection in [c for c in self.connections if now - c.active > self.config.limits.idle_timeout]:
            connection.drop()

    async def close(self, timeout: Optional[float] = None):
        paths = self.paths

        if self.sweeper is not None:
            self.sweeper.cancel()
            self.sweeper = None

        for server in self.servers:
            server.close()

        if self.tasks:
            await asyncio.wait(set(self.tasks), timeout=timeout)

        pending = set(self.tasks)

        for task in pending:
            task.cancel()

        for connection in list(self.connections):
            await connection.close()

        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

        for server in self.servers:
            await server.wait_closed()

        for path in paths:
            self.unlink(path)

        self.servers.clear()
        self.connections.clear()

        if self.stopped is not None:
            self.stopped.set()

    def run(self, handler: UDSHandler, workers: int = 4, paths: Optional[List[UDSPort]] = None):
        if not paths:
            raise ValueError("At least one UDS path must be provided.")

        if workers <= 1:
            self.start(handler, paths)
            return

        sockets = [self.bind(path) for path in paths]
        children: List[int] = []

        for _ in range(workers):
            pid = os.fork()

            if pid == 0:
                try:
                    self.start(handler, paths, sockets=sockets)
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

            for sock in sockets:
                sock.close()

            for path in paths:
                self.unlink(path)

    def start(self, handler: UDSHandler, paths: List[UDSPort], *, sockets: Optional[List[socket.socket]] = None):
        try:
            import uvloop
            run = uvloop.run
        except ImportError:
            run = asyncio.run

        try:
            run(self.serve(handler, paths, sockets=sockets))
        except KeyboardInterrupt:
            pass
