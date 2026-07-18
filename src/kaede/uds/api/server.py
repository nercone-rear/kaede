import os
import time
import signal
import socket
import asyncio
import inspect
from typing import Optional, List, Deque, Callable
from collections import deque
from dataclasses import dataclass, field

from ...protocol import ServerLimits
from ..models import UDSAddress
from ..errors import UDSError
from ..protocol import UDSConnection, UDSProtocol

@dataclass
class UDSServerLimits(ServerLimits):
    pass

@dataclass
class UDSServerConfig:
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
        super().__init__(handler=handler)
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

        self.stopped: Optional[asyncio.Event] = None

    @property
    def paths(self) -> List[UDSAddress]:
        return [UDSProtocol.address(sock.getsockname()) for server in self.servers for sock in (server.sockets or ())]

    async def listen(self, handler: UDSHandler, paths: Optional[List[UDSAddress]] = None, *, sockets: Optional[List[socket.socket]] = None):
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

    async def serve(self, handler: UDSHandler, paths: Optional[List[UDSAddress]] = None, *, sockets: Optional[List[socket.socket]] = None):
        await self.listen(handler, paths, sockets=sockets)
        await self.stopped.wait()

    def bind(self, path: UDSAddress) -> socket.socket:
        self.unlink(path)

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(path))
        sock.listen(100)

        if self.config.mode is not None and not path.abstract:
            os.chmod(str(path), self.config.mode)

        return sock

    def unlink(self, path: UDSAddress):
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

    async def close(self, timeout: Optional[float] = None):
        paths = self.paths

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

        for path in paths:
            self.unlink(path)

        self.servers.clear()
        self.connections.clear()

        if self.stopped is not None:
            self.stopped.set()

    def run(self, handler: UDSHandler, workers: int = 4, paths: Optional[List[UDSAddress]] = None):
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

    def start(self, handler: UDSHandler, paths: List[UDSAddress], *, sockets: Optional[List[socket.socket]] = None):
        try:
            import uvloop
            run = uvloop.run
        except ImportError:
            run = asyncio.run

        try:
            run(self.serve(handler, paths, sockets=sockets))
        except KeyboardInterrupt:
            pass
