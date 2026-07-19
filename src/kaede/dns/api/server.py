import os
import signal
import asyncio
import inspect
from typing import Optional, Union, Callable, Tuple, List
from dataclasses import dataclass, field

from ...tls import TLSConfig
from ...protocol import ServerLimits
from ...tcp import TCPPort, TCPServer, TCPServerConfig, TCPServerLimits, TCPHandler
from ...udp import UDPPort, UDPServer, UDPServerConfig, UDPServerLimits, UDPHandler
from ...quic import QUICServer, QUICServerConfig, QUICServerLimits, QUICHandler
from ...quic.errors import QUICError
from ..models import DNSPort, DNSResponseCode
from ..errors import DNSError, DNSConnectionError
from ..protocol.handler import DNSConnection
from ..protocol.quic import DNSStream

@dataclass
class DNSServerLimits(ServerLimits):
    pass

@dataclass
class DNSServerConfig:
    limits: DNSServerLimits = field(default_factory=lambda: DNSServerLimits())

    idle_timeout: float = 30.0

    tls: Optional[TLSConfig] = None

    handshake_timeout: Optional[float] = 30.0

class DNSHandler:
    def __init__(self, on_connection: Optional[Callable] = None):
        self.on_connection = on_connection # (connection: DNSConnection) -> None

class DNSServer:
    def __init__(self, *, config: Optional[DNSServerConfig] = None):
        self.config = config or DNSServerConfig()

        self.handler: Optional[DNSHandler] = None
        self.servers: List[Tuple[DNSPort, Union[UDPServer, TCPServer]]] = []

        self.stopped: Optional[asyncio.Event] = None

    async def __aenter__(self) -> "DNSServer":
        return self

    async def __aexit__(self, *_):
        await self.close()

    @property
    def ports(self) -> List[Tuple[str, DNSPort]]:
        found: List[Tuple[str, DNSPort]] = []

        for port, server in self.servers:
            for host, bound in server.ports:
                found.append((host, DNSPort(port.type, bound, port.secure)))

        return found

    def limits(self, kind):
        return kind(max_connection_nums=self.config.limits.max_connection_nums, max_connection_rate=list(self.config.limits.max_connection_rate))

    async def listen(self, handler: DNSHandler, ports: Optional[List[Tuple[str, DNSPort]]] = None, *, reuse_port: bool = False):
        ports = [("0.0.0.0", DNSPort("udp", UDPPort(0))), ("0.0.0.0", DNSPort("tcp", TCPPort(0)))] if ports is None else ports

        self.handler = handler
        self.stopped = asyncio.Event()

        try:
            for host, port in ports:
                await self.attach(host, port, reuse_port)

        except BaseException:
            await self.close()
            raise

    async def serve(self, handler: DNSHandler, ports: Optional[List[Tuple[str, DNSPort]]] = None, *, reuse_port: bool = False):
        await self.listen(handler, ports, reuse_port=reuse_port)
        await self.stopped.wait()

    async def attach(self, host: str, port: DNSPort, reuse_port: bool):
        if not port.valid:
            raise DNSConnectionError(f"The port {port!r} is not a valid DNS port.")

        if port.type == "udp":
            config = UDPServerConfig(limits=self.limits(UDPServerLimits), idle_timeout=self.config.idle_timeout)
            server = UDPServer(config)

            await server.listen(UDPHandler(self.datagram), [(host, UDPPort(int(port.value)))], reuse_port=reuse_port)

        elif port.type == "tcp":
            config = TCPServerConfig(limits=self.limits(TCPServerLimits))

            if port.secure:
                if self.config.tls is None:
                    raise DNSConnectionError("A DNS over TLS port needs a TLSConfig with a certificate.")

                config.tls = self.config.tls
                config.alpn = ["dot"]
                config.handshake_timeout = self.config.handshake_timeout

            server = TCPServer(config)

            await server.listen(TCPHandler(self.stream), [(host, TCPPort(int(port.value)))], reuse_port=reuse_port)

        elif port.type == "quic":
            if self.config.tls is None:
                raise DNSConnectionError("A DNS over QUIC port needs a TLSConfig with a certificate.")

            config = QUICServerConfig(
                limits=self.limits(QUICServerLimits), idle_timeout=self.config.idle_timeout,
                tls=self.config.tls, alpn=["doq"], handshake_timeout=self.config.handshake_timeout
            )
            server = QUICServer(config)

            await server.listen(QUICHandler(self.multiplex), [(host, UDPPort(int(port.value)))], reuse_port=reuse_port)

        else:
            raise DNSConnectionError(f"The {port.type} transport is not supported.")

        self.servers.append((port, server))

    async def datagram(self, connection):
        await self.converse(DNSConnection(connection, stream=False, server=True))

    async def stream(self, connection):
        await self.converse(DNSConnection(connection, stream=True, server=True))

    async def multiplex(self, connection):
        tasks = set()

        try:
            while True:
                stream = await connection.accept(timeout=self.config.idle_timeout)

                task = asyncio.ensure_future(self.confer(DNSConnection(DNSStream(connection, stream), stream=True, server=True)))
                tasks.add(task)
                task.add_done_callback(tasks.discard)

        except QUICError:
            pass

        finally:
            for task in set(tasks):
                task.cancel()

    async def confer(self, connection: DNSConnection):
        try:
            await self.converse(connection)

        finally:
            try:
                await connection.close()

            except (DNSError, QUICError):
                pass

    async def converse(self, connection: DNSConnection):
        try:
            if self.handler is not None and self.handler.on_connection is not None:
                result = self.handler.on_connection(connection)

                if inspect.isawaitable(result):
                    await result

            else:
                await self.decline(connection)

        except asyncio.CancelledError:
            raise

        except DNSError:
            pass

    async def decline(self, connection: DNSConnection):
        while True:
            query = await connection.receive(timeout=self.config.idle_timeout)
            await connection.send(query.reply(rcode=DNSResponseCode.REFUSED))

    async def close(self, timeout: Optional[float] = None):
        servers, self.servers = self.servers, []

        for port, server in servers:
            await server.close(timeout)

        if self.stopped is not None:
            self.stopped.set()

    def run(self, handler: DNSHandler, workers: int = 4, ports: Optional[List[Tuple[str, DNSPort]]] = None):
        ports = [("0.0.0.0", DNSPort("udp", UDPPort(0))), ("0.0.0.0", DNSPort("tcp", TCPPort(0)))] if ports is None else ports

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

    def start(self, handler: DNSHandler, ports: List[Tuple[str, DNSPort]], *, reuse_port: bool = False):
        try:
            import uvloop
            run = uvloop.run
        except ImportError:
            run = asyncio.run

        try:
            run(self.serve(handler, ports, reuse_port=reuse_port))
        except KeyboardInterrupt:
            pass
