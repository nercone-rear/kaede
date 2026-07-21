import os
import signal
import asyncio
import inspect
from typing import Optional, Union, Callable, Tuple, List
from dataclasses import dataclass, field

from ...models import ServerLimits, ServerConfig
from ...tcp import TCPPort, TCPServer, TCPServerConfig, TCPServerLimits
from ...udp import UDPPort, UDPServer, UDPServerConfig, UDPServerLimits
from ...quic import QUICServer, QUICServerConfig, QUICServerLimits
from ..models import DNSPort, DNSResponseCode, DNSMessage
from ..errors import DNSError, DNSConnectionError
from ..protocol.common import TRANSPORT_ERRORS
from ..protocol.base import DNSConnection
from ..protocol.https import DNSHTTPSConnection
from ..protocol.handler import DNSUDPHandler, DNSTCPHandler, DNSTLSHandler, DNSQUICHandler, DNSHTTPSHandler
from .common import DNSLimits, DNSConfig

@dataclass
class DNSServerLimits(DNSLimits, ServerLimits):
    idle_timeout: float = 30.0

    handshake_timeout: Optional[float] = 30.0

@dataclass
class DNSServerConfig(DNSConfig, ServerConfig):
    limits: DNSServerLimits = field(default_factory=lambda: DNSServerLimits())

class DNSHandler:
    def __init__(self, on_connection: Optional[Callable] = None):
        self.on_connection = on_connection # (connection: DNSConnection) -> None

class DNSServer:
    def __init__(self, *, config: Optional[DNSServerConfig] = None):
        self.config = config or DNSServerConfig()

        self.handler: Optional[DNSHandler] = None
        self.servers: List[Tuple[DNSPort, Union[UDPServer, TCPServer, QUICServer]]] = []

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
                found.append((host, DNSPort(port.type, bound.value if port.type == "https" else bound)))

        return found

    def limits(self, kind, **specific):
        return kind(max_connection_nums=self.config.limits.max_connection_nums, max_connection_rate=list(self.config.limits.max_connection_rate), idle_timeout=self.config.limits.idle_timeout, **specific)

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
            config = UDPServerConfig(limits=self.limits(UDPServerLimits))
            server = UDPServer(config)

            await server.listen(DNSUDPHandler(self), [(host, UDPPort(int(port.value)))], reuse_port=reuse_port)

        elif port.type == "tcp":
            config = TCPServerConfig(limits=self.limits(TCPServerLimits, handshake_timeout=self.config.limits.handshake_timeout))

            if self.config.tls:
                config.tls = self.config.tls
                config.alpn = ["dot"]

            server = TCPServer(config)

            await server.listen(DNSTLSHandler(self) if self.config.tls else DNSTCPHandler(self), [(host, TCPPort(int(port.value)))], reuse_port=reuse_port)

        elif port.type == "quic":
            if self.config.tls is None:
                raise DNSConnectionError("A DNS over QUIC port needs a TLSConfig with a certificate.")

            config = QUICServerConfig(
                limits=self.limits(QUICServerLimits, handshake_timeout=self.config.limits.handshake_timeout),
                tls=self.config.tls, alpn=["doq"]
            )
            server = QUICServer(config)

            await server.listen(DNSQUICHandler(self), [(host, UDPPort(int(port.value)))], reuse_port=reuse_port)

        elif port.type == "https":
            if self.config.tls is None:
                raise DNSConnectionError("A DNS over HTTPS port needs a TLSConfig with a certificate.")

            from ...http.models import HTTPPort
            from ...http.api.server import HTTPServer, HTTPServerConfig

            config = HTTPServerConfig(versions=["HTTP/2.0", "HTTP/1.1"])
            config.tls = self.config.tls
            config.limits.idle_timeout = self.config.limits.idle_timeout
            config.limits.handshake_timeout = self.config.limits.handshake_timeout

            server = HTTPServer(config=config)

            await server.listen(DNSHTTPSHandler(self), [(host, HTTPPort("tcp", TCPPort(int(port.value))))], reuse_port=reuse_port)

        else:
            raise DNSConnectionError(f"The {port.type} transport is not supported.")

        self.servers.append((port, server))

    async def resolve(self, query: DNSMessage) -> DNSMessage:
        exchange = DNSHTTPSConnection(query.pack())

        await self.converse(exchange)

        if exchange.reply is None:
            return query.reply(rcode=DNSResponseCode.SERVFAIL)

        return DNSMessage.unpack(exchange.reply)

    async def confer(self, connection: DNSConnection):
        try:
            await self.converse(connection)

        finally:
            try:
                await connection.close()

            except (DNSError,) + TRANSPORT_ERRORS:
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
            query = await connection.receive(timeout=self.config.limits.idle_timeout)
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
