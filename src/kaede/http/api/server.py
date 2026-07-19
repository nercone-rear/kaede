import os
import signal
import asyncio
import inspect
from typing import Optional, Union, Tuple, List, Dict
from dataclasses import dataclass, field

from ...tls import TLSConfig
from ...tls.errors import TLSError
from ...protocol import ServerLimits
from ...tcp import TCPPort, TCPServer, TCPServerConfig, TCPServerLimits
from ...tcp.errors import TCPError
from ...uds import UDSAddress, UDSServer, UDSServerConfig, UDSServerLimits
from ...uds.errors import UDSError
from ...udp import UDPPort
from ...quic import QUICServer, QUICServerConfig, QUICServerLimits
from ...quic.errors import QUICError
from ..models import HTTPVersion, HTTPBroadRole, HTTPRole, HTTPPort, HTTPLimits, HTTPHeaders, HTTPResponse
from ..errors import HTTPError
from ..protocol import HTTPState, HTTPConnection, H1Connection
from ..protocol.handler import HUHandler, HTHandler, HQHandler
from ..finalizer import finalize_response
from ..websocket import WSConnection, WSFrame

@dataclass
class HTTPServerLimits(ServerLimits, HTTPLimits):
    pass

@dataclass
class HTTPServerConfig:
    versions: List[HTTPVersion] = field(default_factory=lambda: ["HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0"])

    limits: HTTPServerLimits = field(default_factory=lambda: HTTPServerLimits())

    tls: Optional[Union[TLSConfig, Dict[str, TLSConfig]]] = None # TLSConfig or {hostname: TLSConfig, ...}

    idle_timeout: float = 60.0
    handshake_timeout: Optional[float] = 30.0

class HTTPHandler:
    async def on_connection(self, connection: HTTPConnection):
        await connection.receive()
        await connection.send(await finalize_response(HTTPResponse(version=connection.version, status_code=200, headers=HTTPHeaders(), body=b"This is Default Response from Kaede.")))

    async def on_websocket(self, connection: WSConnection):
        await connection.close(1011, "WebSocket not configured.")

class HTTPServer:
    def __init__(self, *, role: HTTPRole = HTTPRole.ORIGIN, config: Optional[HTTPServerConfig] = None):
        self.role = role
        self.config = config or HTTPServerConfig()

        self.handler: Optional[HTTPHandler] = None
        self.servers: List[Tuple[HTTPPort, Union[UDSServer, TCPServer]]] = []

        self.stopped: Optional[asyncio.Event] = None

    @property
    def alpn(self) -> List[str]:
        offer: List[str] = []

        if "HTTP/2.0" in self.config.versions:
            offer.append("h2")

        if "HTTP/1.1" in self.config.versions or "HTTP/1.0" in self.config.versions:
            offer.append("http/1.1")

        return offer

    @property
    def ports(self) -> List[Tuple[str, HTTPPort]]:
        found: List[Tuple[str, HTTPPort]] = []

        for port, server in self.servers:
            if port.type == "uds":
                for path in server.paths:
                    found.append(("", HTTPPort("uds", str(path))))
            else:
                for host, bound in server.ports:
                    found.append((host, HTTPPort(port.type, bound, port.secure)))

        return found

    def limits(self, kind):
        return kind(max_connection_nums=self.config.limits.max_connection_nums, max_connection_rate=list(self.config.limits.max_connection_rate))

    def credentials(self, host: str) -> Optional[TLSConfig]:
        if isinstance(self.config.tls, dict):
            return self.config.tls.get(host) or self.config.tls.get("*") or next(iter(self.config.tls.values()), None)

        return self.config.tls

    async def listen(self, handler: HTTPHandler, ports: Optional[List[Tuple[str, HTTPPort]]] = None, *, reuse_port: bool = False):
        ports = [("0.0.0.0", HTTPPort("tcp", TCPPort(0)))] if ports is None else ports

        self.handler = handler
        self.stopped = asyncio.Event()

        try:
            for host, port in ports:
                await self.attach(host, port, reuse_port)

        except BaseException:
            await self.close()
            raise

    async def serve(self, handler: HTTPHandler, ports: Optional[List[Tuple[str, HTTPPort]]] = None, *, reuse_port: bool = False):
        await self.listen(handler, ports, reuse_port=reuse_port)
        await self.stopped.wait()

    async def attach(self, host: str, port: HTTPPort, reuse_port: bool):
        if not port.valid:
            raise HTTPError(500, f"The port {port!r} is not a valid HTTP port.")

        if port.type == "uds":
            server = UDSServer(UDSServerConfig(limits=self.limits(UDSServerLimits)))
            await server.listen(HUHandler(self), [UDSAddress(str(port.value))])

        elif port.type == "tcp":
            config = TCPServerConfig(limits=self.limits(TCPServerLimits), handshake_timeout=self.config.handshake_timeout)

            if port.secure:
                config.tls = self.credentials(host)

                if config.tls is None:
                    raise HTTPError(500, "A secure HTTP port needs a TLSConfig with a certificate.")

                config.alpn = self.alpn

            server = TCPServer(config)
            await server.listen(HTHandler(self, secure=port.secure), [(host, TCPPort(int(port.value)))], reuse_port=reuse_port)

        elif port.type == "quic":
            credentials = self.credentials(host)

            if credentials is None:
                raise HTTPError(500, "An HTTP/3 port needs a TLSConfig with a certificate.")

            config = QUICServerConfig(limits=self.limits(QUICServerLimits), idle_timeout=self.config.idle_timeout, tls=credentials, alpn=["h3"], handshake_timeout=self.config.handshake_timeout)
            server = QUICServer(config)
            await server.listen(HQHandler(self), [(host, UDPPort(int(port.value)))], reuse_port=reuse_port)

        else:
            raise HTTPError(500, f"The {port.type} transport is not supported yet.")

        self.servers.append((port, server))

    def spot(self, connection, secure: bool) -> Tuple[Tuple[str, HTTPPort], Tuple[str, HTTPPort]]:
        kind = "uds" if isinstance(connection.dst, str) or not isinstance(connection.dst, tuple) else "tcp"

        if kind == "uds":
            return (("", HTTPPort("uds", str(connection.src))), ("", HTTPPort("uds", str(connection.dst))))

        src = (connection.src[0], HTTPPort("tcp", connection.src[1], secure))
        dst = (connection.dst[0], HTTPPort("tcp", connection.dst[1], secure))

        return (src, dst)

    async def serve_stream(self, connection, *, secure: bool):
        protocol = getattr(connection, "protocol", None)

        if protocol == "h2":
            from ..protocol.h2 import H2Session

            await H2Session(connection, server=True, limits=self.config.limits).run(self.handler, self)
            return

        await self.serve_h1(connection, secure=secure)

    async def serve_quic(self, connection):
        from ..protocol.h3 import H3Session

        await H3Session(connection, server=True, limits=self.config.limits).run(self.handler, self)

    async def serve_h1(self, connection, *, secure: bool):
        src, dst = self.spot(connection, secure)
        version = "HTTP/1.1" if "HTTP/1.1" in self.config.versions else "HTTP/1.0"

        h1 = H1Connection(src, dst, transport=connection, role=HTTPBroadRole.SERVER, version=version, limits=self.config.limits)

        try:
            while True:
                try:
                    if not await h1.begin():
                        break

                except HTTPError as e:
                    await self.error(h1, e)
                    break

                if h1.request.is_websocket_upgrade:
                    await self.upgrade(h1, connection)
                    break

                try:
                    result = self.handler.on_connection(h1)

                    if inspect.isawaitable(result):
                        await result

                except HTTPError as e:
                    if not h1.replied:
                        await self.error(h1, e)

                    break

                except (TCPError, UDSError, TLSError):
                    break

                if not h1.replied:
                    await self.error(h1, HTTPError(500, "Internal Server Error"))
                    break

                try:
                    await h1.drain()

                except (TCPError, UDSError, TLSError):
                    break

                if not h1.reusable:
                    break

        except (TCPError, UDSError, TLSError):
            pass

        finally:
            await h1.close()

    def keyed(self, key: str) -> bool:
        from base64 import b64decode

        try:
            return len(b64decode(key, validate=True)) == 16

        except (ValueError, TypeError):
            return False

    async def upgrade(self, h1: H1Connection, connection):
        request = h1.request
        key = request.headers.get("Sec-WebSocket-Key", "")
        version = request.headers.get("Sec-WebSocket-Version", "")

        if version != "13" or not self.keyed(key):
            headers = HTTPHeaders([
                ("Upgrade", "websocket"),
                ("Connection", "Upgrade"),
                ("Sec-WebSocket-Version", "13"),
            ])

            await self.error(h1, HTTPError(426, "Upgrade Required", headers))
            return

        headers = HTTPHeaders([
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Accept", WSFrame.accept(key)),
        ])

        try:
            await connection.send(b"HTTP/1.1 101 Switching Protocols\r\n" + headers.build().encode("latin-1") + b"\r\n")

        except (TCPError, UDSError, TLSError):
            return

        websocket = WSConnection(h1.src, h1.dst, transport=connection, server=True)

        try:
            result = self.handler.on_websocket(websocket)

            if inspect.isawaitable(result):
                await result

        except (TCPError, UDSError, TLSError):
            pass

        finally:
            await websocket.close()

    async def error(self, h1: H1Connection, exc: HTTPError):
        try:
            h1.closing = True
            response = HTTPResponse(status_code=exc.code, headers=exc.headers or HTTPHeaders(), body=(exc.message or "").encode(), compression=False)
            await h1.send(await finalize_response(response, self.role))

        except (HTTPError, TCPError, UDSError, TLSError):
            pass

    async def close(self, timeout: Optional[float] = None):
        servers, self.servers = self.servers, []

        for port, server in servers:
            await server.close(timeout)

        if self.stopped is not None:
            self.stopped.set()

    def run(self, handler: HTTPHandler, workers: int = 4, ports: Optional[List[Tuple[str, HTTPPort]]] = None):
        ports = [("0.0.0.0", HTTPPort("tcp", TCPPort(0)))] if ports is None else ports

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

    def start(self, handler: HTTPHandler, ports: List[Tuple[str, HTTPPort]], *, reuse_port: bool = False):
        try:
            import uvloop
            run = uvloop.run
        except ImportError:
            run = asyncio.run

        try:
            run(self.serve(handler, ports, reuse_port=reuse_port))
        except KeyboardInterrupt:
            pass
