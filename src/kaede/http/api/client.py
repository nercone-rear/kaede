import asyncio
from typing import Optional, List, Dict, Tuple, Union
from dataclasses import dataclass, field, replace

from ...url import URL
from ...constants import Digits
from ...tls import TLSConfig
from ...tls.openssl import TLSContext
from ...tls.errors import TLSError
from ...tcp import TCPPort, TCPConnection, TLSConnection
from ...tcp.errors import TCPError
from ...udp import UDPPort
from ...quic import QUICClient, QUICClientConfig
from ...quic.errors import QUICError
from ..models import HTTPVersion, HTTPMethod, HTTPBroadRole, HTTPRole, HTTPPort, HTTPHeaders, HTTPMessage, HTTPRequest, HTTPResponse, HTTPLimits
from ..errors import HTTPError
from ..headers import CommaHeader
from ..protocol import HTTPConnection, H1Connection
from ..protocol.h2 import H2Session
from ..protocol.h3 import H3Session, Code as H3Code
from ..finalizer import finalize_request
from ..helpers.hsts import HSTSStore
from ..websocket import WSConnection

@dataclass
class HTTPClientConfig:
    versions: List[HTTPVersion] = field(default_factory=lambda: ["HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0"])

    limits: HTTPLimits = field(default_factory=lambda: HTTPLimits())

    tls: Union[TLSConfig, Dict[str, TLSConfig]] = field(default_factory=lambda: TLSConfig()) # TLSConfig or {hostname: TLSConfig, ...}

    connect_timeout: Optional[float] = 30.0

    hsts: bool = True

class HTTPClient:
    DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}

    def __init__(self, *, role: HTTPRole = HTTPRole.USER_AGENT, config: Optional[HTTPClientConfig] = None):
        self.role = role
        self.config = config or HTTPClientConfig()

        self.store = HSTSStore() if self.config.hsts else None
        self.connections: List[HTTPConnection] = []
        self.sessions: Dict[Tuple[str, int, bool], Tuple[H2Session, "asyncio.Future"]] = {}
        self.tunnels: Dict[Tuple[str, int], Tuple[QUICClient, H3Session, "asyncio.Future"]] = {}

    @property
    def only_h3(self) -> bool:
        return "HTTP/3.0" in self.config.versions and not any(version in self.config.versions for version in ("HTTP/2.0", "HTTP/1.1", "HTTP/1.0"))

    async def __aenter__(self) -> "HTTPClient":
        return self

    async def __aexit__(self, *_):
        await self.close()

    def credentials(self, host: str) -> TLSConfig:
        if isinstance(self.config.tls, dict):
            return self.config.tls.get(host) or self.config.tls.get("*") or next(iter(self.config.tls.values()), None) or TLSConfig()

        return self.config.tls or TLSConfig()

    def alpn(self) -> List[str]:
        offer: List[str] = []

        if "HTTP/2.0" in self.config.versions:
            offer.append("h2")

        if "HTTP/1.1" in self.config.versions or "HTTP/1.0" in self.config.versions:
            offer.append("http/1.1")

        return offer

    def upgrade(self, url: URL) -> URL:
        if self.store is None or url.scheme not in ("http", "ws") or not self.store.secure(url.host):
            return url

        return replace(url, scheme={"http": "https", "ws": "wss"}[url.scheme], port=443 if url.port == 80 else url.port)

    def notice(self, host: str, secure: bool, message: HTTPMessage):
        if self.store is None or not isinstance(message, HTTPResponse) or message.headers is None:
            return

        header = message.headers.get("Strict-Transport-Security")

        if header is not None:
            self.store.learn(host, header, secure=secure)

    async def request(self, method: HTTPMethod, url: Union[URL, str], *, headers=None, cookies: Optional[Dict[str, str]] = None, body: Optional[Union[bytes, str]] = None, timeout: Optional[float] = None) -> HTTPConnection:
        url = self.upgrade(URL.parse(url) if isinstance(url, str) else url)
        secure = url.scheme in ("https", "wss")

        host = url.host
        port = url.port or HTTPClient.DEFAULT_PORTS.get(url.scheme, 443 if secure else 80)

        if secure and self.only_h3:
            tunnel = await self.tunnel(host, port, timeout)

            request = HTTPRequest(version="HTTP/3.0", method=method, target=self.target(url), headers=HTTPHeaders(headers or []), body=body, secure=True)
            request.url = url
            self.cookie(request, cookies)

            await finalize_request(request, self.role)
            request.headers.remove("Host")

            return await tunnel.request(request)

        session = await self.session(host, port, secure, timeout) if secure and "HTTP/2.0" in self.config.versions else None

        request = HTTPRequest(version="HTTP/2.0" if session is not None else "HTTP/1.1", method=method, target=self.target(url), headers=HTTPHeaders(headers or []), body=body, secure=secure)
        request.url = url
        self.cookie(request, cookies)

        await finalize_request(request, self.role)

        if session is not None:
            request.headers.remove("Host")
            return await session.request(request)

        connection = await self.connect(host, port, secure, timeout)

        try:
            await connection.send(request)

        except (TCPError, TLSError) as e:
            await connection.close()
            raise HTTPError(502, f"The request could not be sent: {e}")

        return connection

    async def session(self, host: str, port: int, secure: bool, timeout: Optional[float]) -> Optional[H2Session]:
        key = (host, port, secure)
        kept = self.sessions.get(key)

        if kept is not None and not kept[0].closing and kept[0].error is None:
            return kept[0]

        transport = await self.open(host, port, secure, timeout, alpn=self.alpn())

        if getattr(transport, "protocol", None) != "h2":
            self.hold(host, port, secure, transport)
            return None

        session = H2Session(transport, role=HTTPBroadRole.CLIENT, limits=self.config.limits, observer=lambda message: self.notice(host, secure, message))
        await session.start()
        pump = asyncio.ensure_future(session.pump())

        self.sessions[key] = (session, pump)
        return session

    def cookie(self, request: HTTPRequest, cookies: Optional[Dict[str, str]]):
        if cookies:
            from ..headers import Cookie
            request.headers.set("Cookie", Cookie(dict(cookies)).build())

    async def tunnel(self, host: str, port: int, timeout: Optional[float]) -> H3Session:
        key = (host, port)
        kept = self.tunnels.get(key)

        if kept is not None and not kept[1].closing:
            return kept[1]

        client = QUICClient((host, UDPPort(port)), config=QUICClientConfig(
            connect_timeout=timeout if timeout is not None else self.config.connect_timeout,
            tls=self.credentials(host), alpn=["h3"], hostname=host
        ))

        try:
            connection = await client.open()

        except QUICError as e:
            await client.close()
            raise HTTPError(502, f"Could not reach {host}:{port} over HTTP/3: {e}")

        session = H3Session(connection, role=HTTPBroadRole.CLIENT, limits=self.config.limits, observer=lambda message: self.notice(host, True, message))
        await session.start()
        reader = asyncio.ensure_future(self.overhear(session))

        self.tunnels[key] = (client, session, reader)
        return session

    async def overhear(self, session: H3Session):
        try:
            while True:
                stream = await session.connection.accept()

                if stream.readable and stream.writable:
                    await session.fail(H3Code.STREAM_CREATION_ERROR, "The server opened a bidirectional stream.")
                    return

                asyncio.ensure_future(session.consume(stream))

        except QUICError:
            return

    def target(self, url: URL) -> str:
        target = url.path or "/"

        if url.query:
            target += f"?{url.query}"

        return target

    async def open(self, host: str, port: int, secure: bool, timeout: Optional[float], *, alpn: List[str]):
        transport = TCPConnection(("", TCPPort(0)), (host, TCPPort(port)))
        connect_timeout = timeout if timeout is not None else self.config.connect_timeout

        try:
            await transport.connect(connect_timeout)

            if secure:
                context = TLSContext(self.credentials(host), server=False, alpn=alpn)
                transport = await TLSConnection.connect(transport, hostname=host, timeout=connect_timeout, context=context)

        except (TCPError, TLSError) as e:
            await transport.close()

            if isinstance(e, TLSError):
                raise

            raise HTTPError(502, f"Could not connect to {host}:{port}: {e}")

        return transport

    def hold(self, host: str, port: int, secure: bool, transport):
        self.held = getattr(self, "held", {})
        self.held[(host, port, secure)] = transport

    async def connect(self, host: str, port: int, secure: bool, timeout: Optional[float]) -> H1Connection:
        transport = getattr(self, "held", {}).pop((host, port, secure), None) if hasattr(self, "held") else None

        if transport is None or transport.closed:
            transport = await self.open(host, port, secure, timeout, alpn=["http/1.1"] if secure else [])

        version = "HTTP/1.1" if "HTTP/1.1" in self.config.versions else "HTTP/1.0"

        src = ("", HTTPPort("tcp", TCPPort(0), secure))
        dst = (host, HTTPPort("tcp", TCPPort(port), secure))

        connection = H1Connection(src, dst, transport=transport, role=HTTPBroadRole.CLIENT, version=version, limits=self.config.limits, observer=lambda message: self.notice(host, secure, message))
        self.connections.append(connection)

        return connection

    async def get(self, url, *, headers=None, cookies=None, timeout=None) -> HTTPConnection:
        return await self.request("GET", url, headers=headers, cookies=cookies, timeout=timeout)

    async def head(self, url, *, headers=None, cookies=None, timeout=None) -> HTTPConnection:
        return await self.request("HEAD", url, headers=headers, cookies=cookies, timeout=timeout)

    async def post(self, url, *, headers=None, cookies=None, body=None, timeout=None) -> HTTPConnection:
        return await self.request("POST", url, headers=headers, cookies=cookies, body=body, timeout=timeout)

    async def put(self, url, *, headers=None, cookies=None, body=None, timeout=None) -> HTTPConnection:
        return await self.request("PUT", url, headers=headers, cookies=cookies, body=body, timeout=timeout)

    async def delete(self, url, *, headers=None, cookies=None, timeout=None) -> HTTPConnection:
        return await self.request("DELETE", url, headers=headers, cookies=cookies, timeout=timeout)

    async def options(self, url, *, headers=None, cookies=None, timeout=None) -> HTTPConnection:
        return await self.request("OPTIONS", url, headers=headers, cookies=cookies, timeout=timeout)

    async def patch(self, url, *, headers=None, cookies=None, body=None, timeout=None) -> HTTPConnection:
        return await self.request("PATCH", url, headers=headers, cookies=cookies, body=body, timeout=timeout)

    async def websocket(self, url, *, headers=None, cookies=None, timeout=None, subprotocols=None) -> WSConnection:
        import os
        from base64 import b64encode

        url = self.upgrade(URL.parse(url) if isinstance(url, str) else url)
        secure = url.scheme in ("wss", "https")
        host = url.host
        port = url.port or (443 if secure else 80)

        transport = await self.open(host, port, secure, timeout, alpn=["http/1.1"] if secure else [])
        key = b64encode(os.urandom(16)).decode()

        block = HTTPHeaders(headers or [])
        block.set("Host", url.netloc or host)
        block.set("Upgrade", "websocket")
        block.set("Connection", "Upgrade")
        block.set("Sec-WebSocket-Key", key)
        block.set("Sec-WebSocket-Version", "13")

        if subprotocols:
            block.set("Sec-WebSocket-Protocol", ", ".join(subprotocols))

        self.cookie(HTTPRequest(headers=block), cookies)

        line = f"GET {self.target(url)} HTTP/1.1\r\n".encode("latin-1")

        try:
            await transport.send(line + block.build().encode("latin-1") + b"\r\n")
            status, response = await self.handshake(transport)

        except (TCPError, TLSError) as e:
            await transport.close()
            raise HTTPError(502, f"The WebSocket handshake failed: {e}")

        from ..websocket import WSFrame

        try:
            self.validate(status, response, key, subprotocols)

        except HTTPError:
            await transport.close()
            raise

        return WSConnection(("", None), (host, None), transport=transport, server=False, subprotocol=response.get("sec-websocket-protocol"))

    def validate(self, status: int, response: HTTPHeaders, key: str, subprotocols) -> None:
        from ..websocket import WSFrame

        if status != 101:
            raise HTTPError(502, f"The server did not switch protocols (status {status}).")

        if response.get("upgrade", "").strip().lower() != "websocket":
            raise HTTPError(502, "The server handshake carries no Upgrade: websocket.")

        if not any(token.lower() == "upgrade" for token in CommaHeader(response.get("connection", "")).raw):
            raise HTTPError(502, "The server handshake carries no Connection: Upgrade.")

        if response.get("sec-websocket-accept") != WSFrame.accept(key):
            raise HTTPError(502, "The server handshake carries a wrong Sec-WebSocket-Accept.")

        if any(CommaHeader(value).raw for value in response.values("sec-websocket-extensions")):
            raise HTTPError(502, "The server selected a WebSocket extension that was never offered.")

        chosen = response.values("sec-websocket-protocol")
        offered = {name.strip().lower() for name in (subprotocols or [])}

        if len(chosen) > 1 or (chosen and chosen[0].strip().lower() not in offered):
            raise HTTPError(502, "The server selected a WebSocket subprotocol that was never offered.")

    async def handshake(self, transport) -> Tuple[int, HTTPHeaders]:
        line = await transport.receive_until(b"\r\n", limit=8192)
        parts = line[:-2].decode("latin-1").split(" ", 2)
        status = (Digits.decimal(parts[1], width=3) if len(parts) >= 2 else None) or 0

        block = bytearray()

        while True:
            field = await transport.receive_until(b"\r\n", limit=65536)

            if field == b"\r\n":
                break

            block += field

        return (status, HTTPHeaders.parse(bytes(block), "HTTP/1.1"))

    async def close(self):
        connections, self.connections = self.connections, []

        for connection in connections:
            await connection.close()

        sessions, self.sessions = self.sessions, {}

        for session, pump in sessions.values():
            pump.cancel()
            await session.shutdown()

        tunnels, self.tunnels = self.tunnels, {}

        for client, session, reader in tunnels.values():
            reader.cancel()
            await session.shutdown()
            await client.close()

        for transport in getattr(self, "held", {}).values():
            await transport.close()

        self.held = {}
