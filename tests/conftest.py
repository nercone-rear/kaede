"""
Shared test fixtures, including an in-process QUIC loopback harness.

The harness wires a client and server QUICConnection together over a virtual
network (no sockets), driving the real OpenSSL QUIC-TLS handshake to completion
so that transport behavior (streams, flow control, key update, ...) can be
exercised end to end. Requires an OpenSSL with the QUIC-TLS API (3.5+); tests
that use it are skipped automatically when that is unavailable.
"""
from __future__ import annotations

import ssl
import asyncio
import datetime
import tempfile
import ipaddress

import pytest

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

@pytest.fixture(scope="session")
def tls_cert() -> tuple[str, str]:
    """Generate a self-signed localhost certificate; returns (certfile, keyfile)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    not_before = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )

    certfile = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    certfile.write(cert.public_bytes(serialization.Encoding.PEM))
    certfile.close()

    keyfile = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    keyfile.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    keyfile.close()

    return certfile.name, keyfile.name

class QuicLoopback:
    """A connected client/server QUICConnection pair sharing a virtual network."""

    def __init__(self, certfile: str, keyfile: str, alpn: tuple[str, ...] = ("h3",)):
        from kaede.quic.tls import QuicTLS
        from kaede.quic.connection import QUICConnection
        from kaede.tls.models import TLSServerConfig, TLSClientConfig

        self.now = 0.0
        server_cfg = TLSServerConfig(certfile=certfile, keyfile=keyfile, verify_mode=ssl.CERT_NONE)
        client_cfg = TLSClientConfig(verify=False, check_hostname=False)

        self.client = QUICConnection.create_client(
            lambda tp: QuicTLS.for_client(client_cfg, "localhost", alpn=alpn, transport_params=tp), "localhost",
        )
        initial = self.client.datagrams_to_send(self.now)
        self.server = QUICConnection.create_server(
            initial[0][0], lambda tp: QuicTLS.for_server(server_cfg, alpn=alpn, transport_params=tp),
        )
        for datagram, _ in initial:
            self.server.receive_datagram(datagram, self.now)

    def _pump_once(self, src, dst) -> bool:
        moved = False
        for datagram, _ in src.datagrams_to_send(self.now):
            dst.receive_datagram(datagram, self.now)
            moved = True
        return moved

    def pump(self, max_rounds: int = 60) -> None:
        """Exchange datagrams in both directions until the network is quiescent."""
        for _ in range(max_rounds):
            moved = self._pump_once(self.server, self.client)
            moved = self._pump_once(self.client, self.server) or moved
            if not moved:
                return

    def handshake(self) -> bool:
        self.pump()
        return self.client.handshake_complete and self.server.handshake_complete

    def advance(self, dt: float = 0.001) -> None:
        self.now += dt

def _quic_tls_available() -> bool:
    try:
        from kaede.tls.openssl import OpenSSL
        OpenSSL.get()
        return True
    except Exception:
        return False

@pytest.fixture
def quic_pair(tls_cert):
    if not _quic_tls_available():
        pytest.skip("OpenSSL QUIC-TLS API (3.5+) not available")
    certfile, keyfile = tls_cert
    return QuicLoopback(certfile, keyfile)

# --------------------------------------------------------------------------
# HTTP/3 loopback harness
# --------------------------------------------------------------------------

class _FakeTransport:
    def __init__(self):
        self.queue: list[bytes] = []

    def sendto(self, data, addr=None):
        self.queue.append(bytes(data))

    def close(self):
        pass

    def is_closing(self):
        return False

class _FakeHandler:
    def __init__(self, config, callback):
        self.config = config
        self.callback = callback
        self.shutdown = False
        self.tasks: set = set()
        self.active_websockets: set = set()

    def create_task(self, coro):
        task = asyncio.ensure_future(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

class _FakeProtocol:
    def __init__(self, handler, transport):
        self.handler = handler
        self.transport = transport

    def _reap(self, addr):
        pass

class H3Loopback:
    """Two real H3Connections wired together via in-memory transports. Must be
    constructed inside a running event loop."""

    def __init__(self, certfile: str, keyfile: str, callback, server_config=None):
        from kaede.quic.tls import QuicTLS
        from kaede.quic.connection import QUICConnection
        from kaede.http.h3 import H3Connection
        from kaede.tls.models import TLSServerConfig, TLSClientConfig
        from kaede.api.server import Config

        server_config = server_config or Config()
        server_config.tls = TLSServerConfig(certfile=certfile, keyfile=keyfile, verify_mode=ssl.CERT_NONE)
        client_cfg = TLSClientConfig(verify=False, check_hostname=False)

        self.client_transport = _FakeTransport()
        self.server_transport = _FakeTransport()
        self.server_handler = _FakeHandler(server_config, callback)

        client_quic = QUICConnection.create_client(
            lambda tp: QuicTLS.for_client(client_cfg, "localhost", transport_params=tp), "localhost",
        )
        self.client_h3 = H3Connection(client_quic, _FakeProtocol(None, self.client_transport), is_client=True, authority="localhost")
        self.client_h3.flush()

        first = self.client_transport.queue.pop(0)
        server_quic = QUICConnection.create_server(first, lambda tp: QuicTLS.for_server(server_config.tls, transport_params=tp))
        self.server_h3 = H3Connection(server_quic, _FakeProtocol(self.server_handler, self.server_transport), is_client=False, addr=("127.0.0.1", 443))
        self.server_h3.receive_datagram(first)
        while self.client_transport.queue:
            self.server_h3.receive_datagram(self.client_transport.queue.pop(0))

    def _drain(self) -> bool:
        moved_any = False
        moved = True
        while moved:
            moved = False
            while self.client_transport.queue:
                self.server_h3.receive_datagram(self.client_transport.queue.pop(0))
                moved = moved_any = True
            while self.server_transport.queue:
                self.client_h3.receive_datagram(self.server_transport.queue.pop(0))
                moved = moved_any = True
        return moved_any

    async def _pump_until(self, done, max_iters: int = 400):
        for _ in range(max_iters):
            self._drain()
            if done():
                self._drain()
                return
            await asyncio.sleep(0)
        self._drain()
        if not done():
            raise TimeoutError("H3 loopback did not converge")

    async def handshake(self):
        await self._pump_until(lambda: self.client_h3.connected.done())

    async def drive(self, coro):
        """Run a client coroutine to completion while pumping the network."""
        task = asyncio.ensure_future(coro)
        await self._pump_until(lambda: task.done())
        return await task

    async def request(self, method: str, path: str, *, headers=None, body=None, streaming: bool = False):
        from kaede.models import Request, Headers

        hdrs = Headers(headers or {})
        request = Request(method=method, target=path, headers=hdrs, body=body, scheme="https", secure=True, protocol="HTTP/3.0")
        return await self.drive(self.client_h3.request(request, streaming))

    async def websocket(self, path: str = "/", subprotocols=None):
        from kaede.models import Request, Headers

        request = Request(method="GET", target=path, headers=Headers({}), scheme="https", secure=True, protocol="HTTP/3.0")
        return await self.drive(self.client_h3.open_websocket(request, subprotocols=subprotocols))

    def close(self):
        for conn in (self.client_h3, self.server_h3):
            if conn.timer is not None:
                conn.timer.cancel()
                conn.timer = None
        for task in list(self.server_handler.tasks):
            task.cancel()

@pytest.fixture
def h3_loopback(tls_cert):
    if not _quic_tls_available():
        pytest.skip("OpenSSL QUIC-TLS API (3.5+) not available")
    certfile, keyfile = tls_cert
    created: list[H3Loopback] = []

    def make(callback, server_config=None) -> H3Loopback:
        loopback = H3Loopback(certfile, keyfile, callback, server_config)
        created.append(loopback)
        return loopback

    yield make

    for loopback in created:
        loopback.close()
