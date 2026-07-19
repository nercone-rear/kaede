import asyncio
from ssl import CERT_NONE

import pytest

from kaede.tls import TLSConfig
from kaede.tls.errors import TLSConfigError
from kaede.udp.models import UDPPort
from kaede.quic import QUICClient, QUICClientConfig, QUICServer, QUICServerConfig, QUICServerLimits, QUICHandler
from kaede.quic.tls import QTLS
from kaede.quic.errors import QUICError, QUICTimeoutError

LOCAL = "127.0.0.1"

# The server API on top of the QUIC endpoint: one UDP socket carrying every
# peer, a handler per connection, and the same admission control the other
# protocols have. RFC 9000 section 5.1 routes packets by connection id rather
# than by address, which is why one socket can serve them all.

@pytest.fixture(scope="module", autouse=True)
def servable():
    if not QTLS().servable:
        pytest.skip("a QUIC server needs OpenSSL 4.0 or newer")

class Running:
    """A QUICServer on an ephemeral port."""

    def __init__(self, on_connection, certificate, *, alpn=None, idle_timeout=10, limits=None):
        certfile, keyfile = certificate

        config = QUICServerConfig(idle_timeout=idle_timeout)
        config.tls = TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE)
        config.alpn = ["kaede/1"] if alpn is None else alpn
        config.handshake_timeout = 10

        if limits is not None:
            config.limits = limits

        self.server = QUICServer(config)
        self.handler = QUICHandler(on_connection)

    async def __aenter__(self) -> QUICServer:
        await self.server.listen(self.handler, [(LOCAL, UDPPort(0))])
        return self.server

    async def __aexit__(self, *_):
        await self.server.close(timeout=3)

def client(server, authority, *, alpn=None, hostname="localhost", verify=True, timeout=10):
    config = QUICClientConfig(connect_timeout=timeout)
    config.tls = TLSConfig(cafile=authority.ca) if verify else TLSConfig(verify_mode=CERT_NONE)
    config.alpn = ["kaede/1"] if alpn is None else alpn
    config.hostname = hostname

    return QUICClient(server.ports[0], config=config)

async def upper(connection):
    """Answer every stream with what it sent, in upper case."""

    while True:
        stream = await connection.accept()
        data = await stream.receive()

        await stream.send(data.upper())
        stream.conclude()

class TestRoundTrip:
    async def test_sends_and_receives_over_a_stream(self, server_certificate, authority):
        async with Running(upper, server_certificate) as server:
            async with client(server, authority) as connection:
                stream = await connection.open()

                await stream.send(b"hello")
                stream.conclude()

                assert await stream.receive(timeout=10) == b"HELLO"

    async def test_carries_several_streams_on_one_connection(self, server_certificate, authority):
        # RFC 9000 section 2: a connection multiplexes streams, so these are
        # answered without any of them waiting on the others.
        async with Running(upper, server_certificate) as server:
            async with client(server, authority) as connection:
                streams = []

                for word in (b"one", b"two", b"three"):
                    stream = await connection.open()
                    await stream.send(word)
                    stream.conclude()
                    streams.append(stream)

                answers = [await stream.receive(timeout=10) for stream in streams]

                assert answers == [b"ONE", b"TWO", b"THREE"]

    async def test_reports_the_negotiated_parameters(self, server_certificate, authority):
        async with Running(upper, server_certificate) as server:
            async with client(server, authority) as connection:
                assert connection.version == "QUICv1"
                assert connection.cipher.startswith("TLS_") # RFC 9001 section 4.2
                assert connection.protocol == "kaede/1"
                assert connection.verified

    async def test_the_handler_sees_the_client_address(self, server_certificate, authority):
        seen = []

        async def note(connection):
            seen.append(connection.dst)

            stream = await connection.accept()
            await stream.receive()
            await stream.send(b"ok")
            stream.conclude()

        async with Running(note, server_certificate) as server:
            async with client(server, authority) as connection:
                stream = await connection.open()
                await stream.send(b"x")
                stream.conclude()

                await stream.receive(timeout=10)

        assert seen and seen[0][0] == LOCAL

    async def test_serves_several_clients_on_one_socket(self, server_certificate, authority):
        # One UDP port carries every peer, because RFC 9000 section 5.1 sorts
        # them by connection id rather than by the address they came from.
        async with Running(upper, server_certificate) as server:
            first, second = client(server, authority), client(server, authority)

            async with first as one, second as two:
                assert one.src[1] != two.src[1]

                for connection, word, answer in ((one, b"first", b"FIRST"), (two, b"second", b"SECOND")):
                    stream = await connection.open()
                    await stream.send(word)
                    stream.conclude()

                    assert await stream.receive(timeout=10) == answer

    async def test_carries_a_large_payload(self, server_certificate, authority):
        payload = bytes(range(256)) * 200 # 50 KiB

        async def echo(connection):
            stream = await connection.accept()
            data = await stream.receive()

            await stream.send(data)
            stream.conclude()

        async with Running(echo, server_certificate) as server:
            async with client(server, authority) as connection:
                stream = await connection.open()

                async def feed():
                    await stream.send(payload)
                    stream.conclude()

                sender = asyncio.ensure_future(feed())
                received = await stream.receive(timeout=20)
                await sender

                assert received == payload

class TestPorts:
    async def test_reports_the_port_it_bound(self, server_certificate):
        async with Running(upper, server_certificate) as server:
            assert len(server.ports) == 1
            assert server.ports[0][0] == LOCAL
            assert server.ports[0][1] != 0

    async def test_binds_several_ports(self, server_certificate):
        certfile, keyfile = server_certificate

        config = QUICServerConfig()
        config.tls = TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE)
        config.alpn = ["kaede/1"]

        server = QUICServer(config)

        try:
            await server.listen(QUICHandler(upper), [(LOCAL, UDPPort(0)), (LOCAL, UDPPort(0))])

            assert len(server.ports) == 2
            assert server.ports[0][1] != server.ports[1][1]

        finally:
            await server.close(timeout=3)

class TestAdmission:
    async def test_a_refused_connection_is_not_served(self, server_certificate, authority):
        # With no room at all the gate turns the peer away, so the handler never
        # runs. RFC 9000 section 10.2: the refusal is said rather than implied,
        # so the client learns of it now instead of waiting out its own timeout.
        from kaede.quic.api.server import QUICServerLimits

        limits = QUICServerLimits()
        limits.max_connection_nums = 0

        served = []

        async def note(connection):
            served.append(connection)

        async with Running(note, server_certificate, limits=limits) as server:
            connection = client(server, authority, timeout=10)

            with pytest.raises((QUICError, OSError)):
                async with connection:
                    pass

            assert served == []

    async def test_a_refusal_is_reported_rather_than_left_to_time_out(self, server_certificate, authority):
        from kaede.quic.api.server import QUICServerLimits

        limits = QUICServerLimits()
        limits.max_connection_nums = 0

        async with Running(upper, server_certificate, limits=limits) as server:
            started = asyncio.get_running_loop().time()

            with pytest.raises((QUICError, OSError)):
                async with client(server, authority, timeout=10):
                    pass

            # A silent drop would have cost the whole ten seconds.
            assert asyncio.get_running_loop().time() - started < 5

    async def test_the_gate_releases_when_a_connection_ends(self, server_certificate, authority):
        async def brief(connection):
            stream = await connection.accept()
            await stream.receive()
            await stream.send(b"bye")
            stream.conclude()

        async with Running(brief, server_certificate) as server:
            async with client(server, authority) as connection:
                stream = await connection.open()
                await stream.send(b"x")
                stream.conclude()

                assert await stream.receive(timeout=10) == b"bye"

            # The handler has finished, so the slot it held has to come back.
            for _ in range(100):
                if server.gate.connections == 0:
                    break

                await asyncio.sleep(0.05)

            assert server.gate.connections == 0

class TestShutdown:
    async def test_closing_leaves_nothing_running(self, server_certificate, authority):
        async with Running(upper, server_certificate) as server:
            async with client(server, authority) as connection:
                stream = await connection.open()
                await stream.send(b"x")
                stream.conclude()

                await stream.receive(timeout=10)

            await server.close(timeout=3)

            assert server.endpoints == []
            assert server.connections == set()
            assert not [task for task in server.tasks if not task.done()]

    async def test_closing_twice_is_harmless(self, server_certificate):
        async with Running(upper, server_certificate) as server:
            await server.close(timeout=3)
            await server.close(timeout=3)

class TestConfiguration:
    def test_a_server_needs_alpn(self):
        # RFC 9001 section 8.1 makes ALPN mandatory, and a server with none
        # could never agree on anything.
        config = QUICServerConfig()
        config.tls = TLSConfig(verify_mode=CERT_NONE)

        with pytest.raises(TLSConfigError):
            QUICServer(config)

    def test_the_idle_timeout_is_kaede_s_own(self):
        # RFC 9000 section 10.1's max_idle_timeout is a transport parameter that
        # OpenSSL owns. This one is the server's own reaping on top of it, so it
        # has a plain default rather than trying to mirror the transport's.
        assert QUICServerConfig().idle_timeout == 30.0

    def test_address_validation_is_on_by_default(self):
        # RFC 9000 section 8.1: making a peer prove its address before serving
        # it is what keeps the server from amplifying a forged one.
        assert QUICServerConfig().validate is True

async def hold(connection):
    """Accept every stream, echo one message, and keep the stream open (never conclude it),
    so each stays counted against the per-connection concurrent limit."""
    kept = []

    while True:
        stream = await connection.accept()
        kept.append(stream)

        data = await stream.receive(timeout=10)
        await stream.send(data)

class TestStreamLimit:
    async def test_admits_streams_up_to_the_cap(self, server_certificate, authority):
        # RFC 9000 section 4.6: a connection caps the number of concurrent peer-opened streams.
        async with Running(hold, server_certificate, limits=QUICServerLimits(max_stream_nums=2)) as server:
            async with client(server, authority) as connection:
                for _ in range(2):
                    stream = await connection.open()
                    await stream.send(b"x")
                    stream.conclude()

                    assert await stream.receive(timeout=10) == b"x"

    async def test_refuses_a_stream_past_the_cap(self, server_certificate, authority):
        # The third concurrent stream is over the cap of two, so the server resets it rather than serving it.
        async with Running(hold, server_certificate, limits=QUICServerLimits(max_stream_nums=2)) as server:
            async with client(server, authority) as connection:
                live = []

                for _ in range(2):
                    stream = await connection.open()
                    await stream.send(b"x")
                    stream.conclude()

                    assert await stream.receive(timeout=10) == b"x"
                    live.append(stream)

                extra = await connection.open()
                await extra.send(b"x")
                extra.conclude()

                with pytest.raises(QUICError):
                    await extra.receive(timeout=10)
