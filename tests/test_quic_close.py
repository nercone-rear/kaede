import asyncio
from ssl import CERT_NONE

import pytest

from kaede.tls import TLSConfig
from kaede.udp.models import UDPPort
from kaede.udp.protocol import UDPConnection
from kaede.quic.tls import QTLS, QUICContext
from kaede.quic.protocol import QUICEndpoint, QUICConnection
from kaede.quic.errors import QUICError, QUICClosedError, QUICLostError

LOCAL = "127.0.0.1"

# RFC 9000 section 10.2 closes a connection immediately by sending
# CONNECTION_CLOSE, which states why. Section 20 keeps the transport's error
# codes apart from the application's, and section 20.2 leaves the application
# space to whatever is running on top, so HTTP/3 can pass its own codes through
# untouched. What matters here is that the reason survives the trip.

@pytest.fixture(scope="module", autouse=True)
def servable():
    if not QTLS().servable:
        pytest.skip("a QUIC server needs OpenSSL 4.0 or newer")

class Pair:
    """A connected client and server, and the endpoints under them."""

    def __init__(self, certificate):
        self.certificate = certificate

        self.listener = None
        self.client = None
        self.server = None

    async def __aenter__(self) -> "Pair":
        certfile, keyfile = self.certificate

        context = QUICContext(TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE), server=True, alpn=["kaede/1"])
        self.listener = await QUICEndpoint.serve(context, (LOCAL, UDPPort(0)))

        transport = UDPConnection(("", UDPPort(0)), (LOCAL, self.listener.src[1]))
        await transport.connect(10)

        self.client = await QUICConnection.connect(transport, TLSConfig(verify_mode=CERT_NONE), hostname="localhost", alpn=["kaede/1"], timeout=10)
        self.server = await self.listener.accept(timeout=10)

        await self.server.handshake(10)

        return self

    async def __aexit__(self, *_):
        if self.client is not None:
            await self.client.endpoint.close()

        await self.listener.close()

async def exchange(pair):
    """Carry a byte over a stream before anything else happens.

    OpenSSL 3.6 and 4.0 both only register a peer's CONNECTION_CLOSE on a
    connection that has already carried application data; on one that has
    handshaked and done nothing else the close is discarded and the connection
    is left to its idle timeout instead. That is the library's behaviour rather
    than Kaede's, and it is the same over a socket OpenSSL owns itself, so the
    closing tests put a connection into the state real ones are always in."""

    stream = await pair.client.open()
    await stream.send(b"x")

    accepted = await pair.server.accept(timeout=10)
    await accepted.receive(1, timeout=10)

    return stream, accepted

async def settle(connection, rounds: int = 200):
    """Let the pump run until the connection notices it has been closed."""

    for _ in range(rounds):
        connection.status()

        if connection.error is not None:
            return connection.error

        await asyncio.sleep(0.01)

    return None

class TestClosing:
    async def test_the_peer_learns_the_application_error_code(self, server_certificate):
        # RFC 9000 section 20.2: the code belongs to whatever runs on top, so it
        # has to arrive exactly as it was given rather than being remapped.
        async with Pair(server_certificate) as pair:
            await exchange(pair)

            await pair.client.close(0x100, "done")

            error = await settle(pair.server)

            assert error is not None
            assert "0x100" in str(error)

    async def test_the_peer_learns_the_reason(self, server_certificate):
        async with Pair(server_certificate) as pair:
            await exchange(pair)

            await pair.client.close(0x10f, "going away")

            error = await settle(pair.server)

            assert error is not None
            assert "going away" in str(error)

    async def test_an_application_close_is_not_a_transport_error(self, server_certificate):
        # RFC 9000 section 20 keeps the two spaces apart, and confusing them
        # would have the peer read an application code off the transport table.
        async with Pair(server_certificate) as pair:
            await exchange(pair)

            await pair.client.close(0x100, "done")

            error = await settle(pair.server)

            assert isinstance(error, QUICClosedError)
            assert not isinstance(error, QUICLostError)

    async def test_the_closing_side_records_it_too(self, server_certificate):
        async with Pair(server_certificate) as pair:
            await pair.client.close(0x100, "done")

            assert pair.client.closed

    async def test_closing_twice_is_harmless(self, server_certificate):
        async with Pair(server_certificate) as pair:
            await pair.client.close(0x100, "done")
            await pair.client.close(0x100, "done")

            assert pair.client.closed

    async def test_a_default_close_carries_no_error(self, server_certificate):
        async with Pair(server_certificate) as pair:
            await exchange(pair)

            await pair.client.close()

            error = await settle(pair.server)

            assert error is not None
            assert "0x0" in str(error)

    async def test_streams_cannot_be_opened_afterwards(self, server_certificate):
        async with Pair(server_certificate) as pair:
            await pair.client.close(timeout=0.5)

            with pytest.raises(QUICError):
                await pair.client.open(timeout=2)

    async def test_a_waiting_stream_is_woken_by_the_close(self, server_certificate):
        # A reader parked on a stream must not wait out its own timeout when the
        # connection under it has gone.
        async with Pair(server_certificate) as pair:
            stream = await pair.client.open()
            await stream.send(b"x")

            accepted = await pair.server.accept(timeout=10)
            await accepted.receive(1, timeout=10)

            await pair.client.close(0x100, "done")

            with pytest.raises(QUICError):
                await accepted.receive(timeout=10)

    async def test_closing_an_unfinished_connection_is_harmless(self, server_certificate):
        # Nothing was ever established here, so there is no peer to tell.
        context = QUICContext(TLSConfig(verify_mode=CERT_NONE), alpn=["kaede/1"])
        endpoint = QUICEndpoint(context)

        transport = UDPConnection(("", UDPPort(0)), (LOCAL, UDPPort(9)))
        await transport.connect(5)

        endpoint.adopt(transport)
        connection = endpoint.open(hostname="localhost")

        await connection.close(timeout=0.2)

        assert connection.closed

        await endpoint.close()
