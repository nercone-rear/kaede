import gc
import asyncio
from ssl import CERT_NONE

import pytest

from kaede.tls import TLSConfig
from kaede.udp.models import UDPPort
from kaede.udp.protocol import UDPConnection
from kaede.quic.tls import QTLS, QUICPair, QUICContext
from kaede.quic.protocol import QUICEndpoint, QUICConnection
from kaede.quic.errors import QUICError, QUICClosedError

LOCAL = "127.0.0.1"

# Everything here is about not crashing. The objects form a tree of raw OpenSSL
# pointers with a reference cycle in it (a connection holds its streams and each
# stream holds its connection), and a timer that can fire at any moment and walk
# the whole thing. Freeing in the wrong order, or twice, or leaving the timer
# armed, is a segmentation fault rather than an exception, so each of those is
# provoked deliberately.

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
        if self.client is not None and self.client.endpoint.pair is not None:
            await self.client.endpoint.close()

        if self.listener.pair is not None:
            await self.listener.close()

class TestRepeatedFreeing:
    async def test_an_endpoint_frees_twice(self, server_certificate):
        async with Pair(server_certificate) as pair:
            endpoint = pair.client.endpoint

            endpoint.free()
            endpoint.free()

            assert endpoint.pointer is None
            assert endpoint.pair is None

    async def test_a_connection_frees_twice(self, server_certificate):
        async with Pair(server_certificate) as pair:
            pair.client.free()
            pair.client.free()

            assert pair.client.pointer is None

    async def test_a_stream_frees_twice(self, server_certificate):
        async with Pair(server_certificate) as pair:
            stream = await pair.client.open()

            stream.free()
            stream.free()

            assert stream.pointer is None

    async def test_a_pair_frees_twice(self, server_certificate):
        qtls = QTLS()
        pair = QUICPair(qtls)

        pair.free()
        pair.free()

        assert pair.inner is None and pair.outer is None

class TestOrder:
    async def test_freeing_a_connection_takes_its_streams_with_it(self, server_certificate):
        # The connection must not go before the streams that point into it.
        async with Pair(server_certificate) as pair:
            streams = [await pair.client.open() for _ in range(3)]

            pair.client.free()

            assert all(stream.pointer is None for stream in streams)
            assert pair.client.streams == {}

    async def test_a_held_stream_survives_its_connection_being_freed(self, server_certificate):
        # Holding a reference to a stream whose connection has gone must give an
        # exception rather than a walk into freed memory.
        async with Pair(server_certificate) as pair:
            stream = await pair.client.open()

            pair.client.free()

            with pytest.raises(QUICClosedError):
                await stream.send(b"x")

    async def test_freeing_an_endpoint_takes_its_connections_with_it(self, server_certificate):
        async with Pair(server_certificate) as pair:
            endpoint, connection = pair.client.endpoint, pair.client
            stream = await connection.open()

            endpoint.free()

            assert connection.pointer is None
            assert stream.pointer is None

    async def test_a_client_root_is_freed_exactly_once(self, server_certificate):
        # A client's endpoint and its connection are the same OpenSSL object, so
        # the endpoint must leave the freeing to the connection.
        async with Pair(server_certificate) as pair:
            endpoint, connection = pair.client.endpoint, pair.client

            assert endpoint.pointer == connection.pointer
            assert endpoint.owned is False

            endpoint.free()

            assert endpoint.pointer is None

    async def test_a_server_root_is_owned_by_the_endpoint(self, server_certificate):
        # A listener has no connection object over it, so the endpoint does own
        # that one.
        async with Pair(server_certificate) as pair:
            assert pair.listener.owned is True

class TestTimer:
    async def test_freeing_takes_the_timer_down(self, server_certificate):
        async with Pair(server_certificate) as pair:
            endpoint = pair.client.endpoint

            assert endpoint.timer is not None

            endpoint.free()

            assert endpoint.timer is None

    async def test_nothing_fires_after_freeing(self, server_certificate):
        # A timer left armed would call wake() on pointers that are gone.
        async with Pair(server_certificate) as pair:
            endpoint = pair.client.endpoint

            endpoint.free()

            # Well past any deadline QUIC would have set for itself.
            await asyncio.sleep(0.3)

            assert endpoint.pointer is None

    async def test_waking_a_freed_endpoint_does_nothing(self, server_certificate):
        # The pump is reachable from a timer and from the socket, so it has to
        # refuse to run rather than trusting that neither will call it.
        async with Pair(server_certificate) as pair:
            endpoint = pair.client.endpoint

            endpoint.free()
            endpoint.wake()

            assert endpoint.pointer is None

    async def test_feeding_a_freed_endpoint_does_nothing(self, server_certificate):
        async with Pair(server_certificate) as pair:
            endpoint = pair.client.endpoint

            endpoint.free()
            endpoint.feed(b"rubbish", (LOCAL, UDPPort(1)))

            assert endpoint.pointer is None

class TestCollection:
    async def test_a_dropped_tree_is_collected(self, server_certificate):
        # A connection and its streams reference one another, so the cycle
        # collector is what takes them, and it runs __del__ in whatever order it
        # likes. Nothing may crash on the way out.
        async with Pair(server_certificate) as pair:
            connection = pair.client
            endpoint = connection.endpoint

            for _ in range(3):
                await connection.open()

            await endpoint.close()

        gc.collect()
        gc.collect()

        await asyncio.sleep(0)

    async def test_an_unused_endpoint_is_collected(self, server_certificate):
        # One that never got as far as a socket still holds a BIO pair and two
        # addresses.
        context = QUICContext(TLSConfig(verify_mode=CERT_NONE), alpn=["kaede/1"])

        for _ in range(5):
            QUICEndpoint(context)

        gc.collect()
        gc.collect()

    async def test_an_endpoint_that_failed_to_connect_is_collected(self, server_certificate):
        context = QUICContext(TLSConfig(verify_mode=CERT_NONE), alpn=["kaede/1"])

        transport = UDPConnection(("", UDPPort(0)), (LOCAL, UDPPort(9)))
        await transport.connect(5)

        endpoint = QUICEndpoint(context)
        endpoint.adopt(transport)
        endpoint.open(hostname="localhost")

        endpoint.free()
        await transport.close()

        del endpoint
        gc.collect()

class TestSockets:
    async def test_closing_releases_the_socket(self, server_certificate):
        async with Pair(server_certificate) as pair:
            endpoint = pair.client.endpoint
            socket = endpoint.socket

            await endpoint.close()

            assert socket.closed
            assert endpoint.socket is None

    async def test_the_reader_stops_with_the_endpoint(self, server_certificate):
        async with Pair(server_certificate) as pair:
            endpoint = pair.client.endpoint
            reader = endpoint.reader

            assert reader is not None

            await endpoint.close()
            await asyncio.sleep(0)

            assert reader.cancelled() or reader.done()
