import asyncio
from ssl import CERT_NONE

import pytest

from kaede.tls import TLSConfig
from kaede.udp.models import UDPPort
from kaede.udp.protocol import UDPConnection
from kaede.quic.models import QUICStreamID
from kaede.quic.tls import QTLS, QUICContext
from kaede.quic.protocol import QUICEndpoint, QUICConnection
from kaede.quic.errors import QUICClosedError, QUICStreamError

LOCAL = "127.0.0.1"

# RFC 9000 section 2 gives a connection any number of independent streams, each
# of which is an ordered byte stream rather than a run of messages. Both halves
# of that matter and both are checked here: bytes written separately may arrive
# joined, and two streams must not disturb one another. Section 2.4 ends a
# stream with a FIN and section 19.4 abandons one with a reset, which the
# receiving side has to be able to tell apart.

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

class TestIdentifiers:
    async def test_a_client_bidirectional_stream_is_numbered_for_one(self, server_certificate):
        # RFC 9000 section 2.1, table 1: 0x00 is client initiated bidirectional.
        async with Pair(server_certificate) as pair:
            stream = await pair.client.open()

            assert stream.id.client
            assert stream.id.bidirectional
            assert int(stream.id) % 4 == 0

    async def test_a_client_unidirectional_stream_is_numbered_for_one(self, server_certificate):
        # RFC 9000 section 2.1, table 1: 0x02 is client initiated unidirectional.
        async with Pair(server_certificate) as pair:
            stream = await pair.client.open(unidirectional=True)

            assert stream.id.client
            assert stream.id.unidirectional
            assert int(stream.id) % 4 == 2

    async def test_a_server_bidirectional_stream_is_numbered_for_one(self, server_certificate):
        # RFC 9000 section 2.1, table 1: 0x01 is server initiated bidirectional.
        async with Pair(server_certificate) as pair:
            stream = await pair.server.open()

            assert stream.id.server
            assert stream.id.bidirectional
            assert int(stream.id) % 4 == 1

    async def test_a_server_unidirectional_stream_is_numbered_for_one(self, server_certificate):
        # RFC 9000 section 2.1, table 1: 0x03 is server initiated unidirectional.
        async with Pair(server_certificate) as pair:
            stream = await pair.server.open(unidirectional=True)

            assert stream.id.server
            assert stream.id.unidirectional
            assert int(stream.id) % 4 == 3

    async def test_the_first_stream_of_a_type_is_the_zeroth(self, server_certificate):
        async with Pair(server_certificate) as pair:
            assert (await pair.client.open()).id.ordinal == 0

    async def test_ordinals_count_up_within_a_type(self, server_certificate):
        # RFC 9000 section 2.1 numbers each type separately and in order.
        async with Pair(server_certificate) as pair:
            opened = [await pair.client.open() for _ in range(3)]

            assert [stream.id.ordinal for stream in opened] == [0, 1, 2]

    async def test_the_two_directions_are_numbered_apart(self, server_certificate):
        async with Pair(server_certificate) as pair:
            first = await pair.client.open()
            second = await pair.client.open(unidirectional=True)

            assert first.id.ordinal == second.id.ordinal == 0
            assert int(first.id) != int(second.id)

    async def test_the_peer_sees_the_same_identifier(self, server_certificate):
        async with Pair(server_certificate) as pair:
            stream = await pair.client.open()
            await stream.send(b"ping")

            accepted = await pair.server.accept(timeout=10)

            assert int(accepted.id) == int(stream.id)
            assert accepted.id.client

class TestByteStream:
    async def test_carries_data_from_client_to_server(self, server_certificate):
        async with Pair(server_certificate) as pair:
            stream = await pair.client.open()
            await stream.send(b"ping")

            accepted = await pair.server.accept(timeout=10)

            assert await accepted.receive(4, timeout=10) == b"ping"

    async def test_carries_data_back_the_other_way(self, server_certificate):
        # A bidirectional stream runs both ways, so the answer comes back on the
        # same stream rather than on a new one.
        async with Pair(server_certificate) as pair:
            stream = await pair.client.open()
            await stream.send(b"ping")

            accepted = await pair.server.accept(timeout=10)
            assert await accepted.receive(4, timeout=10) == b"ping"

            await accepted.send(b"pong")
            assert await stream.receive(4, timeout=10) == b"pong"

    async def test_reads_cross_the_boundaries_between_writes(self, server_certificate):
        # RFC 9000 section 2.2: a stream is an ordered byte stream, so it keeps
        # the order but not the boundaries. Asking for four bytes has to return
        # the whole of "one" and the first byte of "two", which is only possible
        # if no boundary survived. This is exactly the property DTLS does not
        # have, where each write is its own record in its own datagram.
        async with Pair(server_certificate) as pair:
            stream = await pair.client.open()

            await stream.send(b"one")
            await stream.send(b"two")
            await stream.send(b"three")
            stream.conclude()

            accepted = await pair.server.accept(timeout=10)

            assert await accepted.receive_exactly(4, timeout=10) == b"onet"
            assert await accepted.receive_exactly(4, timeout=10) == b"woth"
            assert await accepted.receive(timeout=10) == b"ree"

    async def test_the_order_is_kept(self, server_certificate):
        async with Pair(server_certificate) as pair:
            stream = await pair.client.open()

            for number in range(20):
                await stream.send(f"{number:03d}".encode())

            stream.conclude()

            accepted = await pair.server.accept(timeout=10)
            received = await accepted.receive(timeout=10)

            assert received == b"".join(f"{number:03d}".encode() for number in range(20))

    async def test_receive_exactly_waits_for_the_whole_amount(self, server_certificate):
        async with Pair(server_certificate) as pair:
            stream = await pair.client.open()
            await stream.send(b"12345678")

            accepted = await pair.server.accept(timeout=10)

            assert await accepted.receive_exactly(3, timeout=10) == b"123"
            assert await accepted.receive_exactly(5, timeout=10) == b"45678"

    async def test_carries_a_payload_larger_than_a_datagram(self, server_certificate):
        # A stream is not bounded by the path MTU the way a DTLS record is, so
        # this has to be split, carried and put back together underneath.
        payload = bytes(range(256)) * 400 # 100 KiB

        async with Pair(server_certificate) as pair:
            stream = await pair.client.open()
            accepted = None

            async def feed():
                await stream.send(payload)
                stream.conclude()

            sender = asyncio.ensure_future(feed())

            accepted = await pair.server.accept(timeout=10)
            received = await accepted.receive(timeout=20)

            await sender

            assert received == payload

class TestIndependence:
    async def test_two_streams_do_not_disturb_one_another(self, server_certificate):
        # RFC 9000 section 2.1: streams are independent, so interleaving writes
        # across them must not mix their contents.
        async with Pair(server_certificate) as pair:
            first = await pair.client.open()
            second = await pair.client.open()

            await first.send(b"aaa")
            await second.send(b"bbb")
            await first.send(b"AAA")
            await second.send(b"BBB")

            first.conclude()
            second.conclude()

            accepted = [await pair.server.accept(timeout=10), await pair.server.accept(timeout=10)]
            byid = {int(stream.id): stream for stream in accepted}

            assert await byid[int(first.id)].receive(timeout=10) == b"aaaAAA"
            assert await byid[int(second.id)].receive(timeout=10) == b"bbbBBB"

    async def test_streams_arrive_in_the_order_they_were_opened(self, server_certificate):
        async with Pair(server_certificate) as pair:
            opened = []

            for _ in range(3):
                stream = await pair.client.open()
                await stream.send(b"x")
                opened.append(int(stream.id))

            accepted = [int((await pair.server.accept(timeout=10)).id) for _ in range(3)]

            assert accepted == opened

class TestEnding:
    async def test_a_concluded_stream_reads_as_ended(self, server_certificate):
        # RFC 9000 section 2.4: a FIN says there is nothing more, as against
        # merely nothing yet.
        async with Pair(server_certificate) as pair:
            stream = await pair.client.open()
            await stream.send(b"done")
            stream.conclude()

            accepted = await pair.server.accept(timeout=10)

            assert await accepted.receive(timeout=10) == b"done"
            assert await accepted.receive(timeout=10) == b""
            assert accepted.finished

    async def test_a_fin_ends_only_the_one_direction(self, server_certificate):
        # RFC 9000 section 2.4 ends the sending part. The other half of a
        # bidirectional stream is untouched and still carries data.
        async with Pair(server_certificate) as pair:
            stream = await pair.client.open()
            await stream.send(b"ask")
            stream.conclude()

            accepted = await pair.server.accept(timeout=10)

            assert await accepted.receive(timeout=10) == b"ask"
            assert await accepted.receive(timeout=10) == b""

            await accepted.send(b"answer")

            assert await stream.receive(6, timeout=10) == b"answer"

    async def test_sending_after_concluding_is_refused(self, server_certificate):
        # RFC 9000 section 3.1: once the sending part has finished there is no
        # way back to sending.
        async with Pair(server_certificate) as pair:
            stream = await pair.client.open()
            stream.conclude()

            with pytest.raises(QUICClosedError):
                await stream.send(b"more")

    async def test_what_already_arrived_survives_an_abrupt_end(self, server_certificate):
        # Reading to the end of a stream that is cut off rather than finished
        # still has to hand over what did arrive. Discarding it because the
        # failure came afterwards loses data the peer successfully sent.
        async with Pair(server_certificate) as pair:
            stream = await pair.client.open()
            await stream.send(b"abcdef")

            accepted = await pair.server.accept(timeout=10)

            assert await accepted.receive(1, timeout=10) == b"a"

            await pair.client.close(timeout=0.5)

            assert await accepted.receive(timeout=5) == b"bcdef"

    async def test_a_reset_is_not_a_clean_end(self, server_certificate):
        # RFC 9000 section 19.4: a reset carries an application error code, and
        # the receiver has to see an abandoned stream rather than a finished one.
        async with Pair(server_certificate) as pair:
            stream = await pair.client.open()
            await stream.send(b"partial")
            stream.reset(0x10F)

            accepted = await pair.server.accept(timeout=10)

            with pytest.raises(QUICStreamError) as caught:
                for _ in range(50):
                    await accepted.receive(timeout=10)

            assert caught.value.code == 0x10F

class TestDirection:
    async def test_a_unidirectional_stream_only_sends_at_the_opener(self, server_certificate):
        # RFC 9000 section 2.1: the side that opens a unidirectional stream can
        # only send on it.
        async with Pair(server_certificate) as pair:
            stream = await pair.client.open(unidirectional=True)

            assert stream.writable
            assert not stream.readable

            with pytest.raises(QUICClosedError):
                await stream.receive(1, timeout=5)

    async def test_a_unidirectional_stream_only_receives_at_the_peer(self, server_certificate):
        async with Pair(server_certificate) as pair:
            stream = await pair.client.open(unidirectional=True)
            await stream.send(b"one way")
            stream.conclude()

            accepted = await pair.server.accept(timeout=10)

            assert accepted.readable
            assert not accepted.writable
            assert await accepted.receive(timeout=10) == b"one way"

            with pytest.raises(QUICClosedError):
                await accepted.send(b"back")

    async def test_the_opener_is_reported_as_local(self, server_certificate):
        async with Pair(server_certificate) as pair:
            stream = await pair.client.open()
            await stream.send(b"x")

            accepted = await pair.server.accept(timeout=10)

            assert stream.local
            assert not accepted.local
