import asyncio
from ssl import CERT_NONE

import pytest

from kaede.tls import TLSConfig
from kaede.udp.models import UDPPort
from kaede.udp.protocol import UDPConnection
from kaede.quic.models import QUICPacket
from kaede.quic.tls import QTLS, QUICContext
from kaede.quic.protocol import QUICEndpoint, QUICConnection
from kaede.quic.api.server import QUICRelay, QUICServerEndpoint

LOCAL = "127.0.0.1"
PEER = ("192.0.2.10", 4433)  # the peer a learned identifier was handed to

# RFC 9000 section 5.1 routes a packet by the connection id it names, which is
# what lets a connection outlive its peer's address changing. SO_REUSEPORT
# spreads datagrams by address instead, so across several workers the two
# disagree exactly when a peer moves. What is checked here is that a worker
# recognises its own identifiers, passes on what it does not recognise, and
# never passes on a connection that is only just starting.

@pytest.fixture(scope="module", autouse=True)
def servable():
    if not QTLS().servable:
        pytest.skip("a QUIC server needs OpenSSL 4.0 or newer")

class Recording:
    """Stands in for the siblings, noting what it was asked to carry."""

    def __init__(self):
        self.carried = []

    def spread(self, data, address):
        self.carried.append((data, address))

class Gone:
    """A torn-down connection, identified only by the address it answered."""

    def __init__(self, dst):
        self.dst = dst

def endpoint(certificate, relay=None) -> QUICServerEndpoint:
    certfile, keyfile = certificate
    context = QUICContext(TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE), server=True, alpn=["kaede/1"])

    return QUICServerEndpoint(context, relay=relay)

def initial(destination=b"\x01\x02\x03\x04\x05\x06\x07\x08"):
    """A client's first packet: a long header of type Initial."""

    return (bytes([0x80 | 0x40 | (QUICPacket.INITIAL << 4)]) + (1).to_bytes(4, "big")
            + bytes([len(destination)]) + destination + bytes([0]) + b"payload")

def onward(destination, kind=QUICPacket.HANDSHAKE):
    return (bytes([0x80 | 0x40 | (kind << 4)]) + (1).to_bytes(4, "big")
            + bytes([len(destination)]) + destination + bytes([0]) + b"payload")

def short(destination):
    return bytes([0x40]) + destination + b"payload"

def spoken(destination, source):
    """What a server sends back: a long header naming its own id as the source."""

    return (bytes([0x80 | 0x40 | (QUICPacket.HANDSHAKE << 4)]) + (1).to_bytes(4, "big")
            + bytes([len(destination)]) + destination
            + bytes([len(source)]) + source + b"payload")

class TestLearning:
    def test_learns_the_identifiers_it_hands_out(self, server_certificate):
        # RFC 9000 section 17.2: the source connection id of a long header is
        # the one this side is asking to be addressed by from now on.
        one = endpoint(server_certificate)
        one.learn(spoken(b"\xaa\xbb", b"\x01\x02\x03\x04\x05\x06\x07\x08"), PEER)

        assert b"\x01\x02\x03\x04\x05\x06\x07\x08" in one.identifiers
        assert one.lengths == {8}

    def test_learns_nothing_from_a_short_header(self, server_certificate):
        # A short header states no source id at all.
        one = endpoint(server_certificate)
        one.learn(short(b"\x01\x02\x03\x04\x05\x06\x07\x08"), PEER)

        assert one.identifiers == {}

    def test_learns_nothing_from_a_sourceless_long_header(self, server_certificate):
        one = endpoint(server_certificate)
        one.learn(onward(b"\xaa\xbb"), PEER)

        assert one.identifiers == {}

    def test_learns_more_than_one(self, server_certificate):
        one = endpoint(server_certificate)

        one.learn(spoken(b"\xaa", b"\x11" * 8), PEER)
        one.learn(spoken(b"\xbb", b"\x22" * 8), PEER)

        assert set(one.identifiers) == {b"\x11" * 8, b"\x22" * 8}

class TestRecognition:
    def test_recognises_a_short_header_naming_its_own_id(self, server_certificate):
        one = endpoint(server_certificate)
        one.learn(spoken(b"\xaa", b"\x11" * 8), PEER)

        assert one.mine(short(b"\x11" * 8))

    def test_does_not_recognise_another_workers_id(self, server_certificate):
        one = endpoint(server_certificate)
        one.learn(spoken(b"\xaa", b"\x11" * 8), PEER)

        assert not one.mine(short(b"\x22" * 8))

    def test_recognises_a_long_header_naming_its_own_id(self, server_certificate):
        one = endpoint(server_certificate)
        one.learn(spoken(b"\xaa", b"\x11" * 8), PEER)

        assert one.mine(onward(b"\x11" * 8))

    def test_recognises_nothing_before_it_has_spoken(self, server_certificate):
        one = endpoint(server_certificate)

        assert not one.mine(short(b"\x11" * 8))
        assert not one.mine(onward(b"\x11" * 8))

class TestForgetting:
    # A worker must let go of a connection's identifiers once it is gone, or the
    # routing table would grow without bound over the lifetime of the server.

    def test_forgetting_a_connection_drops_the_identifiers_it_handed_out(self, server_certificate):
        one = endpoint(server_certificate)
        one.learn(spoken(b"\xaa", b"\x11" * 8), (LOCAL, 4433))

        assert one.mine(short(b"\x11" * 8))

        one.unlearn(Gone((LOCAL, UDPPort(4433))))

        assert not one.mine(short(b"\x11" * 8))
        assert one.identifiers == {}
        assert one.lengths == set()

    def test_forgetting_one_connection_keeps_anothers_identifiers(self, server_certificate):
        # Each connection answers a different peer, so letting one go must leave
        # the other's identifier in place.
        one = endpoint(server_certificate)
        one.learn(spoken(b"\xaa", b"\x11" * 8), (LOCAL, 4433))
        one.learn(spoken(b"\xbb", b"\x22" * 8), (LOCAL, 5544))

        one.unlearn(Gone((LOCAL, UDPPort(4433))))

        assert not one.mine(short(b"\x11" * 8))
        assert one.mine(short(b"\x22" * 8))
        assert set(one.identifiers) == {b"\x22" * 8}
        assert one.lengths == {8}

class TestRouting:
    def test_takes_everything_when_there_are_no_siblings(self, server_certificate):
        # A server on its own owns its socket outright.
        one = endpoint(server_certificate)

        assert one.owns(short(b"\x99" * 8), (LOCAL, 1))
        assert one.owns(initial(), (LOCAL, 1))

    def test_takes_a_connection_that_is_only_starting(self, server_certificate):
        # The identifier in a client's first packet is one the client invented,
        # so no worker owns it. Passing it on would have every worker answer.
        siblings = Recording()
        one = endpoint(server_certificate, relay=siblings)

        assert one.owns(initial(), (LOCAL, 1))
        assert siblings.carried == []

    def test_takes_a_datagram_naming_its_own_id(self, server_certificate):
        siblings = Recording()
        one = endpoint(server_certificate, relay=siblings)
        one.learn(spoken(b"\xaa", b"\x11" * 8), PEER)

        assert one.owns(short(b"\x11" * 8), (LOCAL, 1))
        assert siblings.carried == []

    def test_passes_on_a_datagram_for_somebody_else(self, server_certificate):
        # This is the case SO_REUSEPORT gets wrong: the peer moved, so the
        # kernel delivered an established connection to the wrong worker.
        siblings = Recording()
        one = endpoint(server_certificate, relay=siblings)
        one.learn(spoken(b"\xaa", b"\x11" * 8), PEER)

        datagram = short(b"\x22" * 8)

        assert not one.owns(datagram, (LOCAL, 5555))
        assert siblings.carried == [(datagram, (LOCAL, 5555))]

    def test_passes_on_an_unreadable_datagram_rather_than_eating_it(self, server_certificate):
        # A worker that has handed out nothing yet cannot read a short header at
        # all, and dropping it would strand the connection that owns it.
        siblings = Recording()
        one = endpoint(server_certificate, relay=siblings)

        datagram = short(b"\x22" * 8)

        assert not one.owns(datagram, (LOCAL, 5555))
        assert siblings.carried == [(datagram, (LOCAL, 5555))]

    def test_passes_on_a_handshake_packet_for_somebody_else(self, server_certificate):
        siblings = Recording()
        one = endpoint(server_certificate, relay=siblings)
        one.learn(spoken(b"\xaa", b"\x11" * 8), PEER)

        assert not one.owns(onward(b"\x22" * 8), (LOCAL, 1))
        assert len(siblings.carried) == 1

class TestMessage:
    def test_the_address_survives_the_trip(self, server_certificate):
        # The worker that takes the datagram has to answer the peer it came
        # from, not the sibling that handed it over.
        message = QUICRelay.pack(b"payload", ("192.0.2.10", 4433))

        assert QUICRelay.unpack(message) == (b"payload", ("192.0.2.10", 4433))

    def test_an_ipv6_address_survives(self, server_certificate):
        message = QUICRelay.pack(b"payload", ("2001:db8::1", 65535))

        assert QUICRelay.unpack(message) == (b"payload", ("2001:db8::1", 65535))

    def test_an_empty_payload_survives(self):
        assert QUICRelay.unpack(QUICRelay.pack(b"", (LOCAL, 1)))[0] == b""

    @pytest.mark.parametrize("message", [b"", b"\x01", b"\x09abc"])
    def test_refuses_a_message_cut_short(self, message):
        assert QUICRelay.unpack(message) is None

class TestCarrying:
    async def test_a_datagram_reaches_the_sibling_that_owns_it(self, server_certificate):
        # The whole mechanism end to end, over the real sockets, without needing
        # to fork: two relays, one holding an identifier the other does not.
        directory, paths, sockets = QUICRelay.prepare(2)

        first = QUICRelay(paths, 0, sockets[0])
        second = QUICRelay(paths, 1, sockets[1])

        owner = endpoint(server_certificate)
        owner.learn(spoken(b"\xaa", b"\x11" * 8), PEER)

        taken = []
        owner.take = lambda data, address: taken.append((data, address))

        try:
            await first.open([endpoint(server_certificate)])
            await second.open([owner])

            datagram = short(b"\x11" * 8)
            first.spread(datagram, ("192.0.2.10", 4433))

            for _ in range(100):
                if taken:
                    break

                await asyncio.sleep(0.01)

            assert taken == [(datagram, ("192.0.2.10", 4433))]

        finally:
            first.close()
            second.close()

            import shutil
            shutil.rmtree(directory, ignore_errors=True)

    async def test_a_sibling_that_does_not_own_it_lets_it_go(self, server_certificate):
        directory, paths, sockets = QUICRelay.prepare(2)

        first = QUICRelay(paths, 0, sockets[0])
        second = QUICRelay(paths, 1, sockets[1])

        stranger = endpoint(server_certificate)
        stranger.learn(spoken(b"\xaa", b"\x99" * 8), PEER)

        taken = []
        stranger.take = lambda data, address: taken.append((data, address))

        try:
            await first.open([endpoint(server_certificate)])
            await second.open([stranger])

            first.spread(short(b"\x11" * 8), ("192.0.2.10", 4433))

            await asyncio.sleep(0.2)

            assert taken == []

        finally:
            first.close()
            second.close()

            import shutil
            shutil.rmtree(directory, ignore_errors=True)
