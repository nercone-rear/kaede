import asyncio

import pytest

from kaede.udp import UDPPort
from kaede.udp.protocol import UDPConnection, UDPProtocol
from kaede.udp.errors import UDPClosedError, UDPTimeoutError, UDPBusyError, UDPLostError

LOCAL = "127.0.0.1"

# RFC 768 defines UDP as a datagram service: each send produces exactly one
# message, message boundaries are preserved, and a message is either delivered
# whole or not at all. None of the stream behaviour TCP has applies here, so
# these tests are written against the datagram contract rather than against any
# resemblance to TCPConnection.

def loose(dst=(LOCAL, 8), src=("", 0)) -> UDPConnection:
    """A connection with no socket behind it, so arrivals can be staged exactly."""

    return UDPConnection((src[0], UDPPort(src[1])), (dst[0], UDPPort(dst[1])))

class Peer(asyncio.DatagramProtocol):
    """A plain asyncio datagram endpoint standing in for the far side, so the
    behaviour under test is checked against the standard library rather than
    against another copy of Kaede."""

    def __init__(self, echo=None):
        self.echo = echo
        self.received = []
        self.transport = None

    async def __aenter__(self):
        loop = asyncio.get_running_loop()
        self.transport, _ = await loop.create_datagram_endpoint(lambda: self, local_addr=(LOCAL, 0))

        return self

    async def __aexit__(self, *_):
        self.transport.close()
        await asyncio.sleep(0)  # let the transport hand its socket back

    @property
    def address(self):
        host, port = self.transport.get_extra_info("sockname")[:2]

        return (host, UDPPort(port))

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.received.append((data, addr))

        if self.echo is not None:
            self.transport.sendto(self.echo(data), addr)

class TestDatagramBoundaries:
    async def test_each_datagram_is_delivered_whole(self):
        # RFC 768: the message is the unit of delivery, so three sends must not
        # be observable as one joined message.
        connection = loose()

        for payload in (b"one", b"two", b"three"):
            connection.feed(payload)

        assert await connection.receive() == b"one"
        assert await connection.receive() == b"two"
        assert await connection.receive() == b"three"

    async def test_datagrams_are_never_joined(self):
        connection = loose()

        connection.feed(b"ab")
        connection.feed(b"cd")

        # A stream implementation would answer b"abcd" here.
        assert await connection.receive() == b"ab"

    async def test_a_datagram_is_never_split(self):
        connection = loose()
        connection.feed(b"hello")

        assert await connection.receive() == b"hello"

    async def test_an_empty_datagram_is_a_datagram(self):
        # RFC 768 permits a zero length payload, and it must not be mistaken for
        # an end of stream the way an empty TCP read would be.
        connection = loose()
        connection.feed(b"")

        assert await connection.receive() == b""

    async def test_an_empty_datagram_does_not_end_the_connection(self):
        connection = loose()

        connection.feed(b"")
        connection.feed(b"after")

        assert await connection.receive() == b""
        assert await connection.receive() == b"after"

class TestTruncation:
    async def test_a_limit_truncates_the_datagram(self):
        connection = loose()
        connection.feed(b"hello")

        assert await connection.receive(2) == b"he"

    async def test_the_remainder_of_a_truncated_datagram_is_discarded(self):
        # This is the defining difference from a stream: the bytes that did not
        # fit are lost, exactly as a short recv on a SOCK_DGRAM socket loses them.
        connection = loose()

        connection.feed(b"hello")
        connection.feed(b"world")

        assert await connection.receive(2) == b"he"
        assert await connection.receive() == b"world"

    async def test_a_limit_larger_than_the_datagram_returns_it_whole(self):
        connection = loose()
        connection.feed(b"hello")

        assert await connection.receive(1024) == b"hello"

    async def test_a_negative_limit_returns_the_whole_datagram(self):
        connection = loose()
        connection.feed(b"hello")

        assert await connection.receive(-1) == b"hello"

    async def test_a_zero_limit_consumes_the_datagram(self):
        # A zero length buffer still receives a message, it just keeps none of it.
        connection = loose()

        connection.feed(b"hello")
        connection.feed(b"world")

        assert await connection.receive(0) == b""
        assert await connection.receive() == b"world"

class TestQueue:
    async def test_arrivals_beyond_the_limit_are_dropped(self):
        # UDP has no flow control, so the only options are to drop or to grow
        # without bound. Dropping is the one that cannot be used to exhaust memory.
        connection = loose()

        for index in range(connection.queue_limit + 10):
            connection.feed(bytes([index % 256]))

        assert len(connection.queue) == connection.queue_limit
        assert connection.dropped == 10

    async def test_the_earliest_datagrams_are_the_ones_kept(self):
        connection = loose()

        for index in range(connection.queue_limit + 5):
            connection.feed(index.to_bytes(2, "big"))

        assert await connection.receive() == (0).to_bytes(2, "big")

    async def test_nothing_is_dropped_below_the_limit(self):
        connection = loose()

        for index in range(connection.queue_limit):
            connection.feed(bytes([index % 256]))

        assert connection.dropped == 0

class TestWaiting:
    async def test_receive_waits_for_a_datagram(self):
        connection = loose()

        async def later():
            await asyncio.sleep(0.01)
            connection.feed(b"eventually")

        asyncio.ensure_future(later())
        assert await connection.receive() == b"eventually"

    async def test_receive_times_out(self):
        connection = loose()

        with pytest.raises(UDPTimeoutError):
            await connection.receive(timeout=0.01)

    async def test_a_timeout_does_not_break_later_receives(self):
        connection = loose()

        with pytest.raises(UDPTimeoutError):
            await connection.receive(timeout=0.01)

        connection.feed(b"late")
        assert await connection.receive() == b"late"

    async def test_a_queued_datagram_is_returned_without_waiting(self):
        connection = loose()
        connection.feed(b"ready")

        # A timeout of zero would expire if the queue were not consulted first.
        assert await connection.receive(timeout=0) == b"ready"

    async def test_two_receivers_are_refused(self):
        connection = loose()

        first = asyncio.ensure_future(connection.receive())
        await asyncio.sleep(0)

        with pytest.raises(UDPBusyError):
            await connection.receive()

        connection.feed(b"done")
        assert await first == b"done"

class TestClosing:
    async def test_receiving_after_close_is_rejected(self):
        connection = loose()
        await connection.close()

        with pytest.raises(UDPClosedError):
            await connection.receive()

    async def test_sending_after_close_is_rejected(self):
        connection = loose()
        await connection.close()

        with pytest.raises(UDPClosedError):
            await connection.send(b"late")

    async def test_sending_without_an_endpoint_is_rejected(self):
        with pytest.raises(UDPClosedError):
            await loose().send(b"nowhere")

    async def test_close_is_idempotent(self):
        connection = loose()

        await connection.close()
        await connection.close()

    async def test_datagrams_queued_before_close_are_still_readable(self):
        connection = loose()

        connection.feed(b"queued")
        await connection.close()

        assert await connection.receive() == b"queued"

    async def test_arrivals_after_close_are_dropped(self):
        # A closed connection must not keep accumulating, or a peer that carries
        # on sending would hold the memory of a connection nobody is reading.
        connection = loose()
        await connection.close()

        connection.feed(b"ignored")

        assert not connection.queue

    async def test_closing_wakes_a_waiting_receiver(self):
        connection = loose()
        waiting = asyncio.ensure_future(connection.receive())

        await asyncio.sleep(0)
        await connection.close()

        with pytest.raises(UDPClosedError):
            await waiting

class TestFailure:
    async def test_a_reported_failure_surfaces_on_receive(self):
        connection = loose()
        connection.fail(OSError("connection refused"))

        with pytest.raises(UDPLostError):
            await connection.receive()

    async def test_a_reported_failure_surfaces_on_send(self):
        connection = loose()
        connection.attach(object())
        connection.fail(OSError("connection refused"))

        with pytest.raises(UDPLostError):
            await connection.send(b"anything")

    async def test_the_cause_is_kept(self):
        connection = loose()
        cause = OSError("connection refused")
        connection.fail(cause)

        with pytest.raises(UDPLostError) as caught:
            await connection.receive()

        assert caught.value.__cause__ is cause

class TestAddress:
    def test_an_address_becomes_a_host_and_a_port(self):
        host, port = UDPProtocol.address(("127.0.0.1", 53))

        assert host == "127.0.0.1"
        assert isinstance(port, UDPPort)
        assert port == 53

    def test_an_absent_address_is_empty(self):
        assert UDPProtocol.address(None) == ("", UDPPort(0))

    def test_an_ipv6_address_keeps_its_host_and_port(self):
        # getsockname returns a four element tuple for IPv6, and the extra
        # flowinfo and scope fields must not disturb the host and port.
        host, port = UDPProtocol.address(("::1", 53, 0, 0))

        assert host == "::1"
        assert port == 53

class TestDemultiplexing:
    def test_each_peer_gets_its_own_connection(self):
        protocol = UDPProtocol(src=(LOCAL, UDPPort(53)))
        protocol.transport = object()

        first = protocol.dispatch((LOCAL, UDPPort(1000)))
        second = protocol.dispatch((LOCAL, UDPPort(2000)))

        assert first is not second
        assert len(protocol.connections) == 2

    def test_the_same_peer_keeps_the_same_connection(self):
        protocol = UDPProtocol(src=(LOCAL, UDPPort(53)))
        protocol.transport = object()

        first = protocol.dispatch((LOCAL, UDPPort(1000)))
        second = protocol.dispatch((LOCAL, UDPPort(1000)))

        assert first is second
        assert len(protocol.connections) == 1

    def test_the_same_port_on_a_different_host_is_a_different_peer(self):
        protocol = UDPProtocol(src=(LOCAL, UDPPort(53)))
        protocol.transport = object()

        first = protocol.dispatch(("10.0.0.1", UDPPort(1000)))
        second = protocol.dispatch(("10.0.0.2", UDPPort(1000)))

        assert first is not second

    def test_datagrams_reach_the_connection_for_their_peer(self):
        protocol = UDPProtocol(src=(LOCAL, UDPPort(53)))
        protocol.transport = object()

        protocol.datagram_received(b"from first", (LOCAL, 1000))
        protocol.datagram_received(b"from second", (LOCAL, 2000))

        assert list(protocol.connections[(LOCAL, UDPPort(1000))].queue) == [b"from first"]
        assert list(protocol.connections[(LOCAL, UDPPort(2000))].queue) == [b"from second"]

    def test_a_refused_peer_is_not_retained(self):
        class Closed(UDPProtocol):
            def arrive(self, connection):
                return False

        protocol = Closed(src=(LOCAL, UDPPort(53)))
        protocol.transport = object()

        protocol.datagram_received(b"unwelcome", (LOCAL, 1000))

        assert protocol.connections == {}

    async def test_forgetting_a_peer_removes_it(self):
        protocol = UDPProtocol(src=(LOCAL, UDPPort(53)))
        protocol.transport = object()

        connection = protocol.dispatch((LOCAL, UDPPort(1000)))
        await connection.close()

        assert protocol.connections == {}

class TestOverTheWire:
    async def test_sends_a_datagram_to_the_peer(self):
        async with Peer() as peer:
            connection = UDPConnection(("", UDPPort(0)), peer.address)
            await connection.connect()

            await connection.send(b"hello")
            await asyncio.sleep(0.05)

            await connection.close()

        assert [data for data, _ in peer.received] == [b"hello"]

    async def test_receives_a_reply(self):
        async with Peer(echo=bytes.upper) as peer:
            connection = UDPConnection(("", UDPPort(0)), peer.address)
            await connection.connect()

            await connection.send(b"hello")
            assert await connection.receive(timeout=2) == b"HELLO"

            await connection.close()

    async def test_boundaries_survive_a_real_socket(self):
        async with Peer(echo=bytes.upper) as peer:
            connection = UDPConnection(("", UDPPort(0)), peer.address)
            await connection.connect()

            for payload in (b"one", b"two", b"three"):
                await connection.send(payload)

            assert await connection.receive(timeout=2) == b"ONE"
            assert await connection.receive(timeout=2) == b"TWO"
            assert await connection.receive(timeout=2) == b"THREE"

            await connection.close()

    async def test_an_empty_datagram_survives_a_real_socket(self):
        async with Peer() as peer:
            connection = UDPConnection(("", UDPPort(0)), peer.address)
            await connection.connect()

            await connection.send(b"")
            await asyncio.sleep(0.05)

            await connection.close()

        assert [data for data, _ in peer.received] == [b""]

    async def test_carries_a_large_datagram(self):
        payload = bytes(range(256)) * 32  # 8 KiB, within the loopback MTU

        async with Peer(echo=lambda data: data) as peer:
            connection = UDPConnection(("", UDPPort(0)), peer.address)
            await connection.connect()

            await connection.send(payload)
            assert await connection.receive(timeout=2) == payload

            await connection.close()

    async def test_learns_its_own_address(self):
        async with Peer() as peer:
            connection = UDPConnection(("", UDPPort(0)), peer.address)
            await connection.connect()

            host, port = connection.src

            assert isinstance(port, UDPPort)
            assert port != 0  # the OS assigned one

            await connection.close()

    async def test_connecting_twice_is_rejected(self):
        from kaede.udp.errors import UDPConnectionError

        async with Peer() as peer:
            connection = UDPConnection(("", UDPPort(0)), peer.address)
            await connection.connect()

            with pytest.raises(UDPConnectionError):
                await connection.connect()

            await connection.close()

    async def test_closing_releases_the_socket(self):
        # close must not return until the socket is actually gone, so a caller
        # that closes and exits does not leave the descriptor behind.
        async with Peer() as peer:
            connection = UDPConnection(("", UDPPort(0)), peer.address)
            await connection.connect()

            sock = connection.socket
            await connection.close()

            assert sock.fileno() == -1
