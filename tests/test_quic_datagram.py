"""
QUIC DATAGRAM extension conformance (RFC 9221).

Frame encode/decode plus end-to-end negotiation and delivery over the loopback
harness, including the rule that an endpoint must not send DATAGRAM frames until
the peer advertises support, nor larger than allowed.
"""
from __future__ import annotations

import pytest

from kaede.quic.frame import Datagram, pull_frame
from kaede.quic.packet import Buffer
from kaede.quic.connection import DatagramReceived

class TestFrame:
    def test_round_trip(self):
        decoded = pull_frame(Buffer(Datagram(b"hello datagram").encode()))
        assert isinstance(decoded, Datagram)
        assert decoded.data == b"hello datagram"

    def test_empty_datagram(self):
        decoded = pull_frame(Buffer(Datagram(b"").encode()))
        assert decoded.data == b""

class TestNegotiation:
    def test_both_advertise_support(self, quic_pair):
        quic_pair.handshake()
        assert quic_pair.client.peer_max_datagram_frame_size > 0
        assert quic_pair.server.peer_max_datagram_frame_size > 0

    def test_send_before_negotiation_raises(self, quic_pair):
        # The handshake has not completed, so no peer limit is known yet.
        with pytest.raises(ValueError):
            quic_pair.client.send_datagram(b"x")

    def test_oversized_raises(self, quic_pair):
        quic_pair.handshake()
        with pytest.raises(ValueError):
            quic_pair.client.send_datagram(b"x" * 2000)

class TestDelivery:
    def test_client_to_server(self, quic_pair):
        quic_pair.handshake()
        quic_pair.client.send_datagram(b"unreliable-payload")
        quic_pair.pump()
        received = [e.data for e in quic_pair.server.events() if isinstance(e, DatagramReceived)]
        assert received == [b"unreliable-payload"]

    def test_server_to_client(self, quic_pair):
        quic_pair.handshake()
        quic_pair.server.send_datagram(b"from-server")
        quic_pair.pump()
        received = [e.data for e in quic_pair.client.events() if isinstance(e, DatagramReceived)]
        assert received == [b"from-server"]

    def test_multiple(self, quic_pair):
        quic_pair.handshake()
        for i in range(4):
            quic_pair.client.send_datagram(f"d{i}".encode())
        quic_pair.pump()
        received = [e.data for e in quic_pair.server.events() if isinstance(e, DatagramReceived)]
        assert received == [b"d0", b"d1", b"d2", b"d3"]
