"""
End-to-end QUIC transport tests over the in-process loopback harness.

These drive a real OpenSSL QUIC-TLS handshake and exercise the transport the way
two peers actually would, validating streams, flow control credit replenishment
(RFC 9000 §4) and key update (RFC 9001 §6) against a live connection rather than
in isolation.
"""
from __future__ import annotations

import os

from kaede.quic.connection import StreamDataReceived

def collect_stream_data(conn, stream_id: int) -> bytes:
    return b"".join(
        e.data for e in conn.events()
        if isinstance(e, StreamDataReceived) and e.stream_id == stream_id
    )

class TestHandshake:
    def test_completes(self, quic_pair):
        assert quic_pair.handshake()
        assert quic_pair.client.handshake_confirmed
        assert quic_pair.server.handshake_confirmed

    def test_alpn_negotiated(self, quic_pair):
        quic_pair.handshake()
        assert quic_pair.client.tls.alpn() == "h3"

class TestStreams:
    def test_client_to_server(self, quic_pair):
        quic_pair.handshake()
        sid = quic_pair.client.get_next_available_stream_id(is_bidi=True)
        quic_pair.client.send_stream_data(sid, b"hello world", end_stream=True)
        quic_pair.pump()
        assert collect_stream_data(quic_pair.server, sid) == b"hello world"

    def test_bidirectional(self, quic_pair):
        quic_pair.handshake()
        sid = quic_pair.client.get_next_available_stream_id(is_bidi=True)
        quic_pair.client.send_stream_data(sid, b"ping", end_stream=False)
        quic_pair.pump()
        assert collect_stream_data(quic_pair.server, sid) == b"ping"

        quic_pair.server.send_stream_data(sid, b"pong", end_stream=True)
        quic_pair.pump()
        assert collect_stream_data(quic_pair.client, sid) == b"pong"

class TestFlowControl:
    def test_transfer_exceeding_initial_window(self, quic_pair):
        # The per-stream initial limit is 1 MiB; sending more than that only
        # completes if the receiver replenishes credit via MAX_STREAM_DATA.
        quic_pair.handshake()
        payload = os.urandom(1_500_000)
        sid = quic_pair.client.get_next_available_stream_id(is_bidi=True)
        quic_pair.client.send_stream_data(sid, payload, end_stream=True)
        quic_pair.pump(max_rounds=200)
        assert collect_stream_data(quic_pair.server, sid) == payload

class TestKeyUpdate:
    def test_update_over_live_connection(self, quic_pair):
        quic_pair.handshake()
        assert quic_pair.client.handshake_confirmed

        sid = quic_pair.client.get_next_available_stream_id(is_bidi=True)
        quic_pair.client.send_stream_data(sid, b"before-", end_stream=False)
        quic_pair.pump()

        quic_pair.client.initiate_key_update()
        assert quic_pair.client.send_key_gen == 1

        quic_pair.client.send_stream_data(sid, b"after", end_stream=True)
        quic_pair.pump()

        data = collect_stream_data(quic_pair.server, sid)
        assert data == b"before-after"
        assert quic_pair.server.recv_key_gen == 1
        assert quic_pair.server.send_key_gen == 1
