"""
RFC 9001 §4: QUIC 0-RTT resumption tests.

All tests require an OpenSSL build with the QUIC-TLS API (3.5+) and a server
that has max_early_data set to a non-zero value.  Tests are skipped automatically
when those prerequisites are not met.
"""
from __future__ import annotations

import ssl
import pytest

from kaede.quic.crypto import LEVEL_EARLY, LEVEL_APPLICATION


def _quic_tls_available() -> bool:
    try:
        from kaede.tls.openssl import OpenSSL
        OpenSSL.get()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _quic_tls_available(),
    reason="OpenSSL QUIC-TLS API (3.5+) not available",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pump(client, server, now: float = 0.0, rounds: int = 80) -> list:
    """Drive datagrams between client and server; return all server events."""
    events: list = []
    for _ in range(rounds):
        moved = False
        for d, _ in client.datagrams_to_send(now):
            server.receive_datagram(d, now)
            events += server.events()
            moved = True
        for d, _ in server.datagrams_to_send(now):
            client.receive_datagram(d, now)
            moved = True
        if not moved:
            break
    return events


def _make_connections(tls_cert):
    """Create a fully-handshaked client/server pair using a shared server context."""
    from kaede.quic.tls import QuicTLS, QuicTLSServerContext
    from kaede.quic.connection import QUICConnection
    from kaede.tls.models import TLSServerConfig, TLSClientConfig

    certfile, keyfile = tls_cert
    server_cfg = TLSServerConfig(certfile=certfile, keyfile=keyfile, verify_mode=ssl.CERT_NONE)
    client_cfg = TLSClientConfig(verify=False, check_hostname=False)

    server_ctx = QuicTLSServerContext.for_server(server_cfg, enable_0rtt=True)

    def srv_factory(tp: bytes) -> QuicTLS:
        return server_ctx.connection(transport_params=tp)

    def cli_factory(tp: bytes, session=None) -> QuicTLS:
        return QuicTLS.for_client(
            client_cfg, "localhost",
            transport_params=tp,
            session_bytes=session.tls_session if session else None,
        )

    return server_ctx, srv_factory, cli_factory


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestZeroRTTSession:
    def test_session_available_after_handshake(self, tls_cert):
        """RFC 9001 §4.6: server must send a NewSessionTicket enabling 0-RTT."""
        from kaede.quic.tls import QuicTLS
        from kaede.quic.connection import QUICConnection

        server_ctx, srv_factory, cli_factory = _make_connections(tls_cert)

        client = QUICConnection.create_client(cli_factory, "localhost")
        initials = [d for d, _ in client.datagrams_to_send(0.0)]
        server = QUICConnection.create_server(initials[0], srv_factory)
        for d in initials:
            server.receive_datagram(d, 0.0)
        _pump(client, server)

        assert client.handshake_complete
        session = client.get_session()
        assert session is not None, "No session ticket received after handshake"
        assert len(session.tls_session) > 0
        assert len(session.peer_transport_params) > 0

        server_ctx.free()

    def test_peer_transport_params_restored_from_session(self, tls_cert):
        """RFC 9001 §4.6.1: saved transport params must be pre-populated on resume."""
        from kaede.quic.connection import QUICConnection, TP_INITIAL_MAX_DATA

        server_ctx, srv_factory, cli_factory = _make_connections(tls_cert)

        # First connection
        client1 = QUICConnection.create_client(cli_factory, "localhost")
        initials = [d for d, _ in client1.datagrams_to_send(0.0)]
        server1 = QUICConnection.create_server(initials[0], srv_factory)
        for d in initials:
            server1.receive_datagram(d, 0.0)
        _pump(client1, server1)
        session = client1.get_session()
        assert session is not None

        # Second connection: transport params should be pre-populated from session
        client2 = QUICConnection.create_client(
            lambda tp: cli_factory(tp, session),
            "localhost",
            session=session,
        )
        assert TP_INITIAL_MAX_DATA in client2.peer_transport_params

        server_ctx.free()


class TestZeroRTTKeys:
    def test_client_has_early_send_keys_before_handshake(self, tls_cert):
        """RFC 9001 §4: client must have 0-RTT send keys without waiting for the server."""
        from kaede.quic.connection import QUICConnection

        server_ctx, srv_factory, cli_factory = _make_connections(tls_cert)

        # First connection – full handshake
        client1 = QUICConnection.create_client(cli_factory, "localhost")
        initials1 = [d for d, _ in client1.datagrams_to_send(0.0)]
        server1 = QUICConnection.create_server(initials1[0], srv_factory)
        for d in initials1:
            server1.receive_datagram(d, 0.0)
        _pump(client1, server1)
        session = client1.get_session()
        assert session is not None

        # Second connection – no server interaction yet
        client2 = QUICConnection.create_client(
            lambda tp: cli_factory(tp, session),
            "localhost",
            session=session,
        )
        # Trigger TLS advance (sends ClientHello; OpenSSL yields EARLY write secret)
        client2.datagrams_to_send(0.0)
        assert LEVEL_EARLY in client2.send_keys, (
            "Client should have LEVEL_EARLY send keys installed after first advance"
        )

        server_ctx.free()

    def test_early_send_keys_removed_after_1rtt_available(self, tls_cert):
        """RFC 9001 §4.9.3: 0-RTT keys must be discarded once 1-RTT keys are available."""
        from kaede.quic.connection import QUICConnection

        server_ctx, srv_factory, cli_factory = _make_connections(tls_cert)

        client1 = QUICConnection.create_client(cli_factory, "localhost")
        initials1 = [d for d, _ in client1.datagrams_to_send(0.0)]
        server1 = QUICConnection.create_server(initials1[0], srv_factory)
        for d in initials1:
            server1.receive_datagram(d, 0.0)
        _pump(client1, server1)
        session = client1.get_session()
        assert session is not None

        client2 = QUICConnection.create_client(
            lambda tp: cli_factory(tp, session),
            "localhost",
            session=session,
        )
        initials2 = [d for d, _ in client2.datagrams_to_send(0.0)]
        server2 = QUICConnection.create_server(initials2[0], srv_factory)
        for d in initials2:
            server2.receive_datagram(d, 0.0)
        _pump(client2, server2)

        assert client2.handshake_complete
        assert LEVEL_APPLICATION in client2.send_keys
        assert LEVEL_EARLY not in client2.send_keys, (
            "LEVEL_EARLY send keys must be removed after 1-RTT keys are installed"
        )

        server_ctx.free()


class TestZeroRTTDataDelivery:
    def test_0rtt_packet_uses_long_header_type_0x01(self, tls_cert):
        """RFC 9000 §17.2.3: 0-RTT packets must use packet type 0x01."""
        from kaede.quic import packet as pkt_mod
        from kaede.quic.connection import QUICConnection

        server_ctx, srv_factory, cli_factory = _make_connections(tls_cert)

        client1 = QUICConnection.create_client(cli_factory, "localhost")
        initials1 = [d for d, _ in client1.datagrams_to_send(0.0)]
        server1 = QUICConnection.create_server(initials1[0], srv_factory)
        for d in initials1:
            server1.receive_datagram(d, 0.0)
        _pump(client1, server1)
        session = client1.get_session()
        assert session is not None

        client2 = QUICConnection.create_client(
            lambda tp: cli_factory(tp, session),
            "localhost",
            session=session,
        )

        # Write stream data before the first advance; it should be coalesced into
        # a 0-RTT packet on the first datagrams_to_send call.
        sid = client2.get_next_available_stream_id(is_bidi=True)
        client2.send_stream_data(sid, b"probe", end_stream=False)

        found_0rtt = False
        for raw, _ in client2.datagrams_to_send(0.0):
            offset = 0
            while offset < len(raw):
                first = raw[offset]
                if not (first & pkt_mod.PACKET_FIXED_BIT):
                    break
                if not pkt_mod.is_long_header(first):
                    break
                hdr = pkt_mod.parse_long_header(raw, offset)
                if hdr.packet_type == pkt_mod.PACKET_TYPE_0RTT:
                    found_0rtt = True
                    break
                offset += hdr.pn_offset + hdr.length

        assert found_0rtt, "No 0-RTT packet (type 0x01) found in client datagrams"

        server_ctx.free()

    def test_handshake_completes_after_0rtt_attempt(self, tls_cert):
        """The handshake must complete normally even when 0-RTT data was sent."""
        from kaede.quic.connection import QUICConnection

        server_ctx, srv_factory, cli_factory = _make_connections(tls_cert)

        client1 = QUICConnection.create_client(cli_factory, "localhost")
        initials1 = [d for d, _ in client1.datagrams_to_send(0.0)]
        server1 = QUICConnection.create_server(initials1[0], srv_factory)
        for d in initials1:
            server1.receive_datagram(d, 0.0)
        _pump(client1, server1)
        session = client1.get_session()
        assert session is not None

        client2 = QUICConnection.create_client(
            lambda tp: cli_factory(tp, session),
            "localhost",
            session=session,
        )
        sid = client2.get_next_available_stream_id(is_bidi=True)
        client2.send_stream_data(sid, b"hello-0rtt", end_stream=True)

        initials2 = [d for d, _ in client2.datagrams_to_send(0.0)]
        assert LEVEL_EARLY in client2.send_keys, "Client must have EARLY send keys"

        server2 = QUICConnection.create_server(initials2[0], srv_factory)
        for d in initials2:
            server2.receive_datagram(d, 0.0)
        _pump(client2, server2)

        assert client2.handshake_complete, "Client handshake must complete"
        assert server2.handshake_complete, "Server handshake must complete"

        server_ctx.free()


class TestZeroRTTServerRecv:
    def test_server_has_early_recv_keys_after_processing_initial(self, tls_cert):
        """Server must obtain LEVEL_EARLY recv keys via keylog callback."""
        from kaede.quic.connection import QUICConnection

        server_ctx, srv_factory, cli_factory = _make_connections(tls_cert)

        client1 = QUICConnection.create_client(cli_factory, "localhost")
        initials1 = [d for d, _ in client1.datagrams_to_send(0.0)]
        server1 = QUICConnection.create_server(initials1[0], srv_factory)
        for d in initials1:
            server1.receive_datagram(d, 0.0)
        _pump(client1, server1)
        session = client1.get_session()
        assert session is not None

        client2 = QUICConnection.create_client(
            lambda tp: cli_factory(tp, session),
            "localhost",
            session=session,
        )
        sid = client2.get_next_available_stream_id(is_bidi=True)
        client2.send_stream_data(sid, b"hello-server-0rtt", end_stream=True)

        initials2 = [d for d, _ in client2.datagrams_to_send(0.0)]
        assert LEVEL_EARLY in client2.send_keys, "Client must have EARLY send keys"

        server2 = QUICConnection.create_server(initials2[0], srv_factory)
        # After receiving the client's Initial (which triggers run_handshake and
        # the keylog callback), the server must have LEVEL_EARLY recv keys.
        for d in initials2:
            server2.receive_datagram(d, 0.0)

        assert LEVEL_EARLY in server2.recv_keys, (
            "Server must install LEVEL_EARLY recv keys via keylog callback"
        )

        server_ctx.free()

    def test_server_receives_0rtt_stream_data(self, tls_cert):
        """0-RTT stream data sent by the client must be delivered to the server."""
        from kaede.quic.connection import QUICConnection, StreamDataReceived

        server_ctx, srv_factory, cli_factory = _make_connections(tls_cert)

        client1 = QUICConnection.create_client(cli_factory, "localhost")
        initials1 = [d for d, _ in client1.datagrams_to_send(0.0)]
        server1 = QUICConnection.create_server(initials1[0], srv_factory)
        for d in initials1:
            server1.receive_datagram(d, 0.0)
        _pump(client1, server1)
        session = client1.get_session()
        assert session is not None

        client2 = QUICConnection.create_client(
            lambda tp: cli_factory(tp, session),
            "localhost",
            session=session,
        )
        sid = client2.get_next_available_stream_id(is_bidi=True)
        client2.send_stream_data(sid, b"hello-server-0rtt", end_stream=True)

        initials2 = [d for d, _ in client2.datagrams_to_send(0.0)]
        server2 = QUICConnection.create_server(initials2[0], srv_factory)
        for d in initials2:
            server2.receive_datagram(d, 0.0)

        events = _pump(client2, server2)
        assert server2.handshake_complete, "Server handshake must complete"

        stream_events = [e for e in server2.events() if isinstance(e, StreamDataReceived)]
        # Also collect events emitted during the pump (passed from server→events())
        all_stream = [e for e in events if isinstance(e, StreamDataReceived)]
        all_stream += stream_events
        payload = b"".join(e.data for e in all_stream if e.stream_id == sid)
        assert payload == b"hello-server-0rtt", (
            f"Expected 0-RTT data on server, got: {payload!r}"
        )

        server_ctx.free()


class TestZeroRTTForbiddenFrames:
    def test_process_frames_rejects_ack_in_0rtt(self, tls_cert):
        """RFC 9000 §12.5: process_frames rejects ACK at LEVEL_EARLY internally.

        NOTE: With OpenSSL 3.x QUIC-TLS external API, the server does not yield
        LEVEL_EARLY read secrets through yield_secret, so 0-RTT packets cannot
        actually be decrypted on the server side.  This test validates the
        PROTOCOL_VIOLATION logic by calling process_frames directly.
        """
        from kaede.quic.connection import QUICConnection, ConnectionTerminated
        from kaede.quic import frame as frames
        from kaede.quic.crypto import LEVEL_EARLY

        server_ctx, srv_factory, cli_factory = _make_connections(tls_cert)

        client1 = QUICConnection.create_client(cli_factory, "localhost")
        initials1 = [d for d, _ in client1.datagrams_to_send(0.0)]
        server1 = QUICConnection.create_server(initials1[0], srv_factory)
        for d in initials1:
            server1.receive_datagram(d, 0.0)
        _pump(client1, server1)

        # Build a fake 0-RTT payload containing an ACK frame (forbidden)
        ack_payload = frames.Ack(largest=0, delay=0, ranges=[(0, 0)]).encode()
        server1.process_frames(ack_payload, LEVEL_EARLY, 0, 0.0)

        # When we detect a protocol violation, we call self.close() which sets
        # close_pending — it does NOT immediately add a ConnectionTerminated event
        # (that only fires when we RECEIVE a peer ConnectionClose frame).
        assert server1.close_pending is not None, (
            "Server must set close_pending (PROTOCOL_VIOLATION) on ACK in LEVEL_EARLY"
        )
        assert server1.close_pending.error_code == 0x0a, (
            f"Expected PROTOCOL_VIOLATION (0x0a), got {server1.close_pending.error_code:#x}"
        )

        server_ctx.free()
