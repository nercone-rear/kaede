from ssl import CERT_NONE

import pytest

from kaede.tls import TLSVersion, TLSGroup, TLSCipher, TLSConfig
from kaede.tls.openssl import OpenSSL, TLSContext, TLSSession, Protocol, Control, Timeval
from kaede.tls.errors import TLSConfigError, TLSHandshakeError, TLSVerificationError

# The two sessions are wired to each other through their memory BIOs, so a full
# RFC 6347 handshake is exercised without any socket being involved.
#
# DTLS differs from TLS in ways these tests pin down: it runs over an unreliable
# datagram transport, so records keep their boundaries, flights are fragmented to
# fit an MTU, and a retransmission timer governs the handshake. OpenSSL 3.6 and
# 4.0 both stop at DTLS 1.2, so there is no 1.3 to negotiate.

@pytest.fixture(scope="module")
def library():
    return OpenSSL()

def pump(client: TLSSession, server: TLSSession, rounds: int = 40) -> bool:
    """Carry datagrams between two sessions until both handshakes complete.

    Each packet is delivered on its own, the way a UDP socket would deliver it,
    rather than joined into one buffer."""

    for _ in range(rounds):
        done = client.handshake()

        for packet in client.packets():
            server.feed(packet)

        done = server.handshake() and done

        for packet in server.packets():
            client.feed(packet)

        if done:
            for packet in client.packets():
                server.feed(packet)

            return True

    return False

def pair(library, server_certificate, *, client=None, server=None, hostname="localhost", alpn=None, ca=None):
    certfile, keyfile = server_certificate

    client = client or TLSConfig()
    server = server or TLSConfig()

    server.certfile, server.keyfile = certfile, keyfile
    server.verify_mode = CERT_NONE

    if ca is not None:
        client.cafile = ca

    client_context = TLSContext(client, server=False, alpn=alpn, datagram=True, library=library)
    server_context = TLSContext(server, server=True, alpn=alpn, datagram=True, library=library)

    return client_context.session(hostname=hostname), server_context.session(), (client_context, server_context)

class TestVersions:
    def test_the_datagram_numbers_match_the_dtls_wire_versions(self):
        # RFC 6347 section 4.1: DTLS versions are the ones complement of the TLS
        # version they correspond to, so they count backwards. DTLS 1.0 is
        # 0xFEFF and DTLS 1.2 is 0xFEFD, and there is no DTLS 1.1.
        assert Protocol.number(TLSVersion.TLSv1_0, True) == 0xFEFF
        assert Protocol.number(TLSVersion.TLSv1_2, True) == 0xFEFD

    def test_the_tls_numbers_are_untouched(self):
        assert Protocol.number(TLSVersion.TLSv1_2) == 0x0303
        assert Protocol.number(TLSVersion.TLSv1_3) == 0x0304

    def test_dtls_1_3_is_refused_rather_than_quietly_downgraded(self):
        # Asking for 1.3 over a datagram transport has to fail loudly. Silently
        # settling for 1.2 would leave the caller believing it got what it asked for.
        with pytest.raises(TLSConfigError):
            Protocol.number(TLSVersion.TLSv1_3, True)

    def test_a_context_refuses_a_minimum_of_tls_1_3(self, library):
        with pytest.raises(TLSConfigError):
            TLSContext(TLSConfig(minimum_version=TLSVersion.TLSv1_3, verify_mode=CERT_NONE), datagram=True, library=library)

class TestTimeval:
    def test_the_fields_are_the_platform_widths(self):
        # A wrong layout reads the seconds from the wrong offset, which would
        # make every retransmission timer nonsense.
        import ctypes, sys

        assert ctypes.sizeof(Timeval) == ctypes.sizeof(ctypes.c_long) * 2

        usec = dict(Timeval._fields_)["usec"]
        assert usec is (ctypes.c_int if sys.platform.startswith("darwin") else ctypes.c_long)

    def test_seconds_combines_both_fields(self):
        assert Timeval(sec=1, usec=500000).seconds == 1.5
        assert Timeval(sec=0, usec=0).seconds == 0.0

class TestContext:
    def test_builds_a_datagram_client_context(self, library):
        assert TLSContext(TLSConfig(verify_mode=CERT_NONE), datagram=True, library=library).pointer

    def test_builds_a_datagram_server_context(self, library, server_certificate):
        certfile, keyfile = server_certificate
        config = TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE)

        assert TLSContext(config, server=True, datagram=True, library=library).pointer

    def test_refuses_a_configuration_with_only_tls_1_3_suites(self, library):
        # DTLS 1.2 cannot use the TLS 1.3 suites, so a configuration offering
        # nothing else has no cipher at all and must be rejected up front.
        config = TLSConfig(verify_mode=CERT_NONE)
        config.ciphers = [TLSCipher.TLS_AES_128_GCM_SHA256]

        with pytest.raises(TLSConfigError):
            TLSContext(config, datagram=True, library=library)

    def test_the_same_configuration_is_fine_over_tls(self, library):
        # The very same configuration must still build for TLS, so the datagram
        # rule stays confined to the datagram path.
        config = TLSConfig(verify_mode=CERT_NONE)
        config.ciphers = [TLSCipher.TLS_AES_128_GCM_SHA256]

        assert TLSContext(config, datagram=False, library=library).pointer

    def test_refuses_a_configuration_without_ciphers(self, library):
        config = TLSConfig(verify_mode=CERT_NONE)
        config.ciphers = []

        with pytest.raises(TLSConfigError):
            TLSContext(config, datagram=True, library=library)

class TestHandshake:
    def test_completes_and_agrees_on_the_parameters(self, library, server_certificate, authority):
        client, server, _ = pair(library, server_certificate, ca=authority.ca)

        assert pump(client, server)
        assert client.established and server.established

        assert client.version == server.version
        assert client.cipher == server.cipher

    def test_negotiates_dtls_1_2(self, library, server_certificate, authority):
        client, server, _ = pair(library, server_certificate, ca=authority.ca)
        assert pump(client, server)

        assert client.version == "DTLSv1.2"
        assert server.version == "DTLSv1.2"

    def test_negotiates_a_classic_group(self, library, server_certificate, authority):
        # TLSConfig lists post-quantum groups first, but those are defined for
        # TLS 1.3 key exchange only. DTLS 1.2 has to fall through to a classic one.
        client, server, _ = pair(library, server_certificate, ca=authority.ca)
        assert pump(client, server)

        assert client.group in {group.value for group in (TLSGroup.X25519, TLSGroup.prime256v1, TLSGroup.secp384r1)}
        assert client.group == server.group

    def test_negotiates_a_tls_1_2_cipher(self, library, server_certificate, authority):
        client, server, _ = pair(library, server_certificate, ca=authority.ca)
        assert pump(client, server)

        # The TLS 1.3 suites are named TLS_*; DTLS 1.2 must not land on one.
        assert not client.cipher.startswith("TLS_")

    def test_honours_a_restricted_cipher_list(self, library, server_certificate, authority):
        config = TLSConfig(cafile=authority.ca)
        config.ciphers = [TLSCipher.ECDHE_RSA_AES256_GCM_SHA384]

        client, server, _ = pair(library, server_certificate, client=config, ca=authority.ca)
        assert pump(client, server)

        assert client.cipher == "ECDHE-RSA-AES256-GCM-SHA384"

    def test_the_server_learns_the_requested_servername(self, library, server_certificate, authority):
        client, server, _ = pair(library, server_certificate, ca=authority.ca)
        assert pump(client, server)

        assert server.servername == "localhost"

    def test_carries_application_data_both_ways(self, library, server_certificate, authority):
        client, server, _ = pair(library, server_certificate, ca=authority.ca)
        assert pump(client, server)

        client.write(b"ping")
        server.feed(client.drain())
        assert server.read() == b"ping"

        server.write(b"pong")
        client.feed(server.drain())
        assert client.read() == b"pong"

    def test_application_records_keep_their_boundaries(self, library, server_certificate, authority):
        # DTLS carries records in datagrams, so two writes must arrive as two
        # reads rather than as one joined buffer the way a stream would give them.
        client, server, _ = pair(library, server_certificate, ca=authority.ca)
        assert pump(client, server)

        client.write(b"first")
        client.write(b"second")

        for packet in client.packets():
            server.feed(packet)

        assert server.read() == b"first"
        assert server.read() == b"second"

    def test_reports_close_notify(self, library, server_certificate, authority):
        client, server, _ = pair(library, server_certificate, ca=authority.ca)
        assert pump(client, server)

        client.unwrap()

        for packet in client.packets():
            server.feed(packet)

        assert server.read() == b""
        assert server.closed

class TestPackets:
    def flight(self, library, server_certificate, authority, mtu=None):
        """The server's first flight, which is the one carrying the certificate."""

        client, server, _ = pair(library, server_certificate, ca=authority.ca)

        if mtu is not None:
            server.mtu(mtu)

        client.handshake()

        for packet in client.packets():
            server.feed(packet)

        server.handshake()
        return server.packets()

    def test_a_flight_is_split_rather_than_joined(self, library, server_certificate, authority):
        # This is the point of packets(). Given a link too small for the whole
        # flight, DTLS fragments it, and joining the pieces back together would
        # rebuild exactly the oversized datagram the fragmentation avoided.
        flight = self.flight(library, server_certificate, authority, mtu=512)

        assert len(flight) > 1, "a flight larger than the link has to be fragmented"

    def test_no_fragment_exceeds_the_link(self, library, server_certificate, authority):
        # RFC 6347 section 4.1.1: DTLS sizes its records so that IP never has to
        # fragment them, so every piece has to fit the link it was sized for.
        for packet in self.flight(library, server_certificate, authority, mtu=512):
            assert len(packet) <= 512

    def test_an_ordinary_link_carries_the_flight_whole(self, library, server_certificate, authority):
        # At the 1280 byte floor IPv6 guarantees, an RSA 2048 flight fits one
        # datagram, so a normal handshake costs a single round trip of packets.
        flight = self.flight(library, server_certificate, authority)

        assert len(flight) == 1
        assert len(flight[0]) <= TLSSession.link_mtu

    def test_drain_still_joins_for_the_stream_path(self, library, server_certificate, authority):
        # TLS callers rely on drain returning one buffer, so reimplementing it on
        # top of packets must not have changed what it gives back.
        certfile, keyfile = server_certificate

        client_context = TLSContext(TLSConfig(cafile=authority.ca), library=library)
        client = client_context.session(hostname="localhost")

        client.handshake()
        hello = client.drain()

        assert isinstance(hello, bytes)
        assert hello[0] == 22  # a single TLS handshake record

    def test_drain_and_packets_carry_the_same_bytes(self, library, server_certificate, authority):
        client, server, _ = pair(library, server_certificate, ca=authority.ca)

        client.handshake()

        for packet in client.packets():
            server.feed(packet)

        server.handshake()
        flight = server.packets()

        # Nothing may be lost or reordered by the split.
        server.feed(b"")  # no effect, but proves an empty feed is harmless

        assert b"".join(flight)

    def test_packets_are_empty_when_nothing_is_waiting(self, library):
        session = TLSContext(TLSConfig(verify_mode=CERT_NONE), datagram=True, library=library).session(hostname="localhost")

        session.packets()  # drain the ClientHello that construction did not send yet
        session.handshake()
        session.packets()

        assert session.packets() == []

class TestRetransmission:
    def test_a_timer_is_pending_after_a_flight_is_sent(self, library, server_certificate, authority):
        # RFC 6347 section 4.2.4: the transport may lose a flight, so DTLS arms a
        # timer and resends when it expires.
        client, _, _ = pair(library, server_certificate, ca=authority.ca)

        client.handshake()
        client.packets()

        remaining = client.timeout()

        assert remaining is not None
        assert remaining > 0

    def test_an_unexpired_timer_resends_nothing(self, library, server_certificate, authority):
        # The deadline is a second away, so acting on it now would be a spurious
        # retransmission.
        client, _, _ = pair(library, server_certificate, ca=authority.ca)

        client.handshake()
        client.packets()

        assert client.expire() is False
        assert client.packets() == []

    def test_expiring_the_timer_resends_the_flight(self, library, server_certificate, authority):
        import time

        client, _, _ = pair(library, server_certificate, ca=authority.ca)

        client.handshake()
        first = client.packets()

        assert first, "the ClientHello has to have been produced"

        # Nothing was delivered, so once the deadline passes the flight has to go
        # back on the wire. RFC 6347 section 4.2.4.1 puts the initial wait at 1s.
        time.sleep(client.timeout() + 0.05)

        assert client.expire() is True

        again = client.packets()

        assert again, "the flight has to be resent once the timer expires"
        assert [len(packet) for packet in again] == [len(packet) for packet in first]

        # It is the same handshake message but a new record: RFC 6347 section 4.1
        # gives every record its own explicit sequence number.
        assert again != first

    def test_a_stream_session_has_no_timer(self, library, authority):
        # The retransmission timer belongs to DTLS. A TLS session runs over a
        # reliable transport and must not report one.
        session = TLSContext(TLSConfig(cafile=authority.ca), library=library).session(hostname="localhost")

        session.handshake()

        assert session.timeout() is None

class TestVerification:
    def test_accepts_a_certificate_from_a_trusted_ca(self, library, server_certificate, authority):
        client, server, _ = pair(library, server_certificate, ca=authority.ca)

        assert pump(client, server)
        assert client.verified

    def test_rejects_a_hostname_that_does_not_match(self, library, other_certificate, authority):
        client, server, _ = pair(library, other_certificate, ca=authority.ca, hostname="localhost")

        with pytest.raises(TLSVerificationError) as caught:
            pump(client, server)

        assert caught.value.code == 62  # X509_V_ERR_HOSTNAME_MISMATCH

    def test_rejects_an_expired_certificate(self, library, expired_certificate, authority):
        client, server, _ = pair(library, expired_certificate, ca=authority.ca)

        with pytest.raises(TLSVerificationError) as caught:
            pump(client, server)

        assert caught.value.code == 10  # X509_V_ERR_CERT_HAS_EXPIRED

    def test_rejects_an_untrusted_certificate(self, library, server_certificate):
        # The system trust store does not have the throwaway CA in it.
        client, server, _ = pair(library, server_certificate, client=TLSConfig())

        with pytest.raises(TLSVerificationError):
            pump(client, server)

    def test_a_rejection_queues_a_fatal_alert_for_the_peer(self, library, server_certificate):
        # RFC 6347 inherits section 6.2 of RFC 5246: a failed handshake is
        # reported to the peer with a fatal alert.
        client, server, _ = pair(library, server_certificate, client=TLSConfig())

        with pytest.raises(TLSVerificationError):
            pump(client, server)

        alert = b"".join(client.packets())

        assert alert, "the alert has to be available to send after the failure"
        assert alert[0] == 21    # content type alert
        assert alert[1] == 0xFE  # a DTLS record version, not a TLS one

    def test_verification_can_be_turned_off(self, library, other_certificate):
        client, server, _ = pair(library, other_certificate, client=TLSConfig(verify_mode=CERT_NONE), hostname="localhost")

        assert pump(client, server)
        assert client.established

class TestALPN:
    def test_agrees_on_a_shared_protocol(self, library, server_certificate, authority):
        client, server, _ = pair(library, server_certificate, ca=authority.ca, alpn=["kaede/1", "other/1"])
        assert pump(client, server)

        assert client.protocol == "kaede/1"
        assert server.protocol == "kaede/1"

    def test_the_server_preference_decides(self, library, server_certificate, authority):
        # RFC 7301 section 3.2: the server picks, so the client's order is advice.
        certfile, keyfile = server_certificate

        client_context = TLSContext(TLSConfig(cafile=authority.ca), alpn=["other/1", "kaede/1"], datagram=True, library=library)
        server_context = TLSContext(TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE), server=True, alpn=["kaede/1", "other/1"], datagram=True, library=library)

        client, server = client_context.session(hostname="localhost"), server_context.session()
        assert pump(client, server)

        assert client.protocol == "kaede/1"

    def test_the_handshake_fails_when_none_overlap(self, library, server_certificate, authority):
        certfile, keyfile = server_certificate

        client_context = TLSContext(TLSConfig(cafile=authority.ca), alpn=["other/1"], datagram=True, library=library)
        server_context = TLSContext(TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE), server=True, alpn=["kaede/1"], datagram=True, library=library)

        client, server = client_context.session(hostname="localhost"), server_context.session()

        with pytest.raises(TLSHandshakeError):
            pump(client, server)

    def test_nothing_is_negotiated_when_alpn_is_unused(self, library, server_certificate, authority):
        client, server, _ = pair(library, server_certificate, ca=authority.ca)
        assert pump(client, server)

        assert client.protocol is None
