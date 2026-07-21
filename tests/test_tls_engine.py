import gc
import sys

from ssl import CERT_NONE, CERT_REQUIRED

import pytest

from kaede.tls import TLSVersion, TLSGroup, TLSCipher, TLSConfig
from kaede.tls.openssl import OpenSSL, TLSContext, TLSSession, ALPN, Protocol, Control
from kaede.tls.errors import TLSConfigError, TLSHandshakeError, TLSVerificationError, TLSLibraryError, TLSECHError
from kaede.tls.helpers.ech import ECHConfigList, ECHStatus

# The two sessions are wired to each other through their memory BIOs, so a full
# RFC 8446 handshake is exercised without any socket being involved.

@pytest.fixture(scope="module")
def library():
    return OpenSSL()

def pump(client: TLSSession, server: TLSSession, rounds: int = 20) -> bool:
    """Carry bytes between two sessions until both handshakes complete."""

    for _ in range(rounds):
        done = client.handshake()
        server.feed(client.drain())

        done = server.handshake() and done
        client.feed(server.drain())

        if done:
            # Let any remaining post-handshake records reach the peer.
            server.feed(client.drain())
            client.feed(server.drain())
            return True

    return False

def pair(library, server_certificate, *, client=None, server=None, hostname="localhost", alpn=None, ca=None, ech=None):
    certfile, keyfile = server_certificate

    client = client or TLSConfig()
    server = server or TLSConfig()

    server.certfile, server.keyfile = certfile, keyfile
    server.verify_mode = CERT_NONE

    if ca is not None:
        client.cafile = ca

    client_context = TLSContext(client, server=False, alpn=alpn, library=library)
    server_context = TLSContext(server, server=True, alpn=alpn, library=library)

    return client_context.session(hostname=hostname, ech=ech), server_context.session(), (client_context, server_context)

class TestLibrary:
    def test_reports_a_supported_version(self, library):
        assert library.version_num() >= OpenSSL.minimum_version
        assert library.version(0).decode().startswith("OpenSSL")

    def test_binds_every_function_it_declares(self, library):
        for name in ("handshake", "read", "write", "ctrl", "context_ctrl", "bio_read", "bio_write"):
            function = getattr(library, name)

            # An unbound function defaults to returning c_int, which truncates
            # pointers. Every one must have been given an explicit signature.
            assert function.argtypes is not None, name

class TestConstants:
    def test_protocol_numbers_match_the_tls_wire_versions(self):
        # RFC 8446 appendix B.1: TLS 1.2 is 0x0303 and TLS 1.3 is 0x0304.
        assert Protocol.number(TLSVersion.TLSv1_0) == 0x0301
        assert Protocol.number(TLSVersion.TLSv1_1) == 0x0302
        assert Protocol.number(TLSVersion.TLSv1_2) == 0x0303
        assert Protocol.number(TLSVersion.TLSv1_3) == 0x0304

    def test_alpn_round_trips_through_the_wire_format(self):
        # RFC 7301 section 3.1: each name is preceded by its one byte length.
        assert ALPN.pack(["h2", "http/1.1"]) == b"\x02h2\x08http/1.1"
        assert ALPN.unpack(b"\x02h2\x08http/1.1") == ["h2", "http/1.1"]

    def test_alpn_rejects_an_unencodable_name(self):
        with pytest.raises(TLSConfigError):
            ALPN.pack([""])

        with pytest.raises(TLSConfigError):
            ALPN.pack(["x" * 256])

class TestContext:
    def test_builds_a_client_context(self, library):
        assert TLSContext(TLSConfig(), library=library).pointer

    def test_builds_a_server_context(self, library, server_certificate):
        certfile, keyfile = server_certificate
        config = TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE)

        assert TLSContext(config, server=True, library=library).pointer

    def test_rejects_an_unknown_group(self, library):
        config = TLSConfig()
        config.groups = [TLSGroup.X25519]
        config.groups[0] = TLSGroup.X25519  # sanity: the enum value is what is sent

        # A group OpenSSL does not know must be refused rather than ignored.
        class Unknown:
            value = "not-a-real-group"

        config.groups = [Unknown()]

        with pytest.raises(TLSConfigError):
            TLSContext(config, library=library)

    def test_rejects_a_missing_certificate(self, library):
        config = TLSConfig(certfile="/nonexistent/certificate.pem", verify_mode=CERT_NONE)

        with pytest.raises(TLSConfigError):
            TLSContext(config, server=True, library=library)

    def test_rejects_a_key_that_does_not_match(self, library, server_certificate, other_certificate):
        certfile, _ = server_certificate
        _, keyfile = other_certificate

        with pytest.raises(TLSConfigError):
            TLSContext(TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE), server=True, library=library)

class TestHandshake:
    def test_completes_and_agrees_on_the_parameters(self, library, server_certificate, authority):
        client, server, _ = pair(library, server_certificate, ca=authority.ca)

        assert pump(client, server)
        assert client.established and server.established

        assert client.version == server.version
        assert client.cipher == server.cipher

    def test_negotiates_tls_1_3_by_default(self, library, server_certificate, authority):
        client, server, _ = pair(library, server_certificate, ca=authority.ca)
        assert pump(client, server)

        # TLSConfig offers TLS 1.3 suites and both ends support them.
        assert client.version == "TLSv1.3"

    def test_negotiates_a_post_quantum_group(self, library, server_certificate, authority):
        # TLSConfig lists X25519MLKEM768 first, so it must be what is chosen.
        client, server, _ = pair(library, server_certificate, ca=authority.ca)
        assert pump(client, server)

        assert client.group == "X25519MLKEM768"
        assert client.group == server.group

    def test_honours_a_restricted_group_list(self, library, server_certificate, authority):
        config = TLSConfig(cafile=authority.ca)
        config.groups = [TLSGroup.X25519]

        client, server, _ = pair(library, server_certificate, client=config, ca=authority.ca)
        assert pump(client, server)

        assert client.group == "x25519"

    def test_honours_a_minimum_version_of_tls_1_2(self, library, server_certificate, authority):
        config = TLSConfig(cafile=authority.ca, minimum_version=TLSVersion.TLSv1_2)
        config.ciphers = [TLSCipher.ECDHE_RSA_AES256_GCM_SHA384]  # no TLS 1.3 suites offered

        client, server, _ = pair(library, server_certificate, client=config, ca=authority.ca)
        assert pump(client, server)

        assert client.version == "TLSv1.2"

    def test_only_tls_1_3_is_offered_when_only_suites_are_configured(self, library, server_certificate, authority):
        config = TLSConfig(cafile=authority.ca, minimum_version=TLSVersion.TLSv1_2)
        config.ciphers = [TLSCipher.TLS_AES_128_GCM_SHA256]  # no TLS 1.2 ciphers offered

        client, server, _ = pair(library, server_certificate, client=config, ca=authority.ca)
        assert pump(client, server)

        assert client.version == "TLSv1.3"
        assert client.cipher == "TLS_AES_128_GCM_SHA256"

    def test_a_configuration_without_ciphers_is_rejected(self, library):
        config = TLSConfig()
        config.ciphers = []

        with pytest.raises(TLSConfigError):
            TLSContext(config, library=library)

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

    def test_carries_a_payload_larger_than_one_record(self, library, server_certificate, authority):
        # A TLS record holds at most 16384 bytes, so this must be split and rejoined.
        payload = bytes(range(256)) * 400  # 100 KiB

        client, server, _ = pair(library, server_certificate, ca=authority.ca)
        assert pump(client, server)

        sent = 0
        while sent < len(payload):
            sent += client.write(payload[sent:])

        server.feed(client.drain())

        received = b""
        while len(received) < len(payload):
            chunk = server.read()
            if not chunk:
                break
            received += chunk

        assert received == payload

    def test_reports_close_notify(self, library, server_certificate, authority):
        client, server, _ = pair(library, server_certificate, ca=authority.ca)
        assert pump(client, server)

        client.unwrap()
        server.feed(client.drain())

        assert server.read() == b""
        assert server.closed

class TestVerification:
    def test_accepts_a_certificate_from_a_trusted_ca(self, library, server_certificate, authority):
        client, server, _ = pair(library, server_certificate, ca=authority.ca)

        assert pump(client, server)
        assert client.verified

    def test_rejects_an_untrusted_certificate(self, library, server_certificate):
        # No CA file, so the throwaway CA is not trusted.
        config = TLSConfig(cafile="/nonexistent/ca.pem")

        with pytest.raises(TLSConfigError):
            pair(library, server_certificate, client=config)

    def test_rejects_a_hostname_that_does_not_match(self, library, other_certificate, authority):
        # The certificate is valid and trusted, but issued for another name.
        client, server, _ = pair(library, other_certificate, ca=authority.ca, hostname="localhost")

        with pytest.raises(TLSVerificationError) as caught:
            pump(client, server)

        assert caught.value.code == 62  # X509_V_ERR_HOSTNAME_MISMATCH

    def test_rejects_an_expired_certificate(self, library, expired_certificate, authority):
        client, server, _ = pair(library, expired_certificate, ca=authority.ca)

        with pytest.raises(TLSVerificationError) as caught:
            pump(client, server)

        assert caught.value.code == 10  # X509_V_ERR_CERT_HAS_EXPIRED

    def test_a_rejection_queues_a_fatal_alert_for_the_peer(self, library, server_certificate):
        # RFC 8446 section 6.2: a failed handshake is reported to the peer with
        # a fatal alert, so those bytes must be waiting to be sent afterwards.
        config = TLSConfig()  # the test CA is not in the system trust store

        client, server, _ = pair(library, server_certificate, client=config)

        with pytest.raises(TLSVerificationError):
            pump(client, server)

        alert = client.drain()

        assert alert, "the alert has to be available to send after the failure"
        assert alert[0] == 21   # content type alert, RFC 8446 appendix B.1
        assert alert[5] == 2    # fatal, RFC 8446 appendix B.2
        assert alert[6] == 48   # unknown_ca

    def test_verification_can_be_turned_off(self, library, other_certificate):
        config = TLSConfig(verify_mode=CERT_NONE)

        client, server, _ = pair(library, other_certificate, client=config, hostname="localhost")

        assert pump(client, server)
        assert client.established

class TestALPN:
    def test_agrees_on_a_shared_protocol(self, library, server_certificate, authority):
        client, server, _ = pair(library, server_certificate, ca=authority.ca, alpn=["h2", "http/1.1"])
        assert pump(client, server)

        assert client.protocol == "h2"
        assert server.protocol == "h2"

    def test_the_server_preference_decides(self, library, server_certificate, authority):
        # RFC 7301 section 3.2: the server selects the protocol it most prefers
        # among those the client offered, so the client's order does not decide.
        certfile, keyfile = server_certificate

        client_context = TLSContext(TLSConfig(cafile=authority.ca), alpn=["http/1.1", "h2"], library=library)
        server_context = TLSContext(TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE), server=True, alpn=["h2", "http/1.1"], library=library)

        client, server = client_context.session(hostname="localhost"), server_context.session()
        assert pump(client, server)

        assert client.protocol == "h2"
        assert server.protocol == "h2"

    def test_the_handshake_fails_when_none_overlap(self, library, server_certificate, authority):
        # RFC 7301 section 3.2: with no protocol in common the server shall send
        # a fatal no_application_protocol alert rather than continue.
        certfile, keyfile = server_certificate

        client_context = TLSContext(TLSConfig(cafile=authority.ca), alpn=["http/1.1"], library=library)
        server_context = TLSContext(TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE), server=True, alpn=["h2"], library=library)

        client, server = client_context.session(hostname="localhost"), server_context.session()

        with pytest.raises(TLSHandshakeError):
            pump(client, server)

    def test_nothing_is_negotiated_when_alpn_is_unused(self, library, server_certificate, authority):
        client, server, _ = pair(library, server_certificate, ca=authority.ca)
        assert pump(client, server)

        assert client.protocol is None

class TestClientCertificatePolicy:
    def test_the_default_verify_mode_depends_on_the_role(self):
        # RFC 8446 4.3.2: client authentication is optional. The safe default is
        # a client that checks the server and a server that does not demand a
        # certificate from the client.
        config = TLSConfig()

        assert config.verification(server=False) == CERT_REQUIRED
        assert config.verification(server=True) == CERT_NONE

    def test_a_default_server_does_not_demand_a_client_certificate(self, library, server_certificate, authority):
        certfile, keyfile = server_certificate

        server_context = TLSContext(TLSConfig(certfile=certfile, keyfile=keyfile), server=True, library=library)
        client_context = TLSContext(TLSConfig(cafile=authority.ca), library=library)

        client, server = client_context.session(hostname="localhost"), server_context.session()

        assert pump(client, server)
        assert client.established and server.established

    def test_a_server_can_still_require_a_client_certificate(self, library, server_certificate, authority):
        # An explicit CERT_REQUIRED is mutual TLS, so a client that offers no
        # certificate has to be turned away.
        certfile, keyfile = server_certificate

        server_context = TLSContext(TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_REQUIRED, cafile=authority.ca), server=True, library=library)
        client_context = TLSContext(TLSConfig(cafile=authority.ca), library=library)

        client, server = client_context.session(hostname="localhost"), server_context.session()

        with pytest.raises(TLSHandshakeError):
            pump(client, server)

class TestHostnameRequirement:
    def test_a_verifying_client_without_a_hostname_is_refused(self, library):
        # RFC 8446 4.4.2: with no name to check the certificate against, a
        # verifying client would accept any certificate a trusted CA signed.
        context = TLSContext(TLSConfig(), library=library)

        with pytest.raises(TLSConfigError):
            context.session()

    def test_an_unverified_client_may_omit_the_hostname(self, library):
        context = TLSContext(TLSConfig(verify_mode=CERT_NONE), library=library)

        assert context.session().pointer

class TestServerName:
    def test_a_trailing_dot_is_stripped_from_the_servername(self, library, server_certificate, authority):
        # RFC 6066 3: the SNI host_name is carried without a trailing dot, and
        # the certificate check must succeed all the same.
        client, server, _ = pair(library, server_certificate, ca=authority.ca, hostname="localhost.")

        assert pump(client, server)
        assert server.servername == "localhost"

    def test_ascii_names_pass_through_unchanged(self):
        assert TLSSession.identity("example.com") == b"example.com"

    def test_an_internationalized_name_becomes_its_a_label(self):
        # RFC 6066 3 / RFC 5890: an IDN travels as its ASCII A-label (punycode).
        assert TLSSession.identity("bücher.example") == b"xn--bcher-kva.example"

    def test_an_ip_literal_passes_through(self):
        assert TLSSession.identity("192.0.2.1") == b"192.0.2.1"

class TestClosure:
    def test_a_clean_close_is_not_flagged_as_truncated(self, library, server_certificate, authority):
        client, server, _ = pair(library, server_certificate, ca=authority.ca)
        assert pump(client, server)

        server.unwrap()
        client.feed(server.drain())

        assert client.read() == b""
        assert client.closed and not client.truncated

    def test_a_transport_end_without_close_notify_is_truncation(self, library, server_certificate, authority):
        # RFC 8446 6.1: a transport that ends before close_notify means the data
        # may have been cut short, which must be distinguishable from a clean end.
        client, server, _ = pair(library, server_certificate, ca=authority.ca)
        assert pump(client, server)

        client.eof()  # the peer vanished: no more bytes, and no close_notify

        assert client.read() == b""
        assert client.closed and client.truncated

class TestCipherCatalogue:
    def test_no_anonymous_or_null_suite_is_offered(self):
        # A secure-transport library must expose no suite that authenticates no
        # one (ADH/AECDH) or encrypts nothing (NULL).
        for cipher in TLSCipher:
            name = cipher.value.upper()

            assert not name.startswith(("ADH-", "AECDH-")), name
            assert "NULL" not in name, name

    def test_an_anonymous_suite_cannot_be_resolved_by_name(self):
        with pytest.raises(KeyError):
            TLSCipher.from_name("ADH-AES128-SHA")

    def test_the_server_cipher_preference_decides_in_tls_1_2(self, library, server_certificate, authority):
        # RFC 9325 recommends the server, not the client, decides the cipher. The
        # two ends list the same two suites in opposite orders, so only the
        # server's order being honoured explains the outcome.
        certfile, keyfile = server_certificate

        client_config = TLSConfig(cafile=authority.ca, minimum_version=TLSVersion.TLSv1_2)
        client_config.ciphers = [TLSCipher.ECDHE_RSA_AES128_GCM_SHA256, TLSCipher.ECDHE_RSA_AES256_GCM_SHA384]

        server_config = TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE, minimum_version=TLSVersion.TLSv1_2)
        server_config.ciphers = [TLSCipher.ECDHE_RSA_AES256_GCM_SHA384, TLSCipher.ECDHE_RSA_AES128_GCM_SHA256]

        client_context = TLSContext(client_config, server=False, library=library)
        server_context = TLSContext(server_config, server=True, library=library)

        client, server = client_context.session(hostname="localhost"), server_context.session()
        assert pump(client, server)

        assert client.version == "TLSv1.2"
        assert client.cipher == "ECDHE-RSA-AES256-GCM-SHA384"

class TestConstructionFailure:
    # A TLSContext frees its native context in __del__. If construction fails
    # before the context exists (for instance OpenSSL is too old and the binding
    # layer raises), __del__ still runs while the object is collected, so the
    # attributes it touches must already exist or it would raise a second,
    # confusing error that masks the real one.

    def test_a_failed_construction_is_collected_cleanly(self, monkeypatch):
        def refuse(self, **kwargs):
            raise TLSLibraryError("simulated: this OpenSSL is too old")

        monkeypatch.setattr(OpenSSL, "__init__", refuse)

        captured = []
        monkeypatch.setattr(sys, "unraisablehook", lambda unraisable: captured.append(unraisable))

        with pytest.raises(TLSLibraryError):
            TLSContext()

        gc.collect()
        assert not captured, f"__del__ raised while collecting a half-built TLSContext: {[str(item.exc_value) for item in captured]}"

class TestECHConfigList:
    def test_parses_the_public_name_out_of_a_real_configlist(self, ech_keys):
        configs = ECHConfigList.parse(ech_keys.configlist)

        assert len(configs) == 1
        assert configs[0].version == ECHConfigList.RFC9849_VERSION
        assert configs[0].public_name == ech_keys.public_name

    def test_rejects_an_empty_value(self):
        with pytest.raises(TLSConfigError):
            ECHConfigList.parse(b"")

    def test_rejects_a_wrong_length_prefix(self, ech_keys):
        raw = ech_keys.configlist

        with pytest.raises(TLSConfigError):
            ECHConfigList.parse(raw[:1] + bytes([raw[1] + 1]) + raw[2:])

    def test_rejects_a_truncated_config(self, ech_keys):
        with pytest.raises(TLSConfigError):
            ECHConfigList.parse(ech_keys.configlist[:-1])

    def test_skips_an_unsupported_version_and_then_has_nothing_left(self):
        # A 2-byte outer length, one ECHConfig entry tagged with an unknown
        # version and an empty body: structurally valid, but nothing usable.
        body = (0xdead).to_bytes(2, "big") + (0).to_bytes(2, "big")
        raw = len(body).to_bytes(2, "big") + body

        with pytest.raises(TLSConfigError):
            ECHConfigList.parse(raw)

class TestECH:
    def test_a_client_and_server_agree_on_the_encrypted_hello(self, library, server_certificate, authority, ech_keys):
        server = TLSConfig(echfile=ech_keys.pemfile)
        client, server_session, _ = pair(library, server_certificate, server=server, ca=authority.ca, ech=ech_keys.configlist)

        assert pump(client, server_session)
        assert client.verified

        status = client.ech_status
        assert status.succeeded
        assert status.inner_sni == "localhost"
        assert status.outer_sni == ech_keys.public_name

        assert server_session.servername == "localhost"

    def test_a_session_without_ech_reports_no_status(self, library, server_certificate, authority):
        client, server, _ = pair(library, server_certificate, ca=authority.ca)
        assert pump(client, server)

        assert client.ech_status is None
        assert client.ech_retry_config is None

    def test_a_server_unaware_of_ech_does_not_silently_downgrade(self, library, server_certificate, ech_keys):
        # RFC 9849 section 6.1.3: a client must not fall back to revealing the
        # real name in cleartext just because ECH went unanswered, so a server
        # that never heard of ECH cannot complete the handshake as if nothing
        # had happened - the connection has to fail rather than downgrade.
        client_config = TLSConfig(verify_mode=CERT_NONE)
        client, server_session, _ = pair(library, server_certificate, client=client_config, ech=ech_keys.configlist, hostname="localhost")

        with pytest.raises(TLSHandshakeError):
            pump(client, server_session)

        # And the server, having never understood the extension, only ever
        # saw the cleartext outer name - the real "localhost" name never reached it.
        assert server_session.servername == ech_keys.public_name

    def test_a_corrupted_config_is_rejected_with_a_retry_config(self, library, server_certificate, ech_keys):
        # No certificate authority is involved here: with verification off on
        # both ends, OpenSSL still hands back a fresh ECHConfigList to retry
        # with, which is exactly the "fix yourself and reconnect" signal a
        # client that hit a stale or corrupted config needs.
        corrupted = bytearray(ech_keys.configlist)
        corrupted[20] ^= 0xff  # deep inside the HPKE public key, keeps every length field intact

        server = TLSConfig(verify_mode=CERT_NONE, echfile=ech_keys.pemfile)
        client = TLSConfig(verify_mode=CERT_NONE)
        client_session, server_session, _ = pair(library, server_certificate, client=client, server=server, ech=bytes(corrupted))

        with pytest.raises(TLSECHError) as caught:
            pump(client_session, server_session)

        assert caught.value.status.code in (ECHStatus.FAILED_ECH, ECHStatus.FAILED_ECH_BAD_NAME)
        assert caught.value.retry_config  # the server hands back a usable config to retry with
        ECHConfigList.parse(caught.value.retry_config)  # and it is well formed

    def test_echfile_is_rejected_on_a_client_context(self, library):
        with pytest.raises(TLSConfigError):
            TLSContext(TLSConfig(echfile="/nonexistent/ech.pem"), server=False, library=library)

    def test_a_missing_ech_pemfile_is_rejected(self, library, server_certificate):
        certfile, keyfile = server_certificate
        config = TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE, echfile="/nonexistent/ech.pem")

        with pytest.raises(TLSConfigError):
            TLSContext(config, server=True, library=library)

    def test_a_malformed_configlist_is_rejected_before_reaching_openssl(self, library):
        context = TLSContext(TLSConfig(verify_mode=CERT_NONE), library=library)

        with pytest.raises(TLSConfigError):
            context.session(hostname="localhost", ech=b"not a real ECHConfigList")

    def test_ech_requires_openssl_4_0(self, library, monkeypatch, server_certificate, ech_keys):
        # Simulate an OpenSSL older than 4.0, which does not export the ECH API.
        monkeypatch.setattr(library, "set_ech_config_list", None)

        context = TLSContext(TLSConfig(verify_mode=CERT_NONE), library=library)

        with pytest.raises(TLSConfigError):
            context.session(hostname="localhost", ech=ech_keys.configlist)

    def test_echfile_requires_openssl_4_0(self, library, monkeypatch, server_certificate, ech_keys):
        monkeypatch.setattr(library, "echstore_new", None)

        certfile, keyfile = server_certificate
        config = TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE, echfile=ech_keys.pemfile)

        with pytest.raises(TLSConfigError):
            TLSContext(config, server=True, library=library)
