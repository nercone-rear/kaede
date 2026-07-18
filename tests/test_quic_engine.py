import ctypes
from ssl import CERT_NONE

import pytest

from kaede.tls import TLSConfig, TLSCipher
from kaede.tls.openssl import VOID_P, TLSContext, Timeval
from kaede.tls.errors import TLSConfigError
from kaede.quic.tls import QTLS, QUICPair, QUICContext, BIOMessage, ShutdownArgs, CloseInfo, Stream, Incoming, Listener, Shutdown, Close, Capability

# QUIC (RFC 9000) carries TLS 1.3 (RFC 9001) over UDP. What that costs the TLS
# layer is pinned down here: there is no protocol version to negotiate, only the
# TLS 1.3 suites can apply, ALPN stops being optional, and the datagrams have to
# be carried across a pair of memory BIOs that exchange their addresses in
# transit. None of these are read off Kaede's behaviour; they are the RFCs and
# the documented contract of the OpenSSL calls involved.

@pytest.fixture(scope="module")
def qtls():
    library = QTLS()

    if not library.available:
        pytest.skip("this OpenSSL was built without QUIC support")

    return library

def read(qtls, half, limit: int = 2048):
    """Take one datagram off a BIO, reporting both addresses it carries."""

    buffer = ctypes.create_string_buffer(limit)
    peer, local = qtls.library.address_new(), qtls.library.address_new()

    message = BIOMessage(ctypes.cast(buffer, VOID_P), limit, peer, local, 0)
    done = ctypes.c_size_t(0)

    taken = qtls.receive(half, ctypes.byref(message), ctypes.sizeof(BIOMessage), 1, 0, ctypes.byref(done))
    found = (buffer.raw[:message.length], qtls.where(peer), qtls.where(local)) if taken == 1 and done.value else None

    qtls.library.address_free(peer)
    qtls.library.address_free(local)

    return found

def server(certificate, **kwargs) -> TLSConfig:
    certfile, keyfile = certificate
    return TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE, **kwargs)

class TestLibrary:
    def test_quic_is_available(self, qtls):
        assert qtls.available
        assert qtls.client_method is not None

    def test_servable_follows_the_peer_address_call(self, qtls):
        # A server has to know which peer a connection came from. OpenSSL 3.6
        # cannot say, so it is reported as unable to serve rather than serving
        # blind.
        assert qtls.servable is (qtls.peer_address is not None)

class TestStructures:
    def test_the_message_carries_a_datagram_and_two_addresses(self):
        names = [name for name, _ in BIOMessage._fields_]
        assert names == ["data", "length", "peer", "local", "flags"]

    def test_the_message_is_the_size_of_its_fields(self):
        pointer, size = ctypes.sizeof(VOID_P), ctypes.sizeof(ctypes.c_size_t)
        assert ctypes.sizeof(BIOMessage) == pointer * 3 + size + ctypes.sizeof(ctypes.c_uint64)

    def test_the_shutdown_arguments_are_a_code_and_a_reason(self):
        assert [name for name, _ in ShutdownArgs._fields_] == ["code", "reason"]
        assert ctypes.sizeof(ShutdownArgs) == ctypes.sizeof(ctypes.c_uint64) + ctypes.sizeof(VOID_P)

    def test_the_close_information_is_laid_out_in_order(self):
        assert [name for name, _ in CloseInfo._fields_] == ["code", "frame", "reason", "length", "flags"]

    def test_the_timeval_comes_from_the_tls_module(self):
        # Redefining it here would be a second place for the platform dependent
        # layout to be got wrong.
        assert Timeval(sec=1, usec=500000).seconds == 1.5

class TestConstants:
    def test_the_stream_flag_bits_do_not_overlap(self):
        # RFC 9000 section 2.1 has two independent properties, so the bits that
        # carry them must be distinct.
        assert Stream.UNI == 1
        assert Stream.NO_BLOCK == 2
        assert Stream.ADVANCE == 4

    def test_the_stream_type_is_a_pair_of_direction_bits(self):
        assert Stream.TYPE_BIDI == Stream.TYPE_READ | Stream.TYPE_WRITE
        assert Stream.TYPE_NONE == 0

    def test_the_stream_states_are_distinct(self):
        states = [Stream.STATE_NONE, Stream.STATE_OK, Stream.STATE_WRONG_DIR, Stream.STATE_FINISHED, Stream.STATE_RESET_LOCAL, Stream.STATE_RESET_REMOTE, Stream.STATE_CONN_CLOSED]
        assert states == list(range(7))

    def test_the_incoming_policies_are_distinct(self):
        assert [Incoming.AUTO, Incoming.ACCEPT, Incoming.REJECT] == [0, 1, 2]

    def test_the_shutdown_flags_do_not_overlap(self):
        assert [Shutdown.RAPID, Shutdown.NO_STREAM_FLUSH, Shutdown.NO_BLOCK, Shutdown.WAIT_PEER] == [1, 2, 4, 8]

    def test_the_close_flags_do_not_overlap(self):
        assert [Close.LOCAL, Close.TRANSPORT] == [1, 2]

    def test_the_listener_flag_is_the_second_bit(self):
        assert Listener.NO_VALIDATE == 2

    def test_all_capabilities_is_every_bit(self):
        assert Capability.ALL == Capability.HANDLES_SRC | Capability.HANDLES_DST | Capability.PROVIDES_SRC | Capability.PROVIDES_DST
        assert Capability.ALL == 0b1111

class TestAddress:
    @pytest.mark.parametrize("host, port", [("127.0.0.1", 4433), ("0.0.0.0", 0), ("192.0.2.10", 65535), ("::1", 443), ("2001:db8::1", 8443)])
    def test_round_trips(self, qtls, host, port):
        address = qtls.address(host, port)

        try:
            assert qtls.where(address) == (host, port)
        finally:
            qtls.library.address_free(address)

    def test_the_port_is_not_byte_swapped(self, qtls):
        # BIO_ADDR_rawmake wants the port in network byte order. Handing it the
        # host order value sends the first packet to a plausible looking wrong
        # port, which looks exactly like a timeout and nothing like a bug.
        address = qtls.address("127.0.0.1", 4433)

        try:
            assert qtls.where(address)[1] == 4433
            assert qtls.where(address)[1] != 0x5111 # 4433 with its bytes exchanged
        finally:
            qtls.library.address_free(address)

    def test_an_absent_address_reads_as_empty(self, qtls):
        assert qtls.where(None) == ("", 0)

class TestPair:
    def test_both_halves_are_created(self, qtls):
        pair = QUICPair(qtls)

        try:
            assert pair.inner and pair.outer
        finally:
            pair.free()

    def test_the_addresses_are_exchanged_in_transit(self, qtls):
        # This is the whole reason QUICPair exists. A dgram pair hands the peer
        # address over as the local one and the other way about, so a datagram
        # fed in with the sender as its peer has to reach OpenSSL still naming
        # the sender as its peer. Getting this backwards makes a server accept a
        # connection and then stall with nothing reported.
        pair = QUICPair(qtls)
        sender, receiver = qtls.address("10.0.0.1", 1111), qtls.address("10.0.0.2", 2222)

        try:
            assert pair.feed(b"HELLO", peer=sender, local=receiver)

            found = read(qtls, pair.inner)

            assert found is not None, "the datagram has to reach the half OpenSSL reads"

            data, peer, local = found

            assert data == b"HELLO"
            assert peer == ("10.0.0.1", 1111), "the sender has to arrive as the peer"
            assert local == ("10.0.0.2", 2222), "the address it arrived on has to arrive as the local one"
        finally:
            qtls.library.address_free(sender)
            qtls.library.address_free(receiver)
            pair.free()

    def test_an_empty_datagram_is_refused(self, qtls):
        # A dgram pair does not carry zero length datagrams.
        pair = QUICPair(qtls)
        address = qtls.address("10.0.0.1", 1111)

        try:
            assert pair.feed(b"", peer=address, local=address) is False
        finally:
            qtls.library.address_free(address)
            pair.free()

    def test_nothing_is_waiting_on_a_fresh_pair(self, qtls):
        pair = QUICPair(qtls)

        try:
            assert pair.packets() == []
        finally:
            pair.free()

    def test_datagrams_keep_their_boundaries(self, qtls):
        # A datagram transport delivers what it was given, one at a time. Two
        # writes must not arrive joined the way a stream would give them.
        pair = QUICPair(qtls)
        sender, receiver = qtls.address("10.0.0.1", 1111), qtls.address("10.0.0.2", 2222)

        try:
            pair.feed(b"first", peer=sender, local=receiver)
            pair.feed(b"second", peer=sender, local=receiver)

            assert read(qtls, pair.inner)[0] == b"first"
            assert read(qtls, pair.inner)[0] == b"second"
        finally:
            qtls.library.address_free(sender)
            qtls.library.address_free(receiver)
            pair.free()

    def test_freeing_twice_is_harmless(self, qtls):
        pair = QUICPair(qtls)

        pair.free()
        pair.free()

        assert pair.inner is None and pair.outer is None

class TestContext:
    def test_builds_a_client_context(self, qtls):
        assert QUICContext(TLSConfig(verify_mode=CERT_NONE), alpn=["h3"], qtls=qtls).pointer

    def test_builds_a_server_context(self, qtls, server_certificate):
        assert QUICContext(server(server_certificate), server=True, alpn=["h3"], qtls=qtls).pointer

    def test_requires_alpn(self, qtls):
        # RFC 9001 section 8.1: the use of ALPN is mandatory over QUIC.
        with pytest.raises(TLSConfigError):
            QUICContext(TLSConfig(verify_mode=CERT_NONE), qtls=qtls)

    def test_requires_alpn_of_a_server_too(self, qtls, server_certificate):
        with pytest.raises(TLSConfigError):
            QUICContext(server(server_certificate), server=True, qtls=qtls)

    def test_an_empty_alpn_list_is_not_alpn(self, qtls):
        with pytest.raises(TLSConfigError):
            QUICContext(TLSConfig(verify_mode=CERT_NONE), alpn=[], qtls=qtls)

    def test_the_default_configuration_is_accepted(self, qtls):
        # TLSConfig lists both TLS 1.3 suites and TLS 1.2 ciphers. QUIC has to
        # take the first group and quietly leave the second, so that callers
        # need no QUIC specific configuration.
        assert QUICContext(TLSConfig(verify_mode=CERT_NONE), alpn=["h3"], qtls=qtls).pointer

    def test_refuses_a_configuration_without_a_tls_1_3_suite(self, qtls):
        # RFC 9001 section 4.2: QUIC uses TLS 1.3. A configuration offering only
        # the 1.2 ciphers leaves it with no usable cipher at all.
        config = TLSConfig(verify_mode=CERT_NONE)
        config.ciphers = [TLSCipher.ECDHE_RSA_AES128_GCM_SHA256]

        with pytest.raises(TLSConfigError):
            QUICContext(config, alpn=["h3"], qtls=qtls)

    def test_the_same_configuration_is_fine_over_dtls(self, qtls):
        # The mirror of the rule above, and the point of keeping each rule in
        # its own module: DTLS 1.2 can use exactly the ciphers QUIC cannot.
        config = TLSConfig(verify_mode=CERT_NONE)
        config.ciphers = [TLSCipher.ECDHE_RSA_AES128_GCM_SHA256]

        assert TLSContext(config, datagram=True, library=qtls.library).pointer

    def test_a_suite_only_configuration_is_fine_over_quic(self, qtls):
        # The other half of the same mirror: test_dtls_engine rejects this one.
        config = TLSConfig(verify_mode=CERT_NONE)
        config.ciphers = [TLSCipher.TLS_AES_128_GCM_SHA256]

        assert QUICContext(config, alpn=["h3"], qtls=qtls).pointer

    def test_refuses_a_configuration_without_ciphers(self, qtls):
        config = TLSConfig(verify_mode=CERT_NONE)
        config.ciphers = []

        with pytest.raises(TLSConfigError):
            QUICContext(config, alpn=["h3"], qtls=qtls)

    def test_the_minimum_version_is_ignored_rather_than_refused(self, qtls):
        # RFC 9001 section 4.2 leaves no version to choose, and the default
        # TLSConfig asks for a 1.2 floor. Refusing that would make every caller
        # carry a QUIC specific configuration for no gain.
        config = TLSConfig(verify_mode=CERT_NONE)

        assert QUICContext(config, alpn=["h3"], qtls=qtls).pointer

class TestObjects:
    def test_makes_a_client_connection(self, qtls):
        context = QUICContext(TLSConfig(verify_mode=CERT_NONE), alpn=["h3"], qtls=qtls)
        assert context.connection()

    def test_makes_a_listener(self, qtls, server_certificate):
        context = QUICContext(server(server_certificate), server=True, alpn=["h3"], qtls=qtls)
        assert context.listener()

    def test_makes_a_listener_that_skips_address_validation(self, qtls, server_certificate):
        # RFC 9000 section 8.1 lets a server validate an address with Retry
        # before committing to it. Turning it off is a deliberate choice.
        context = QUICContext(server(server_certificate), server=True, alpn=["h3"], qtls=qtls)
        assert context.listener(validate=False)

    def test_refuses_to_make_a_tls_session(self, qtls):
        # TLSContext.session would build a record protocol session with memory
        # BIOs, which is not how a QUIC connection is driven.
        context = QUICContext(TLSConfig(verify_mode=CERT_NONE), alpn=["h3"], qtls=qtls)

        with pytest.raises(TLSConfigError):
            context.session()
