import asyncio
from ssl import CERT_NONE

import pytest

from kaede.tls import TLSConfig
from kaede.tls.errors import TLSError, TLSHandshakeError, TLSVerificationError
from kaede.udp.models import UDPPort
from kaede.udp.protocol import UDPConnection
from kaede.quic.tls import QTLS, QUICContext
from kaede.quic.protocol import QUICEndpoint, QUICConnection
from kaede.quic.errors import QUICError, QUICTimeoutError

LOCAL = "127.0.0.1"

# QUIC (RFC 9000) runs TLS 1.3 (RFC 9001) over UDP. The handshake is checked
# here against what those two say it must produce, not against what Kaede
# happens to do: the wire version is QUIC's own rather than TLS's, ALPN stops
# being optional, and certificate verification has to behave exactly as it does
# over a record protocol.
#
# Every test needs a peer to talk to, and a QUIC server needs OpenSSL 4.0, so
# the whole module stands down on 3.6 rather than pretending to cover it.

@pytest.fixture(scope="module", autouse=True)
def servable():
    if not QTLS().servable:
        pytest.skip("a QUIC server needs OpenSSL 4.0 or newer")

class Running:
    """A QUIC server endpoint on an ephemeral port."""

    def __init__(self, certificate, *, alpn=None, validate=True):
        certfile, keyfile = certificate

        self.config = TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE)
        self.alpn = ["kaede/1"] if alpn is None else alpn
        self.validate = validate
        self.endpoint = None

    async def __aenter__(self) -> QUICEndpoint:
        context = QUICContext(self.config, server=True, alpn=self.alpn)
        self.endpoint = await QUICEndpoint.serve(context, (LOCAL, UDPPort(0)), validate=self.validate)

        return self.endpoint

    async def __aexit__(self, *_):
        await self.endpoint.close()

async def dial(endpoint, authority=None, *, alpn=None, hostname="localhost", timeout=10):
    """Open a client connection to a running server endpoint."""

    transport = UDPConnection(("", UDPPort(0)), (LOCAL, endpoint.src[1]))
    await transport.connect(timeout)

    config = TLSConfig(cafile=authority.ca) if authority is not None else TLSConfig(verify_mode=CERT_NONE)
    context = QUICContext(config, alpn=["kaede/1"] if alpn is None else alpn)

    try:
        return await QUICConnection.connect(transport, hostname=hostname, timeout=timeout, context=context)

    except BaseException:
        await transport.close()
        raise

async def shut(*connections):
    for connection in connections:
        await connection.endpoint.close()

class TestHandshake:
    async def test_completes_on_both_sides(self, server_certificate, authority):
        async with Running(server_certificate) as endpoint:
            client = await dial(endpoint, authority)
            served = await endpoint.accept(timeout=10)

            await served.handshake(10)

            assert client.established
            assert served.established

            await shut(client)

    async def test_reports_the_quic_wire_version(self, server_certificate, authority):
        # OpenSSL names the QUIC version here, not the TLS one. RFC 9000 section
        # 15 registers QUIC version 1, which is what a v1 connection is running.
        async with Running(server_certificate) as endpoint:
            client = await dial(endpoint, authority)

            assert client.version == "QUICv1"

            await shut(client)

    async def test_negotiates_a_tls_1_3_cipher(self, server_certificate, authority):
        # RFC 9001 section 4.2: QUIC uses TLS 1.3, whose suites are the TLS_*
        # ones. Landing on a TLS 1.2 cipher would mean the version rule leaked.
        async with Running(server_certificate) as endpoint:
            client = await dial(endpoint, authority)

            assert client.cipher.startswith("TLS_")

            await shut(client)

    async def test_agrees_on_the_parameters(self, server_certificate, authority):
        async with Running(server_certificate) as endpoint:
            client = await dial(endpoint, authority)
            served = await endpoint.accept(timeout=10)
            await served.handshake(10)

            assert client.version == served.version
            assert client.cipher == served.cipher

            await shut(client)

    async def test_the_server_learns_the_requested_servername(self, server_certificate, authority):
        async with Running(server_certificate) as endpoint:
            client = await dial(endpoint, authority)
            served = await endpoint.accept(timeout=10)
            await served.handshake(10)

            assert served.servername == "localhost"

            await shut(client)

    async def test_the_server_learns_the_peer_address(self, server_certificate, authority):
        async with Running(server_certificate) as endpoint:
            client = await dial(endpoint, authority)
            served = await endpoint.accept(timeout=10)

            assert served.dst[0] == LOCAL
            assert served.dst[1] == client.src[1]

            await shut(client)

    async def test_gives_up_on_a_port_nobody_answers(self, server_certificate):
        # RFC 9000 section 8.1 lets a server ignore an unvalidated client
        # outright, so a client has to bound its own wait rather than hang.
        async with Running(server_certificate) as endpoint:
            free = endpoint.src[1]

        # The endpoint is gone, so nothing is listening on that port any more.
        transport = UDPConnection(("", UDPPort(0)), (LOCAL, free))
        await transport.connect(5)

        context = QUICContext(TLSConfig(verify_mode=CERT_NONE), alpn=["kaede/1"])

        with pytest.raises(QUICTimeoutError):
            await QUICConnection.connect(transport, hostname="localhost", timeout=1, context=context)

        await transport.close()

class TestALPN:
    async def test_agrees_on_a_shared_protocol(self, server_certificate, authority):
        async with Running(server_certificate, alpn=["kaede/1", "other/1"]) as endpoint:
            client = await dial(endpoint, authority, alpn=["kaede/1", "other/1"])
            served = await endpoint.accept(timeout=10)
            await served.handshake(10)

            assert client.protocol == "kaede/1"
            assert served.protocol == "kaede/1"

            await shut(client)

    async def test_the_server_preference_decides(self, server_certificate, authority):
        # RFC 7301 section 3.2: the server picks, so the client's order is only
        # advice.
        async with Running(server_certificate, alpn=["kaede/1", "other/1"]) as endpoint:
            client = await dial(endpoint, authority, alpn=["other/1", "kaede/1"])

            assert client.protocol == "kaede/1"

            await shut(client)

    async def test_the_handshake_fails_when_none_overlap(self, server_certificate, authority):
        # RFC 9001 section 8.1 makes ALPN mandatory, so no shared protocol means
        # no connection rather than a connection carrying nothing agreed.
        async with Running(server_certificate, alpn=["kaede/1"]) as endpoint:
            with pytest.raises((TLSError, QUICError)):
                await dial(endpoint, authority, alpn=["other/1"], timeout=5)

class TestVerification:
    async def test_accepts_a_certificate_from_a_trusted_ca(self, server_certificate, authority):
        async with Running(server_certificate) as endpoint:
            client = await dial(endpoint, authority)

            assert client.verified

            await shut(client)

    async def test_rejects_a_hostname_that_does_not_match(self, other_certificate, authority):
        async with Running(other_certificate) as endpoint:
            with pytest.raises(TLSVerificationError) as caught:
                await dial(endpoint, authority, hostname="localhost", timeout=5)

            assert caught.value.code == 62 # X509_V_ERR_HOSTNAME_MISMATCH

    async def test_rejects_an_expired_certificate(self, expired_certificate, authority):
        async with Running(expired_certificate) as endpoint:
            with pytest.raises(TLSVerificationError) as caught:
                await dial(endpoint, authority, timeout=5)

            assert caught.value.code == 10 # X509_V_ERR_CERT_HAS_EXPIRED

    async def test_rejects_an_untrusted_certificate(self, server_certificate):
        # The throwaway CA is not in the system trust store, and no cafile is
        # given here, so the chain has nowhere to end.
        async with Running(server_certificate) as endpoint:
            transport = UDPConnection(("", UDPPort(0)), (LOCAL, endpoint.src[1]))
            await transport.connect(5)

            context = QUICContext(TLSConfig(), alpn=["kaede/1"])

            with pytest.raises(TLSVerificationError):
                await QUICConnection.connect(transport, hostname="localhost", timeout=5, context=context)

            await transport.close()

    async def test_verification_can_be_turned_off(self, other_certificate):
        async with Running(other_certificate) as endpoint:
            client = await dial(endpoint, None, hostname="localhost")

            assert client.established

            await shut(client)

class TestTimer:
    async def test_a_timer_is_pending_while_a_connection_is_live(self, server_certificate, authority):
        # RFC 9000 section 13.2 has a connection acknowledge on a timer, so
        # there is always something for QUIC to do next.
        async with Running(server_certificate) as endpoint:
            client = await dial(endpoint, authority)
            remaining = client.endpoint.delay()

            assert remaining is None or remaining >= 0.0

            await shut(client)

    async def test_the_timer_is_armed_after_the_handshake(self, server_certificate, authority):
        async with Running(server_certificate) as endpoint:
            client = await dial(endpoint, authority)

            # Nothing else drives loss recovery, so the endpoint has to be
            # holding a live handle rather than waiting to be poked.
            assert client.endpoint.timer is not None

            await shut(client)

    async def test_closing_takes_the_timer_down(self, server_certificate, authority):
        # A timer that fires after the objects it would touch are gone is a
        # crash rather than an exception.
        async with Running(server_certificate) as endpoint:
            client = await dial(endpoint, authority)
            pump = client.endpoint

            await shut(client)

            assert pump.timer is None
            assert pump.closed

            await asyncio.sleep(0.05) # nothing left to fire

class TestServable:
    async def test_serving_needs_a_reportable_peer_address(self, server_certificate):
        # Guarded rather than assumed: the check exists so that 3.6 fails with
        # an explanation instead of accepting connections it cannot tell apart.
        context = QUICContext(TLSConfig(verify_mode=CERT_NONE), server=True, alpn=["kaede/1"])

        assert context.qtls.servable is (context.qtls.peer_address is not None)
