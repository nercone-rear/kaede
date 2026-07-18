from ssl import CERT_NONE

import pytest

from kaede.tls import TLSConfig
from kaede.tls.errors import TLSConfigError, TLSVerificationError
from kaede.udp.models import UDPPort
from kaede.quic import QUICClient, QUICClientConfig, QUICServer, QUICServerConfig, QUICHandler
from kaede.quic.tls import QTLS

LOCAL = "127.0.0.1"

# The client API mirrors UDPClient, with one difference worth stating: RFC 9001
# section 1 leaves QUIC no unencrypted mode, so an unset tls configuration asks
# for the defaults rather than for no TLS, and ALPN is required rather than
# optional (RFC 9001 section 8.1).

@pytest.fixture(scope="module", autouse=True)
def servable():
    if not QTLS().servable:
        pytest.skip("a QUIC server needs OpenSSL 4.0 or newer")

async def upper(connection):
    while True:
        stream = await connection.accept()
        data = await stream.receive()

        await stream.send(data.upper())
        stream.conclude()

class Running:
    """A QUICServer on an ephemeral port."""

    def __init__(self, certificate, *, alpn=None):
        certfile, keyfile = certificate

        config = QUICServerConfig()
        config.tls = TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE)
        config.alpn = ["kaede/1"] if alpn is None else alpn
        config.handshake_timeout = 10

        self.server = QUICServer(config)

    async def __aenter__(self) -> QUICServer:
        await self.server.listen(QUICHandler(upper), [(LOCAL, UDPPort(0))])
        return self.server

    async def __aexit__(self, *_):
        await self.server.close(timeout=3)

def configured(authority, *, alpn=None, hostname="localhost", verify=True) -> QUICClientConfig:
    config = QUICClientConfig(connect_timeout=10)
    config.tls = TLSConfig(cafile=authority.ca) if verify else TLSConfig(verify_mode=CERT_NONE)
    config.alpn = ["kaede/1"] if alpn is None else alpn
    config.hostname = hostname

    return config

async def ask(connection, message: bytes) -> bytes:
    stream = await connection.open()

    await stream.send(message)
    stream.conclude()

    return await stream.receive(timeout=10)

class TestConfiguration:
    def test_requires_alpn(self):
        # RFC 9001 section 8.1: ALPN is mandatory, so a client with none could
        # never agree on anything and is refused while the cause is still clear.
        with pytest.raises(TLSConfigError):
            QUICClient((LOCAL, UDPPort(443)), config=QUICClientConfig())

    def test_an_unset_tls_configuration_means_the_defaults(self):
        # Not "no TLS": QUIC has no such mode. The client has to build a working
        # context from an untouched configuration.
        config = QUICClientConfig()
        config.alpn = ["kaede/1"]

        assert QUICClient((LOCAL, UDPPort(443)), config=config).context.pointer

    def test_the_source_port_defaults_to_ephemeral(self):
        config = QUICClientConfig()
        config.alpn = ["kaede/1"]

        assert QUICClient((LOCAL, UDPPort(443)), config=config).src.dynamic

    def test_a_source_port_can_be_asked_for(self):
        config = QUICClientConfig()
        config.alpn = ["kaede/1"]

        assert QUICClient((LOCAL, UDPPort(443)), UDPPort(51234), config=config).src == 51234

class TestOpening:
    async def test_opens_and_closes_as_a_context_manager(self, server_certificate, authority):
        async with Running(server_certificate) as server:
            async with QUICClient(server.ports[0], config=configured(authority)) as connection:
                assert connection.established
                assert await ask(connection, b"hello") == b"HELLO"

    async def test_the_connection_is_closed_afterwards(self, server_certificate, authority):
        async with Running(server_certificate) as server:
            client = QUICClient(server.ports[0], config=configured(authority))
            connection = await client.open()

            await client.close()

            assert client.connections == []
            assert connection.endpoint.closed

    async def test_opens_more_than_one_connection(self, server_certificate, authority):
        async with Running(server_certificate) as server:
            client = QUICClient(server.ports[0], config=configured(authority))

            try:
                first = await client.open()
                second = await client.open()

                # Each gets its own socket, so they are separate connections
                # rather than two views of one.
                assert first.src[1] != second.src[1]
                assert len(client.connections) == 2

                assert await ask(first, b"one") == b"ONE"
                assert await ask(second, b"two") == b"TWO"

            finally:
                await client.close()

    async def test_the_destination_can_be_given_per_call(self, server_certificate, authority):
        async with Running(server_certificate) as server:
            client = QUICClient((LOCAL, UDPPort(1)), config=configured(authority))

            try:
                connection = await client.open(server.ports[0])
                assert await ask(connection, b"x") == b"X"

            finally:
                await client.close()

    async def test_reports_the_negotiated_protocol(self, server_certificate, authority):
        async with Running(server_certificate) as server:
            async with QUICClient(server.ports[0], config=configured(authority)) as connection:
                assert connection.protocol == "kaede/1"
                assert connection.version == "QUICv1"

class TestVerification:
    async def test_verifies_the_certificate_by_default(self, server_certificate, authority):
        async with Running(server_certificate) as server:
            async with QUICClient(server.ports[0], config=configured(authority)) as connection:
                assert connection.verified

    async def test_refuses_a_name_the_certificate_does_not_carry(self, other_certificate, authority):
        async with Running(other_certificate) as server:
            client = QUICClient(server.ports[0], config=configured(authority))

            with pytest.raises(TLSVerificationError):
                await client.open()

            await client.close()

    async def test_the_transport_is_not_left_behind_when_opening_fails(self, other_certificate, authority):
        # A failed handshake still has a UDP socket under it, and nothing else
        # is going to close it.
        async with Running(other_certificate) as server:
            client = QUICClient(server.ports[0], config=configured(authority))

            with pytest.raises(TLSVerificationError):
                await client.open()

            assert client.connections == []

            await client.close()
