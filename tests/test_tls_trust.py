import ssl
from ssl import CERT_NONE

import pytest

from kaede.tls import TLSConfig
from kaede.tls.errors import TLSConfigError, TLSVerificationError
from kaede.tls.openssl import TLSContext
from kaede.tcp import TCPPort, TCPClient, TCPServer, TCPServerConfig, TCPHandler
from kaede.tcp.api.client import TCPClientConfig

LOCAL = "127.0.0.1"

class Running:
    """A TLS enabled TCPServer on an ephemeral port."""

    def __init__(self, on_connection, certificate):
        certfile, keyfile = certificate

        config = TCPServerConfig()
        config.tls = TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE)

        self.server = TCPServer(config)
        self.handler = TCPHandler(on_connection)

    async def __aenter__(self):
        await self.server.listen(self.handler, [(LOCAL, TCPPort(0))])
        return self.server

    async def __aexit__(self, *_):
        await self.server.close(timeout=2)

def client(server, tls):
    config = TCPClientConfig(connect_timeout=5)
    config.tls = tls
    config.hostname = "localhost"

    return TCPClient(server.ports[0], config=config)

async def upper(connection):
    data = await connection.receive_exactly(5)
    await connection.send(data.upper())

async def exchange(server, tls):
    async with client(server, tls) as connection:
        assert connection.verified
        await connection.send(b"hello")
        assert await connection.receive_exactly(5) == b"HELLO"

class TestCAData:
    async def test_a_pem_string_is_trusted(self, server_certificate, authority):
        with open(authority.ca) as f:
            pem = f.read()

        async with Running(upper, server_certificate) as server:
            await exchange(server, TLSConfig(cadata=pem))

    async def test_pem_bytes_are_trusted(self, server_certificate, authority):
        with open(authority.ca, "rb") as f:
            pem = f.read()

        async with Running(upper, server_certificate) as server:
            await exchange(server, TLSConfig(cadata=pem))

    async def test_der_bytes_are_trusted(self, server_certificate, authority):
        der_path = authority.path("ca.der")
        authority.run("x509", "-in", authority.ca, "-outform", "DER", "-out", der_path)

        with open(der_path, "rb") as f:
            der = f.read()

        async with Running(upper, server_certificate) as server:
            await exchange(server, TLSConfig(cadata=der))

    async def test_cadata_alone_defines_the_trust_scope(self, server_certificate, authority):
        # With cadata set, the system trust store must not be consulted, so a
        # trust anchor unrelated to the test CA has to make verification fail.
        elsewhere = authority.issue("island", "DNS:island.example")

        with open(elsewhere[0]) as f:
            pem = f.read()

        flags = ssl.VERIFY_X509_TRUSTED_FIRST | ssl.VERIFY_X509_PARTIAL_CHAIN

        async with Running(upper, server_certificate) as server:
            with pytest.raises(TLSVerificationError):
                await client(server, TLSConfig(cadata=pem, verify_flags=flags)).open()

    def test_garbage_is_rejected(self):
        with pytest.raises(TLSConfigError):
            TLSContext(TLSConfig(cadata=b"\x30\x03junk"))

    def test_empty_cadata_is_rejected(self):
        with pytest.raises(TLSConfigError):
            TLSContext(TLSConfig(cadata=""))

class TestVerifyFlags:
    async def test_partial_chain_trusts_a_leaf(self, server_certificate, authority):
        # X509_V_FLAG_PARTIAL_CHAIN lets a non self-signed certificate act as a
        # trust anchor, so trusting the leaf itself has to be enough.
        with open(server_certificate[0]) as f:
            leaf = f.read()

        flags = ssl.VERIFY_X509_TRUSTED_FIRST | ssl.VERIFY_X509_PARTIAL_CHAIN

        async with Running(upper, server_certificate) as server:
            await exchange(server, TLSConfig(cadata=leaf, verify_flags=flags))

    async def test_without_partial_chain_a_leaf_is_not_enough(self, server_certificate, authority):
        with open(server_certificate[0]) as f:
            leaf = f.read()

        async with Running(upper, server_certificate) as server:
            with pytest.raises(TLSVerificationError):
                await client(server, TLSConfig(cadata=leaf)).open()
