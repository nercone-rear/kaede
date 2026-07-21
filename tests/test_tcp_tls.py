import ssl
import asyncio
from ssl import CERT_NONE

import pytest

from kaede.tls import TLSConfig, TLSGroup
from kaede.tls.errors import TLSError, TLSVerificationError, TLSECHError
from kaede.tcp import TCPPort, TCPClient, TCPServer, TCPServerConfig, TCPHandler
from kaede.tcp.api.client import TCPClientConfig, TCPClientLimits
from kaede.tcp.errors import TCPClosedError

LOCAL = "127.0.0.1"

class Running:
    """A TLS enabled TCPServer on an ephemeral port."""

    def __init__(self, on_connection, certificate, *, alpn=None, echfile=None):
        certfile, keyfile = certificate

        config = TCPServerConfig()
        config.tls = TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE, echfile=echfile)
        config.alpn = alpn

        self.server = TCPServer(config)
        self.handler = TCPHandler(on_connection)

    async def __aenter__(self):
        await self.server.listen(self.handler, [(LOCAL, TCPPort(0))])
        return self.server

    async def __aexit__(self, *_):
        await self.server.close(timeout=2)

def client(server, authority, *, alpn=None, hostname="localhost", verify=True, ech=None):
    config = TCPClientConfig(limits=TCPClientLimits(timeout_connection=5))
    config.tls = TLSConfig(cafile=authority.ca) if verify else TLSConfig(verify_mode=CERT_NONE)
    config.alpn = alpn
    config.hostname = hostname
    config.ech = ech

    return TCPClient(server.ports[0], config=config)

async def upper(connection):
    data = await connection.receive_exactly(5)
    await connection.send(data.upper())

class TestRoundTrip:
    async def test_sends_and_receives_over_tls(self, server_certificate, authority):
        async with Running(upper, server_certificate) as server:
            async with client(server, authority) as connection:
                await connection.send(b"hello")
                assert await connection.receive_exactly(5) == b"HELLO"

    async def test_reports_the_negotiated_parameters(self, server_certificate, authority):
        async with Running(upper, server_certificate) as server:
            async with client(server, authority) as connection:
                assert connection.version == "TLSv1.3"
                assert connection.group == "X25519MLKEM768"
                assert connection.verified
                assert connection.cipher.startswith("TLS_")

    async def test_carries_a_payload_larger_than_one_record(self, server_certificate, authority):
        # A TLS record holds at most 16384 bytes, so this spans many records.
        payload = bytes(range(256)) * 1024  # 256 KiB

        async def echo(connection):
            data = await connection.receive_exactly(len(payload))
            await connection.send(data)

        async with Running(echo, server_certificate) as server:
            async with client(server, authority) as connection:
                await connection.send(payload)
                assert await connection.receive_exactly(len(payload)) == payload

    async def test_receive_until_works_over_tls(self, server_certificate, authority):
        async def lines(connection):
            await connection.send(b"first\r\nsecond\r\n")

        async with Running(lines, server_certificate) as server:
            async with client(server, authority) as connection:
                assert await connection.receive_until(b"\r\n") == b"first\r\n"
                assert await connection.receive_until(b"\r\n") == b"second\r\n"

    async def test_receive_all_reads_until_close_notify(self, server_certificate, authority):
        async def send(connection):
            await connection.send(b"complete message")

        async with Running(send, server_certificate) as server:
            async with client(server, authority) as connection:
                assert await connection.receive(-1) == b"complete message"

    async def test_the_server_sees_the_client_address(self, server_certificate, authority):
        seen = []

        async def note(connection):
            seen.append(connection.dst)
            await connection.send(b"ok")

        async with Running(note, server_certificate) as server:
            async with client(server, authority) as connection:
                await connection.receive(2)

        assert seen and seen[0][0] == LOCAL

class TestVerification:
    async def test_rejects_a_certificate_from_an_unknown_ca(self, server_certificate):
        async with Running(upper, server_certificate) as server:
            config = TCPClientConfig(limits=TCPClientLimits(timeout_connection=5))
            config.tls = TLSConfig()  # the system trust store, which lacks the test CA

            with pytest.raises(TLSVerificationError):
                await TCPClient(server.ports[0], config=config).open(hostname="localhost")

    async def test_rejects_a_hostname_that_does_not_match(self, other_certificate, authority):
        async with Running(upper, other_certificate) as server:
            with pytest.raises(TLSVerificationError) as caught:
                await client(server, authority).open(hostname="localhost")

            assert caught.value.code == 62  # X509_V_ERR_HOSTNAME_MISMATCH

    async def test_rejects_an_expired_certificate(self, expired_certificate, authority):
        async with Running(upper, expired_certificate) as server:
            with pytest.raises(TLSVerificationError) as caught:
                await client(server, authority).open(hostname="localhost")

            assert caught.value.code == 10  # X509_V_ERR_CERT_HAS_EXPIRED

    async def test_connects_when_verification_is_disabled(self, other_certificate, authority):
        async with Running(upper, other_certificate) as server:
            async with client(server, authority, verify=False) as connection:
                await connection.send(b"hello")
                assert await connection.receive_exactly(5) == b"HELLO"

    async def test_a_rejected_handshake_does_not_stop_the_server(self, server_certificate, authority):
        async with Running(upper, server_certificate) as server:
            config = TCPClientConfig(limits=TCPClientLimits(timeout_connection=5))
            config.tls = TLSConfig()

            with pytest.raises(TLSVerificationError):
                await TCPClient(server.ports[0], config=config).open(hostname="localhost")

            # A client that does trust the CA must still be served.
            async with client(server, authority) as connection:
                await connection.send(b"hello")
                assert await connection.receive_exactly(5) == b"HELLO"

class TestSNIAndALPN:
    async def test_the_server_receives_the_servername(self, server_certificate, authority):
        seen = []

        async def note(connection):
            seen.append(connection.servername)
            await connection.send(b"ok")

        async with Running(note, server_certificate) as server:
            async with client(server, authority) as connection:
                await connection.receive(2)

        assert seen == ["localhost"]

    async def test_no_servername_is_sent_for_an_ip_address(self, server_certificate, authority):
        # RFC 6066 section 3: a literal IP address must not be sent as SNI.
        seen = []

        async def note(connection):
            seen.append(connection.servername)
            await connection.send(b"ok")

        async with Running(note, server_certificate) as server:
            # The certificate carries IP:127.0.0.1, so verification still succeeds.
            async with client(server, authority, hostname=LOCAL) as connection:
                await connection.receive(2)
                assert connection.verified

        assert seen == [None]

    async def test_alpn_is_negotiated(self, server_certificate, authority):
        seen = []

        async def note(connection):
            seen.append(connection.protocol)
            await connection.send(b"ok")

        async with Running(note, server_certificate, alpn=["h2", "http/1.1"]) as server:
            async with client(server, authority, alpn=["h2"]) as connection:
                await connection.receive(2)
                assert connection.protocol == "h2"

        assert seen == ["h2"]

    async def test_the_server_preference_decides(self, server_certificate, authority):
        # RFC 7301 section 3.2: the server's order decides, not the client's.
        async with Running(upper, server_certificate, alpn=["h2", "http/1.1"]) as server:
            async with client(server, authority, alpn=["http/1.1", "h2"]) as connection:
                assert connection.protocol == "h2"

    async def test_the_handshake_fails_when_none_overlap(self, server_certificate, authority):
        # RFC 7301 section 3.2: a fatal no_application_protocol alert is required.
        async with Running(upper, server_certificate, alpn=["h2"]) as server:
            with pytest.raises(TLSError):
                await client(server, authority, alpn=["http/1.1"]).open()

class TestInteroperability:
    async def test_a_stdlib_client_can_talk_to_the_server(self, server_certificate, authority):
        # Checked against Python's own TLS implementation rather than Kaede's.
        async with Running(upper, server_certificate) as server:
            context = ssl.create_default_context(cafile=authority.ca)

            reader, writer = await asyncio.open_connection(LOCAL, int(server.ports[0][1]), ssl=context, server_hostname="localhost")

            writer.write(b"hello")
            await writer.drain()

            assert await reader.readexactly(5) == b"HELLO"

            writer.close()
            await writer.wait_closed()

    async def test_the_client_can_talk_to_a_stdlib_server(self, server_certificate, authority):
        certfile, keyfile = server_certificate

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile, keyfile)

        async def serve(reader, writer):
            data = await reader.readexactly(5)
            writer.write(data.upper())
            await writer.drain()
            writer.close()

        listener = await asyncio.start_server(serve, LOCAL, 0, ssl=context)
        port = listener.sockets[0].getsockname()[1]

        try:
            config = TCPClientConfig(limits=TCPClientLimits(timeout_connection=5))
            config.tls = TLSConfig(cafile=authority.ca)

            async with TCPClient((LOCAL, TCPPort(port)), config=config) as connection:
                await connection.send(b"hello")
                assert await connection.receive_exactly(5) == b"HELLO"

        finally:
            listener.close()
            await listener.wait_closed()

class TestAlerts:
    async def test_a_rejecting_server_sends_a_real_alert(self, server_certificate, authority):
        # The peer must be told why, rather than just seeing the connection end.
        # Checked with the standard library so the alert is decoded independently.
        async with Running(upper, server_certificate, alpn=["h2"]) as server:
            context = ssl.create_default_context(cafile=authority.ca)
            context.set_alpn_protocols(["http/1.1"])

            with pytest.raises(ssl.SSLError) as caught:
                await asyncio.open_connection(LOCAL, int(server.ports[0][1]), ssl=context, server_hostname="localhost")

            assert "NO_APPLICATION_PROTOCOL" in str(caught.value).upper().replace(" ", "_")

    async def test_a_rejecting_client_still_reaches_the_server(self, server_certificate, authority):
        # A client that distrusts the certificate must not leave the server
        # hanging: the handshake ends and the connection is released.
        certfile, keyfile = server_certificate

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile, keyfile)

        async def serve(reader, writer):
            writer.close()

        listener = await asyncio.start_server(serve, LOCAL, 0, ssl=context)
        port = listener.sockets[0].getsockname()[1]

        try:
            config = TCPClientConfig(limits=TCPClientLimits(timeout_connection=5))
            config.tls = TLSConfig()  # the test CA is not in the system trust store
            config.hostname = "localhost"

            client = TCPClient((LOCAL, TCPPort(port)), config=config)

            with pytest.raises(TLSError):
                await client.open()

            # The failed attempt must not have been retained as a live connection.
            assert client.connections == []

        finally:
            listener.close()
            await listener.wait_closed()

class TestClosing:
    async def test_sending_after_close_is_rejected(self, server_certificate, authority):
        async with Running(upper, server_certificate) as server:
            connection = await client(server, authority).open(hostname="localhost")
            await connection.close()

            with pytest.raises(TCPClosedError):
                await connection.send(b"late")

    async def test_close_is_idempotent(self, server_certificate, authority):
        async with Running(upper, server_certificate) as server:
            connection = await client(server, authority).open(hostname="localhost")

            await connection.close()
            await connection.close()

class TestECH:
    async def test_a_real_connection_encrypts_the_client_hello(self, server_certificate, authority, ech_keys):
        async with Running(upper, server_certificate, echfile=ech_keys.pemfile) as server:
            async with client(server, authority, ech=ech_keys.configlist) as connection:
                await connection.send(b"hello")
                assert await connection.receive_exactly(5) == b"HELLO"

                assert connection.ech_status.succeeded
                assert connection.ech_status.inner_sni == "localhost"
                assert connection.ech_status.outer_sni == ech_keys.public_name

    async def test_a_server_without_ech_configured_does_not_downgrade(self, server_certificate, authority, ech_keys):
        # The server here never received echfile, so it cannot decrypt the
        # inner Client Hello: the client must fail rather than proceed in the clear.
        async with Running(upper, server_certificate) as server:
            with pytest.raises(TLSError):
                await client(server, authority, ech=ech_keys.configlist, verify=False).open(hostname="localhost")

    async def test_a_stale_config_is_rejected_with_a_retry_config(self, server_certificate, ech_keys):
        corrupted = bytearray(ech_keys.configlist)
        corrupted[20] ^= 0xff

        async with Running(upper, server_certificate, echfile=ech_keys.pemfile) as server:
            config = TCPClientConfig(limits=TCPClientLimits(timeout_connection=5))
            config.tls = TLSConfig(verify_mode=CERT_NONE)
            config.hostname = "localhost"
            config.ech = bytes(corrupted)

            with pytest.raises(TLSECHError) as caught:
                await TCPClient(server.ports[0], config=config).open()

            assert caught.value.retry_config
