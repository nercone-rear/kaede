import socket
import asyncio
from ssl import CERT_NONE

import pytest

from kaede.tls import TLSConfig, TLSCipher
from kaede.tls.errors import TLSError, TLSVerificationError
from kaede.udp import UDPPort, UDPClient, UDPServer, UDPServerConfig, UDPHandler
from kaede.udp.api.client import UDPClientConfig, UDPClientLimits
from kaede.udp.errors import UDPClosedError, UDPLimitError

from .conftest import Authority

LOCAL = "127.0.0.1"

# DTLS (RFC 6347) is TLS carried over a transport that may lose, reorder or
# duplicate what it is given, and that keeps message boundaries. These tests
# check both halves of that: the security properties TLS already had, and the
# datagram behaviour that must survive being encrypted.

class Running:
    """A DTLS enabled UDPServer on an ephemeral port."""

    def __init__(self, on_connection, certificate, *, alpn=None, idle_timeout=10):
        certfile, keyfile = certificate

        config = UDPServerConfig()
        config.limits.idle_timeout = idle_timeout
        config.tls = TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE)
        config.alpn = alpn
        config.limits.handshake_timeout = 10

        self.server = UDPServer(config)
        self.handler = UDPHandler(on_connection)

    async def __aenter__(self):
        await self.server.listen(self.handler, [(LOCAL, UDPPort(0))])
        return self.server

    async def __aexit__(self, *_):
        await self.server.close(timeout=3)

def client(server, authority, *, alpn=None, hostname="localhost", verify=True):
    config = UDPClientConfig(limits=UDPClientLimits(timeout_connection=10))
    config.tls = TLSConfig(cafile=authority.ca) if verify else TLSConfig(verify_mode=CERT_NONE)
    config.alpn = alpn
    config.hostname = hostname

    return UDPClient(server.ports[0], config=config)

async def upper(connection):
    while True:
        await connection.send((await connection.receive()).upper())

def openssl() -> str:
    """The openssl tool that goes with the library Kaede was pointed at."""

    import shutil

    path = Authority.locate()

    if not shutil.which(path) and not path.startswith("/"):
        pytest.skip("the openssl command line tool is not available")

    return path

def free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LOCAL, 0))

    try:
        return sock.getsockname()[1]
    finally:
        sock.close()

class TestRoundTrip:
    async def test_sends_and_receives_over_dtls(self, server_certificate, authority):
        async with Running(upper, server_certificate) as server:
            async with client(server, authority) as connection:
                await connection.send(b"hello")
                assert await connection.receive(timeout=10) == b"HELLO"

    async def test_reports_the_negotiated_parameters(self, server_certificate, authority):
        async with Running(upper, server_certificate) as server:
            async with client(server, authority) as connection:
                # OpenSSL 3.6 and 4.0 both stop at DTLS 1.2, so that is the ceiling.
                assert connection.version == "DTLSv1.2"
                assert connection.verified

                # DTLS 1.2 uses the TLS 1.2 ciphers, never the TLS 1.3 suites.
                assert not connection.cipher.startswith("TLS_")

    async def test_the_server_sees_the_client_address(self, server_certificate, authority):
        seen = []

        async def note(connection):
            seen.append(connection.dst)
            await connection.send(b"ok")

        async with Running(note, server_certificate) as server:
            async with client(server, authority) as connection:
                await connection.receive(timeout=10)

        assert seen and seen[0][0] == LOCAL

    async def test_carries_a_payload_of_several_kilobytes(self, server_certificate, authority):
        # One DTLS record, so this stays well inside what a single datagram holds.
        payload = bytes(range(256)) * 4  # 1 KiB

        async def echo(connection):
            await connection.send(await connection.receive())

        async with Running(echo, server_certificate) as server:
            async with client(server, authority) as connection:
                await connection.send(payload)
                assert await connection.receive(timeout=10) == payload

class TestDatagramBoundaries:
    async def test_boundaries_survive_encryption(self, server_certificate, authority):
        # Each write becomes its own record in its own datagram, so three sends
        # must still arrive as three messages rather than one joined buffer.
        async with Running(upper, server_certificate) as server:
            async with client(server, authority) as connection:
                for payload in (b"one", b"two", b"three"):
                    await connection.send(payload)

                assert await connection.receive(timeout=10) == b"ONE"
                assert await connection.receive(timeout=10) == b"TWO"
                assert await connection.receive(timeout=10) == b"THREE"

    async def test_a_limit_truncates_and_discards_the_rest(self, server_certificate, authority):
        async with Running(upper, server_certificate) as server:
            async with client(server, authority) as connection:
                await connection.send(b"hello")
                await connection.send(b"world")

                assert await connection.receive(2, timeout=10) == b"HE"
                assert await connection.receive(timeout=10) == b"WORLD"

    async def test_a_message_too_large_for_a_record_is_refused(self, server_certificate, authority):
        # DTLS cannot spread one message over several records the way a stream
        # does, so an oversized payload has to fail rather than be cut short.
        async with Running(upper, server_certificate) as server:
            async with client(server, authority) as connection:
                with pytest.raises(UDPLimitError):
                    await connection.send(b"x" * 100000)

    async def test_the_record_limit_is_exact(self, server_certificate, authority):
        async with Running(upper, server_certificate) as server:
            async with client(server, authority) as connection:
                limit = connection.session.limit()

                # Records are sized to a 1280 byte link, the smallest MTU IPv6
                # requires every path to carry (RFC 8200 section 5). Left to its
                # own devices OpenSSL assumes a far worse path and leaves only
                # about 200 bytes usable, which no real protocol could work with.
                assert limit > 1000

                await connection.send(b"x" * limit)
                assert await connection.receive(timeout=10) == b"X" * limit

                with pytest.raises(UDPLimitError):
                    await connection.send(b"x" * (limit + 1))

class Lossy(asyncio.DatagramProtocol):
    """A relay between one client and the server that throws chosen datagrams
    away, so the handshake has to cope with the loss a real path would inflict."""

    def __init__(self, server, drop):
        self.server = server # (host, port) of the real server
        self.drop = drop     # datagram numbers to discard, keyed by direction
        self.seen = {"out": 0, "back": 0}
        self.dropped = 0
        self.client = None
        self.transport = None

    async def __aenter__(self):
        loop = asyncio.get_running_loop()
        self.transport, _ = await loop.create_datagram_endpoint(lambda: self, local_addr=(LOCAL, 0))

        return self

    async def __aexit__(self, *_):
        self.transport.close()
        await asyncio.sleep(0)  # let the transport hand its socket back

    @property
    def address(self):
        host, port = self.transport.get_extra_info("sockname")[:2]

        return (host, UDPPort(port))

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if addr == self.server:
            way, target = "back", self.client
        else:
            self.client = addr
            way, target = "out", self.server

        self.seen[way] += 1

        if self.seen[way] in self.drop.get(way, ()):
            self.dropped += 1
            return

        if target is not None:
            self.transport.sendto(data, target)

def through(relay, authority):
    config = UDPClientConfig(limits=UDPClientLimits(timeout_connection=30))
    config.tls = TLSConfig(cafile=authority.ca)
    config.hostname = "localhost"

    return UDPClient(relay.address, config=config)

class TestLoss:
    """RFC 6347 section 4.2.4: the transport may lose a flight outright, so the
    handshake carries its own timer and resends rather than stalling. Loopback
    never drops anything, so the loss has to be inflicted deliberately."""

    async def relay(self, server, drop):
        host, port = server.ports[0]

        return Lossy((host, int(port)), drop)

    async def test_recovers_when_the_servers_flight_is_lost(self, server_certificate, authority):
        async with Running(upper, server_certificate, idle_timeout=30) as server:
            async with await self.relay(server, {"back": (1,)}) as relay:
                async with through(relay, authority) as connection:
                    assert relay.dropped == 1

                    await connection.send(b"survived")
                    assert await connection.receive(timeout=20) == b"SURVIVED"

    async def test_recovers_when_the_client_hello_is_lost(self, server_certificate, authority):
        async with Running(upper, server_certificate, idle_timeout=30) as server:
            async with await self.relay(server, {"out": (1,)}) as relay:
                async with through(relay, authority) as connection:
                    assert relay.dropped == 1

                    await connection.send(b"survived")
                    assert await connection.receive(timeout=20) == b"SURVIVED"

class TestVerification:
    async def test_rejects_a_certificate_from_an_unknown_ca(self, server_certificate):
        async with Running(upper, server_certificate) as server:
            config = UDPClientConfig(limits=UDPClientLimits(timeout_connection=10))
            config.tls = TLSConfig()  # the system trust store, which lacks the test CA

            with pytest.raises(TLSVerificationError):
                await UDPClient(server.ports[0], config=config).open(hostname="localhost")

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
                assert await connection.receive(timeout=10) == b"HELLO"

    async def test_a_rejected_handshake_does_not_stop_the_server(self, server_certificate, authority):
        async with Running(upper, server_certificate) as server:
            config = UDPClientConfig(limits=UDPClientLimits(timeout_connection=10))
            config.tls = TLSConfig()

            with pytest.raises(TLSVerificationError):
                await UDPClient(server.ports[0], config=config).open(hostname="localhost")

            # A client that does trust the CA must still be served.
            async with client(server, authority) as connection:
                await connection.send(b"hello")
                assert await connection.receive(timeout=10) == b"HELLO"

    async def test_a_failed_handshake_is_not_kept_as_a_connection(self, server_certificate):
        async with Running(upper, server_certificate) as server:
            config = UDPClientConfig(limits=UDPClientLimits(timeout_connection=10))
            config.tls = TLSConfig()

            failing = UDPClient(server.ports[0], config=config)

            with pytest.raises(TLSVerificationError):
                await failing.open(hostname="localhost")

            assert failing.connections == []

class TestSNIAndALPN:
    async def test_the_server_receives_the_servername(self, server_certificate, authority):
        seen = []

        async def note(connection):
            seen.append(connection.servername)
            await connection.send(b"ok")

        async with Running(note, server_certificate) as server:
            async with client(server, authority) as connection:
                await connection.receive(timeout=10)

        assert seen == ["localhost"]

    async def test_no_servername_is_sent_for_an_ip_address(self, server_certificate, authority):
        # RFC 6066 section 3: a literal address must not be sent as SNI.
        seen = []

        async def note(connection):
            seen.append(connection.servername)
            await connection.send(b"ok")

        async with Running(note, server_certificate) as server:
            async with client(server, authority, hostname=LOCAL) as connection:
                await connection.receive(timeout=10)
                assert connection.verified

        assert seen == [None]

    async def test_alpn_is_negotiated(self, server_certificate, authority):
        async with Running(upper, server_certificate, alpn=["kaede/1", "other/1"]) as server:
            async with client(server, authority, alpn=["kaede/1"]) as connection:
                assert connection.protocol == "kaede/1"

    async def test_the_server_preference_decides(self, server_certificate, authority):
        # RFC 7301 section 3.2: the server's order decides, not the client's.
        async with Running(upper, server_certificate, alpn=["kaede/1", "other/1"]) as server:
            async with client(server, authority, alpn=["other/1", "kaede/1"]) as connection:
                assert connection.protocol == "kaede/1"

    async def test_the_handshake_fails_when_none_overlap(self, server_certificate, authority):
        async with Running(upper, server_certificate, alpn=["kaede/1"]) as server:
            with pytest.raises(TLSError):
                await client(server, authority, alpn=["other/1"]).open()

class TestClosing:
    async def test_sending_after_close_is_rejected(self, server_certificate, authority):
        async with Running(upper, server_certificate) as server:
            connection = await client(server, authority).open(hostname="localhost")
            await connection.close()

            with pytest.raises(UDPClosedError):
                await connection.send(b"late")

    async def test_close_is_idempotent(self, server_certificate, authority):
        async with Running(upper, server_certificate) as server:
            connection = await client(server, authority).open(hostname="localhost")

            await connection.close()
            await connection.close()

    async def test_closing_the_client_closes_its_connections(self, server_certificate, authority):
        async with Running(upper, server_certificate) as server:
            talking = client(server, authority)
            connection = await talking.open(hostname="localhost")

            await talking.close()

            with pytest.raises(UDPClosedError):
                await connection.send(b"late")

class TestInteroperability:
    """Checked against OpenSSL's own DTLS tools rather than against Kaede.

    Python's ssl module has no DTLS at all, so unlike the TLS tests there is no
    standard library implementation to compare with. The command line tool comes
    from the same OpenSSL that Kaede was pointed at."""

    async def test_the_openssl_client_can_talk_to_the_server(self, server_certificate, authority):
        tool = openssl()
        certfile, keyfile = server_certificate

        async with Running(upper, server_certificate) as server:
            process = await asyncio.create_subprocess_exec(
                tool, "s_client", "-dtls1_2",
                "-connect", f"{LOCAL}:{int(server.ports[0][1])}",
                "-CAfile", authority.ca,
                "-servername", "localhost",
                "-verify_return_error",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )

            collected = b""

            try:
                # stdin stays open: closing it makes s_client quit before it has
                # read the answer back off the wire.
                process.stdin.write(b"hello from openssl\n")
                await process.stdin.drain()

                while b"HELLO FROM OPENSSL" not in collected.upper():
                    chunk = await asyncio.wait_for(process.stdout.read(4096), timeout=20)

                    if not chunk:
                        break

                    collected += chunk

            finally:
                process.kill()
                await process.wait()

        text = collected.decode(errors="replace")

        assert "Protocol  : DTLSv1.2" in text
        assert "Verify return code: 0 (ok)" in text
        assert "HELLO FROM OPENSSL" in text.upper()

    async def test_the_client_can_talk_to_the_openssl_server(self, server_certificate, authority):
        tool = openssl()
        certfile, keyfile = server_certificate
        port = free_port()

        process = await asyncio.create_subprocess_exec(
            tool, "s_server", "-dtls1_2",
            "-accept", f"{LOCAL}:{port}",
            "-cert", certfile,
            "-key", keyfile,
            "-quiet",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        try:
            await asyncio.sleep(1.0)  # let s_server bind

            config = UDPClientConfig(limits=UDPClientLimits(timeout_connection=20))
            config.tls = TLSConfig(cafile=authority.ca)
            config.hostname = "localhost"

            async with UDPClient((LOCAL, UDPPort(port)), config=config) as connection:
                assert connection.version == "DTLSv1.2"
                assert connection.verified

                await connection.send(b"hello from kaede\n")

                seen = await asyncio.wait_for(process.stdout.readline(), timeout=20)
                assert b"hello from kaede" in seen

                # s_server sends whatever arrives on its stdin back over DTLS.
                process.stdin.write(b"reply from openssl\n")
                await process.stdin.drain()

                assert await connection.receive(timeout=20) == b"reply from openssl\n"

        finally:
            process.kill()
            await process.wait()
