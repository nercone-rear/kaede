import asyncio
from ssl import CERT_NONE

import pytest

from kaede.tls import TLSConfig
from kaede.tls.openssl import TLSContext, Cookies
from kaede.tls.errors import TLSConfigError
from kaede.udp import UDPPort, UDPClient, UDPServer, UDPServerConfig, UDPHandler
from kaede.udp.api.client import UDPClientConfig

from .conftest import Authority

LOCAL = "127.0.0.1"

# RFC 6347 section 4.2.1. A datagram carries whatever source address its sender
# chose to write, so a server that answers immediately will answer whoever was
# named rather than whoever asked. Since its first flight carries a certificate,
# the reply is several times the size of the request, and the server becomes an
# amplifier. The cookie exchange makes a peer echo back something only the real
# holder of that address could have received, before anything expensive is sent.

class Running:
    def __init__(self, on_connection, certificate, *, cookies=True):
        certfile, keyfile = certificate

        config = UDPServerConfig(idle_timeout=30)
        config.tls = TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE)
        config.cookies = cookies
        config.handshake_timeout = 20

        self.server = UDPServer(config)
        self.handler = UDPHandler(on_connection)

    async def __aenter__(self):
        await self.server.listen(self.handler, [(LOCAL, UDPPort(0))])
        return self.server

    async def __aexit__(self, *_):
        await self.server.close(timeout=3)

async def upper(connection):
    while True:
        await connection.send((await connection.receive()).upper())

class Probe(asyncio.DatagramProtocol):
    """A bare socket that speaks to the server without Kaede's client, so what
    goes on the wire can be inspected and replayed."""

    def __init__(self):
        self.received = asyncio.Queue()
        self.transport = None

    async def __aenter__(self):
        loop = asyncio.get_running_loop()
        self.transport, _ = await loop.create_datagram_endpoint(lambda: self, local_addr=(LOCAL, 0))

        return self

    async def __aexit__(self, *_):
        self.transport.close()
        await asyncio.sleep(0)  # let the transport hand its socket back

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.received.put_nowait(data)

    async def exchange(self, data, address, timeout=5):
        """Send one datagram and gather everything that comes back."""

        self.transport.sendto(data, (address[0], int(address[1])))

        answers = []

        while True:
            try:
                answers.append(await asyncio.wait_for(self.received.get(), timeout if not answers else 0.4))
            except asyncio.TimeoutError:
                return answers

def hello(authority, *, session=None):
    """A genuine DTLS ClientHello, produced by a real client session."""

    session = session or TLSContext(TLSConfig(cafile=authority.ca), datagram=True).session(hostname="localhost")

    session.handshake()
    return session, b"".join(session.packets())

class TestAmplification:
    async def test_the_first_answer_is_a_hello_verify_request(self, server_certificate, authority):
        _, first = hello(authority)

        async with Running(upper, server_certificate) as server:
            async with Probe() as probe:
                answers = await probe.exchange(first, server.ports[0])

        assert answers, "the server has to answer, or a genuine client could never start"

        # RFC 6347 section 4.2.1: handshake type 3 is hello_verify_request. Byte
        # 13 is where the handshake message begins inside a DTLS record.
        assert answers[0][0] == 22   # content type handshake
        assert answers[0][13] == 3   # hello_verify_request, not server_hello

    async def test_an_unproven_peer_is_never_sent_a_certificate(self, server_certificate, authority):
        # Handshake type 11 is the certificate, which is what makes the flight
        # big enough to be worth abusing.
        _, first = hello(authority)

        async with Running(upper, server_certificate) as server:
            async with Probe() as probe:
                answers = await probe.exchange(first, server.ports[0])

        assert all(answer[13] != 11 for answer in answers)

    async def test_the_answer_is_smaller_than_the_request(self, server_certificate, authority):
        # This is the property that matters. If the answer were larger, the
        # server could be pointed at a forged address to multiply traffic.
        _, first = hello(authority)

        async with Running(upper, server_certificate) as server:
            async with Probe() as probe:
                answers = await probe.exchange(first, server.ports[0])

        assert sum(len(answer) for answer in answers) < len(first)

    async def test_a_server_without_cookies_does_amplify(self, server_certificate, authority):
        # The counterpart, which is why cookies are on by default: with them off
        # the same forged request draws the whole certificate flight back.
        _, first = hello(authority)

        async with Running(upper, server_certificate, cookies=False) as server:
            async with Probe() as probe:
                answers = await probe.exchange(first, server.ports[0])

        assert sum(len(answer) for answer in answers) > len(first)

class TestExchange:
    async def test_a_returned_cookie_completes_the_handshake(self, server_certificate, authority):
        async with Running(upper, server_certificate) as server:
            async with UDPClient(server.ports[0], config=self.config(authority)) as connection:
                assert connection.version == "DTLSv1.2"
                assert connection.verified

                await connection.send(b"hello")
                assert await connection.receive(timeout=20) == b"HELLO"

    def config(self, authority):
        config = UDPClientConfig(connect_timeout=20)
        config.tls = TLSConfig(cafile=authority.ca)
        config.hostname = "localhost"

        return config

    async def test_a_forged_cookie_is_refused(self, server_certificate, authority):
        session, first = hello(authority)

        async with Running(upper, server_certificate) as server:
            async with Probe() as probe:
                answers = await probe.exchange(first, server.ports[0])

                # Take the real cookied ClientHello, then corrupt the cookie in it.
                for answer in answers:
                    session.feed(answer)

                session.handshake()
                cookied = b"".join(session.packets())

                # The cookie sits after the 2 byte version and 32 byte random,
                # then a session id length, at the start of the ClientHello body.
                spoiled = bytearray(cookied)
                spoiled[-1] ^= 0xFF
                spoiled[60] ^= 0xFF

                again = await probe.exchange(bytes(spoiled), server.ports[0])

        # It must be challenged again rather than served.
        assert all(answer[13] != 11 for answer in again)

    async def test_a_cookie_is_bound_to_the_address_it_was_issued_for(self, server_certificate, authority):
        # The whole point is that the cookie proves an address. Replaying one
        # from somewhere else has to fail, or nothing has been proved.
        session, first = hello(authority)

        async with Running(upper, server_certificate) as server:
            async with Probe() as issued:
                answers = await issued.exchange(first, server.ports[0])

                for answer in answers:
                    session.feed(answer)

                session.handshake()
                cookied = b"".join(session.packets())

            # A different socket means a different source port, so the cookie
            # that was minted for the first one must not be honoured here.
            async with Probe() as elsewhere:
                replayed = await elsewhere.exchange(cookied, server.ports[0])

        assert replayed, "the replay still has to be answered"
        assert all(answer[13] != 11 for answer in replayed), "a replayed cookie must not earn a certificate"
        assert replayed[0][13] == 3, "it has to be challenged again"

class TestConfiguration:
    async def test_cookies_are_on_by_default(self):
        assert UDPServerConfig().cookies is True

    async def test_cookies_can_be_turned_off(self, server_certificate, authority):
        config = UDPClientConfig(connect_timeout=20)
        config.tls = TLSConfig(cafile=authority.ca)
        config.hostname = "localhost"

        async with Running(upper, server_certificate, cookies=False) as server:
            async with UDPClient(server.ports[0], config=config) as connection:
                await connection.send(b"hello")
                assert await connection.receive(timeout=20) == b"HELLO"

    def test_cookies_are_refused_on_a_client(self):
        # A client has nothing to protect this way, and asking for it means the
        # caller has misunderstood which side issues the challenge.
        with pytest.raises(TLSConfigError):
            TLSContext(TLSConfig(verify_mode=CERT_NONE), server=False, datagram=True, cookies=Cookies())

    def test_cookies_are_refused_over_a_stream(self):
        # TCP already proves the address with its own handshake.
        with pytest.raises(TLSConfigError):
            TLSContext(TLSConfig(verify_mode=CERT_NONE), server=True, datagram=False, cookies=Cookies())

class TestCookies:
    """The cookie itself, which has to be unguessable, tied to one address, and
    cheap enough that issuing one costs the server nothing to remember."""

    def test_a_cookie_verifies_for_the_address_it_was_made_for(self):
        cookies = Cookies()

        assert cookies.check("10.0.0.1:1000", cookies.make("10.0.0.1:1000"))

    def test_a_cookie_does_not_verify_for_another_address(self):
        cookies = Cookies()

        assert not cookies.check("10.0.0.2:1000", cookies.make("10.0.0.1:1000"))

    def test_a_cookie_does_not_verify_for_another_port(self):
        cookies = Cookies()

        assert not cookies.check("10.0.0.1:2000", cookies.make("10.0.0.1:1000"))

    def test_a_tampered_cookie_does_not_verify(self):
        cookies = Cookies()
        cookie = bytearray(cookies.make("10.0.0.1:1000"))
        cookie[0] ^= 0xFF

        assert not cookies.check("10.0.0.1:1000", bytes(cookie))

    def test_a_cookie_from_another_server_does_not_verify(self):
        # The secret is per process, so one server's cookie is worthless at another.
        assert not Cookies().check("10.0.0.1:1000", Cookies().make("10.0.0.1:1000"))

    def test_two_servers_do_not_share_a_secret(self):
        assert Cookies().secret != Cookies().secret

    def test_the_secret_is_long_enough_to_be_unguessable(self):
        assert len(Cookies().secret) >= 32

    def test_a_cookie_fits_what_the_protocol_allows(self):
        # RFC 6347 section 4.2.1 caps the cookie at 255 bytes.
        assert 0 < len(Cookies().make("10.0.0.1:1000")) <= 255

    def test_a_cookie_survives_into_the_next_window(self):
        # One issued just before a boundary must not be refused for arriving
        # just after it, or a client would be turned away through no fault.
        cookies = Cookies()
        cookie = cookies.make("10.0.0.1:1000", at=0.0)

        assert cookies.check("10.0.0.1:1000", cookie, at=cookies.lifetime + 1)

    def test_a_cookie_expires_eventually(self):
        cookies = Cookies()
        cookie = cookies.make("10.0.0.1:1000", at=0.0)

        assert not cookies.check("10.0.0.1:1000", cookie, at=cookies.lifetime * 3)

    def test_nothing_is_remembered_between_the_two_exchanges(self):
        # Issuing has to leave no per peer state behind, or the defence would
        # itself be a way to exhaust the server's memory.
        cookies = Cookies()
        before = dict(vars(cookies))

        for port in range(1000, 1100):
            cookies.make(f"10.0.0.1:{port}")

        after = dict(vars(cookies))

        assert set(before) == set(after)
        assert after["secret"] == before["secret"]

class TestInteroperability:
    async def test_the_openssl_client_completes_the_cookie_exchange(self, server_certificate, authority):
        # s_client does the cookie exchange on its own, so this checks Kaede's
        # side of it against OpenSSL's rather than against Kaede's own client.
        import shutil

        tool = Authority.locate()

        if not shutil.which(tool) and not tool.startswith("/"):
            pytest.skip("the openssl command line tool is not available")

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
                process.stdin.write(b"cookied\n")
                await process.stdin.drain()

                while b"COOKIED" not in collected.upper():
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
        assert "COOKIED" in text.upper()
