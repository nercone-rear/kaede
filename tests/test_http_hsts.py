"""HSTS end to end, from RFC 6797 §8.1 (learning) through §8.3 (applying).

The store, the parser and the upgrade were each present and correct on their own, and
nothing ever called learn(), so the whole mechanism was inert. These tests exercise the
path rather than the pieces, since that is where the gap was.
"""

from ssl import CERT_NONE

import pytest

from kaede.url import URL
from kaede.tls import TLSConfig
from kaede.tcp import TCPPort
from kaede.http.models import HTTPPort, HTTPHeaders, HTTPResponse
from kaede.http.api.server import HTTPServer, HTTPServerConfig, HTTPHandler
from kaede.http.api.client import HTTPClient, HTTPClientConfig, HTTPClientLimits

LOCAL = "127.0.0.1"

class Strict(HTTPHandler):
    """An origin that advertises a policy on every response."""

    def __init__(self, header="max-age=31536000; includeSubDomains"):
        self.header = header

    async def on_connection(self, connection):
        await connection.receive()

        headers = HTTPHeaders([("Strict-Transport-Security", self.header)])
        await connection.send(HTTPResponse(status_code=200, headers=headers, body=b"ok", compression=False))

class Running:
    def __init__(self, handler, certificate):
        config = HTTPServerConfig(versions=["HTTP/1.1"])
        certfile, keyfile = certificate
        config.tls = TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE)

        self.server = HTTPServer(config=config)
        self.handler = handler

    async def __aenter__(self):
        await self.server.listen(self.handler, [(LOCAL, HTTPPort("tcp", TCPPort(0)))])
        return self.server

    async def __aexit__(self, *_):
        await self.server.close(timeout=2)

NAME = "localhost" # HSTS never applies to an IP address, so the origin has to have a name

def address(server) -> str:
    return f"https://{NAME}:{int(server.ports[0][1].value)}"

def client(authority) -> HTTPClient:
    return HTTPClient(config=HTTPClientConfig(versions=["HTTP/1.1"], limits=HTTPClientLimits(timeout_connection=5), tls=TLSConfig(cafile=authority.ca)))

class TestLearning:
    async def test_a_policy_on_a_secure_response_is_recorded(self, server_certificate, authority):
        """§8.1: a UA that receives the header over a secure transport notes the host."""
        async with Running(Strict(), server_certificate) as server:
            async with client(authority) as http:
                await (await http.get(address(server) + "/")).receive()

                assert http.store.secure(NAME)

    async def test_a_broken_policy_does_not_erase_a_stored_one(self, server_certificate, authority):
        # §6.1: an unparsable header is ignored. Treating it as max-age=0 would let any
        # malformed or truncated header take a host back off the list.
        async with Running(Strict(), server_certificate) as server:
            async with client(authority) as http:
                await (await http.get(address(server) + "/")).receive()
                assert http.store.secure(NAME)

        async with Running(Strict("includeSubDomains"), server_certificate) as server:
            async with client(authority) as http:
                http.store.learn(NAME, "max-age=31536000")
                await (await http.get(address(server) + "/")).receive()

                assert http.store.secure(NAME)

    async def test_an_origin_named_by_ip_address_is_never_recorded(self, server_certificate, authority):
        # §8.1.1: an IP address MUST NOT become a Known HSTS Host, however it advertises.
        async with Running(Strict(), server_certificate) as server:
            async with client(authority) as http:
                await (await http.get(f"https://{LOCAL}:{int(server.ports[0][1].value)}/")).receive()

                assert not http.store.secure(LOCAL)

    async def test_a_policy_is_not_learned_when_the_store_is_off(self, server_certificate, authority):
        config = HTTPClientConfig(versions=["HTTP/1.1"], limits=HTTPClientLimits(timeout_connection=5), tls=TLSConfig(cafile=authority.ca), hsts=False)

        async with Running(Strict(), server_certificate) as server:
            async with HTTPClient(config=config) as http:
                await (await http.get(address(server) + "/")).receive()

                assert http.store is None

class TestUpgrading:
    """§8.3 step 5: the scheme is replaced with https, and an explicit port 80 becomes 443."""

    def upgraded(self, http, url: str) -> URL:
        return http.upgrade(URL.parse_absolute(target=url))

    def test_a_known_host_upgrades_the_scheme(self):
        http = HTTPClient()
        http.store.learn("example.com", "max-age=31536000")

        assert self.upgraded(http, "http://example.com/x").scheme == "https"

    def test_an_explicit_port_80_becomes_443(self):
        """Leaving the scheme as http meant the default port lookup still answered 80, and
        the connection then ran a TLS handshake against the cleartext port."""
        http = HTTPClient()
        http.store.learn("example.com", "max-age=31536000")

        assert self.upgraded(http, "http://example.com:80/x").port == 443

    def test_the_effective_port_is_443(self):
        http = HTTPClient()
        http.store.learn("example.com", "max-age=31536000")

        url = self.upgraded(http, "http://example.com/x")

        assert (url.port or HTTPClient.DEFAULT_PORTS[url.scheme]) == 443

    def test_another_explicit_port_is_left_alone(self):
        http = HTTPClient()
        http.store.learn("example.com", "max-age=31536000")

        assert self.upgraded(http, "http://example.com:8080/x").port == 8080

    def test_a_websocket_scheme_upgrades_too(self):
        http = HTTPClient()
        http.store.learn("example.com", "max-age=31536000")

        assert self.upgraded(http, "ws://example.com/x").scheme == "wss"

    def test_an_unknown_host_is_left_alone(self):
        http = HTTPClient()

        assert self.upgraded(http, "http://example.com/x").scheme == "http"

    def test_an_https_url_is_left_alone(self):
        http = HTTPClient()
        http.store.learn("example.com", "max-age=31536000")

        url = self.upgraded(http, "https://example.com:8443/x")

        assert (url.scheme, url.port) == ("https", 8443)
