import os

import pytest

from kaede.quic.tls import QTLS
from kaede.http.api.client import HTTPClient, HTTPClientConfig, HTTPClientLimits

pytestmark = [
    pytest.mark.network,
    pytest.mark.skipif(os.environ.get("KAEDE_NETWORK_TESTS") != "1", reason="set KAEDE_NETWORK_TESTS=1 to reach real servers"),
]

def client(versions) -> HTTPClient:
    return HTTPClient(config=HTTPClientConfig(versions=list(versions), limits=HTTPClientLimits(timeout_connection=15)))

class TestH1:
    async def test_plain_http(self):
        async with client(["HTTP/1.1"]) as http:
            response = await (await http.get("http://example.com/")).receive()

            assert response.version == "HTTP/1.1"
            assert response.status_code == 200
            assert b"Example Domain" in response.body

    async def test_https(self):
        async with client(["HTTP/1.1"]) as http:
            response = await (await http.get("https://www.cloudflare.com/")).receive()

            assert response.status_code == 200
            assert response.body # transparently decompressed

    async def test_a_redirect_status_is_surfaced_not_followed(self):
        async with client(["HTTP/1.1"]) as http:
            response = await (await http.get("http://cloudflare.com/")).receive()

            assert response.status_code in (301, 302, 307, 308)
            assert response.headers.get("Location")

class TestH2:
    async def test_https(self):
        async with client(["HTTP/2.0", "HTTP/1.1"]) as http:
            response = await (await http.get("https://www.cloudflare.com/")).receive()

            assert response.version == "HTTP/2.0"
            assert response.status_code == 200

    async def test_google(self):
        async with client(["HTTP/2.0", "HTTP/1.1"]) as http:
            response = await (await http.get("https://www.google.com/")).receive()

            assert response.version == "HTTP/2.0"
            assert response.status_code == 200

    async def test_concurrent_streams(self):
        import asyncio

        async with client(["HTTP/2.0", "HTTP/1.1"]) as http:
            connections = await asyncio.gather(
                http.get("https://www.cloudflare.com/"),
                http.get("https://www.cloudflare.com/robots.txt"),
                http.get("https://www.cloudflare.com/favicon.ico"),
            )
            responses = await asyncio.gather(*[c.receive() for c in connections])

            assert all(r.status_code in (200, 404) for r in responses)
            assert len(http.sessions) == 1

class TestH3:
    async def test_https(self):
        if not QTLS().available:
            pytest.skip("this OpenSSL has no QUIC client")

        async with client(["HTTP/3.0"]) as http:
            response = await (await http.get("https://cloudflare-quic.com/")).receive()

            assert response.version == "HTTP/3.0"
            assert response.status_code == 200

    async def test_google_h3(self):
        if not QTLS().available:
            pytest.skip("this OpenSSL has no QUIC client")

        async with client(["HTTP/3.0"]) as http:
            response = await (await http.get("https://www.google.com/")).receive()

            assert response.version == "HTTP/3.0"
            assert response.status_code == 200
