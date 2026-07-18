import asyncio
from ssl import CERT_NONE

import pytest

from kaede.tls import TLSConfig
from kaede.udp import UDPPort
from kaede.quic.tls import QTLS
from kaede.http.models import HTTPPort, HTTPHeaders, HTTPResponse
from kaede.http.responses import JSONResponse
from kaede.http.errors import HTTPError
from kaede.http.finalizer import finalize_response
from kaede.http.api.server import HTTPServer, HTTPServerConfig, HTTPHandler
from kaede.http.api.client import HTTPClient, HTTPClientConfig

LOCAL = "127.0.0.1"

@pytest.fixture(scope="module", autouse=True)
def servable():
    if not QTLS().servable:
        pytest.skip("an HTTP/3 server needs OpenSSL 4.0 or newer")

class Echo(HTTPHandler):
    async def on_connection(self, connection):
        request = await connection.receive()
        body = request.body if isinstance(request.body, bytes) else b""

        await connection.send(await finalize_response(JSONResponse({
            "version": request.version,
            "method": request.method,
            "target": request.target,
            "host": request.headers.get("Host"),
            "body": body.decode("latin-1"),
        })))

class Running:
    def __init__(self, handler=None, *, certificate):
        certfile, keyfile = certificate

        config = HTTPServerConfig(versions=["HTTP/3.0"])
        config.tls = TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE)
        config.handshake_timeout = 10

        self.server = HTTPServer(config=config)
        self.handler = handler or Echo()

    async def __aenter__(self):
        await self.server.listen(self.handler, [(LOCAL, HTTPPort("quic", UDPPort(0), True))])
        return self.server

    async def __aexit__(self, *_):
        await self.server.close(timeout=3)

def endpoint(server) -> str:
    host, port = server.ports[0]

    return f"https://{LOCAL}:{int(port.value)}"

def client(authority) -> HTTPClient:
    config = HTTPClientConfig(versions=["HTTP/3.0"], connect_timeout=10)
    config.tls = TLSConfig(cafile=authority.ca)

    return HTTPClient(config=config)

class TestExchange:
    async def test_a_get_over_h3(self, server_certificate, authority):
        async with Running(certificate=server_certificate) as server:
            async with client(authority) as http:
                response = await (await http.get(endpoint(server) + "/hello")).receive()

                assert response.version == "HTTP/3.0"
                assert response.status_code == 200
                assert response.json["target"] == "/hello"

    async def test_the_authority_becomes_the_host(self, server_certificate, authority):
        async with Running(certificate=server_certificate) as server:
            async with client(authority) as http:
                response = await (await http.get(endpoint(server) + "/")).receive()

                assert response.json["host"] == f"{LOCAL}:{int(server.ports[0][1].value)}"

    async def test_a_body_round_trips(self, server_certificate, authority):
        async with Running(certificate=server_certificate) as server:
            async with client(authority) as http:
                response = await (await http.post(endpoint(server) + "/", body=b"payload")).receive()

                assert response.json["body"] == "payload"

    async def test_many_requests_share_one_connection(self, server_certificate, authority):
        async with Running(certificate=server_certificate) as server:
            async with client(authority) as http:
                connections = await asyncio.gather(*[http.get(endpoint(server) + f"/n{i}") for i in range(8)])
                responses = await asyncio.gather(*[c.receive() for c in connections])

                assert {r.json["target"] for r in responses} == {f"/n{i}" for i in range(8)}
                assert len(http.tunnels) == 1

    async def test_a_body_larger_than_one_packet(self, server_certificate, authority):
        payload = bytes(range(256)) * 512  # 128 KiB

        class Big(HTTPHandler):
            async def on_connection(self, connection):
                await connection.receive()
                await connection.send(await finalize_response(HTTPResponse(status_code=200, headers=HTTPHeaders(), body=payload, compression=False)))

        async with Running(Big(), certificate=server_certificate) as server:
            async with client(authority) as http:
                response = await (await http.get(endpoint(server) + "/big")).receive()

                assert response.body == payload

class TestErrors:
    async def test_a_handler_error_becomes_a_response(self, server_certificate, authority):
        class Failing(HTTPHandler):
            async def on_connection(self, connection):
                await connection.receive()
                raise HTTPError(503, "Service Unavailable")

        async with Running(Failing(), certificate=server_certificate) as server:
            async with client(authority) as http:
                response = await (await http.get(endpoint(server) + "/")).receive()

                assert response.status_code == 503
