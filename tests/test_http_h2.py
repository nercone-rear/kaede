import asyncio
from ssl import CERT_NONE

import pytest

from kaede.tls import TLSConfig
from kaede.tcp import TCPPort
from kaede.http.models import HTTPPort, HTTPHeaders, HTTPResponse
from kaede.http.responses import JSONResponse, PlainTextResponse
from kaede.http.errors import HTTPError
from kaede.http.finalizer import finalize_response
from kaede.http.api.server import HTTPServer, HTTPServerConfig, HTTPHandler
from kaede.http.api.client import HTTPClient, HTTPClientConfig
from kaede.http.protocol.h2 import H2Settings, H2Frame, Frame

LOCAL = "127.0.0.1"

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
    def __init__(self, handler=None, *, certificate, versions=("HTTP/1.1", "HTTP/2.0")):
        certfile, keyfile = certificate

        config = HTTPServerConfig(versions=list(versions))
        config.tls = TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE)

        self.server = HTTPServer(config=config)
        self.handler = handler or Echo()

    async def __aenter__(self):
        await self.server.listen(self.handler, [(LOCAL, HTTPPort("tcp", TCPPort(0), True))])
        return self.server

    async def __aexit__(self, *_):
        await self.server.close(timeout=2)

def endpoint(server) -> str:
    host, port = server.ports[0]

    return f"https://{LOCAL}:{int(port.value)}"

def client(authority, *, versions=("HTTP/2.0", "HTTP/1.1")) -> HTTPClient:
    config = HTTPClientConfig(versions=list(versions), connect_timeout=5)
    config.tls = TLSConfig(cafile=authority.ca)

    return HTTPClient(config=config)

class TestExchange:
    async def test_a_get_negotiates_h2(self, server_certificate, authority):
        async with Running(certificate=server_certificate) as server:
            async with client(authority) as http:
                response = await (await http.get(endpoint(server) + "/hello")).receive()

                assert response.version == "HTTP/2.0"
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

    async def test_many_streams_multiplex_on_one_connection(self, server_certificate, authority):
        async with Running(certificate=server_certificate) as server:
            async with client(authority) as http:
                connections = await asyncio.gather(*[http.get(endpoint(server) + f"/n{i}") for i in range(20)])
                responses = await asyncio.gather(*[c.receive() for c in connections])

                assert {r.json["target"] for r in responses} == {f"/n{i}" for i in range(20)}
                assert len(http.sessions) == 1

    async def test_falls_back_to_h1_when_h2_is_not_offered(self, server_certificate, authority):
        async with Running(certificate=server_certificate, versions=["HTTP/1.1"]) as server:
            async with client(authority) as http:
                response = await (await http.get(endpoint(server) + "/")).receive()

                assert response.version == "HTTP/1.1"

class TestFlowControl:
    async def test_a_large_body_crosses_many_frames(self, server_certificate, authority):
        payload = bytes(range(256)) * 2048  # 512 KiB, well over one 16 KiB frame and the 64 KiB window

        class Big(HTTPHandler):
            async def on_connection(self, connection):
                await connection.receive()
                await connection.send(await finalize_response(HTTPResponse(status_code=200, headers=HTTPHeaders(), body=payload, compression=False)))

        async with Running(Big(), certificate=server_certificate) as server:
            async with client(authority) as http:
                response = await (await http.get(endpoint(server) + "/big")).receive()

                assert response.body == payload

    async def test_a_large_request_body_is_received(self, server_certificate, authority):
        payload = b"a" * (256 * 1024)

        async with Running(certificate=server_certificate) as server:
            async with client(authority) as http:
                response = await (await http.post(endpoint(server) + "/", body=payload)).receive()

                assert len(response.json["body"]) == len(payload)

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

class TestSettings:
    def test_the_defaults_disable_push(self):
        assert H2Settings().enable_push == 0

    def test_settings_round_trip(self):
        settings = H2Settings(initial_window_size=1000, max_frame_size=32768)
        parsed = H2Settings()
        parsed.apply(settings.pack())

        assert parsed.initial_window_size == 1000
        assert parsed.max_frame_size == 32768

    def test_a_bad_frame_size_is_rejected(self):
        from kaede.http.protocol.h2 import H2Error

        payload = (5).to_bytes(2, "big") + (100).to_bytes(4, "big") # max_frame_size below 16384

        with pytest.raises(H2Error):
            H2Settings().apply(payload)

    def test_a_truncated_settings_payload_is_rejected(self):
        from kaede.http.protocol.h2 import H2Error

        with pytest.raises(H2Error):
            H2Settings().apply(b"\x00\x01\x00")

class TestFrames:
    def test_a_frame_packs_to_the_wire_shape(self):
        frame = H2Frame(Frame.DATA, 0x1, 3, b"hi")
        wire = frame.pack()

        assert wire[0:3] == (2).to_bytes(3, "big")
        assert wire[3] == Frame.DATA
        assert wire[4] == 0x1
        assert int.from_bytes(wire[5:9], "big") == 3
        assert wire[9:] == b"hi"
