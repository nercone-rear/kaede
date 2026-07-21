import asyncio
from ssl import CERT_NONE

import pytest

from kaede.tls import TLSConfig
from kaede.tcp import TCPPort
from kaede.http.models import HTTPPort, HTTPHeaders, HTTPResponse, HTTPBroadRole
from kaede.http.responses import JSONResponse, PlainTextResponse
from kaede.http.errors import HTTPError
from kaede.http.finalizer import finalize_response
from kaede.http.api.server import HTTPServer, HTTPServerConfig, HTTPHandler
from kaede.http.api.client import HTTPClient, HTTPClientConfig, HTTPClientLimits
from kaede.http.protocol.h2 import H2Settings, H2Frame, Frame, H2Connection, H2StreamError

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
    def __init__(self, handler=None, *, certificate, versions=("HTTP/1.1", "HTTP/2.0"), body_limit=None):
        certfile, keyfile = certificate

        config = HTTPServerConfig(versions=list(versions))
        config.tls = TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE)

        if body_limit is not None:
            config.limits.max_message_body_size = body_limit

        self.server = HTTPServer(config=config)
        self.handler = handler or Echo()

    async def __aenter__(self):
        await self.server.listen(self.handler, [(LOCAL, HTTPPort("tcp", TCPPort(0)))])
        return self.server

    async def __aexit__(self, *_):
        await self.server.close(timeout=2)

def endpoint(server) -> str:
    host, port = server.ports[0]

    return f"https://{LOCAL}:{int(port.value)}"

def client(authority, *, versions=("HTTP/2.0", "HTTP/1.1")) -> HTTPClient:
    config = HTTPClientConfig(versions=list(versions), limits=HTTPClientLimits(timeout_connection=5))
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

class TestBodyLimit:
    # RFC 9113 has no per-stream body cap of its own, but an unbounded receive
    # buffer is a memory-exhaustion vector, so the server must stop a stream
    # whose data exceeds the configured limit instead of buffering it all. h1
    # answers 413 and h3 raises H3_EXCESSIVE_LOAD for the same reason; h2 has to
    # be symmetric with them.

    async def test_a_body_within_the_limit_still_round_trips(self, server_certificate, authority):
        async with Running(certificate=server_certificate, body_limit=4096) as server:
            async with client(authority) as http:
                response = await (await http.post(endpoint(server) + "/", body=b"a" * 4096)).receive()

                assert len(response.json["body"]) == 4096

    async def test_a_body_over_the_limit_resets_the_stream(self, server_certificate, authority):
        # A body that fits in the initial flow-control window is sent in one
        # burst, so the reset is observed on the response rather than racing the
        # send. 8 KiB is over the 1 KiB limit but well under the 64 KiB window.
        async with Running(certificate=server_certificate, body_limit=1024) as server:
            async with client(authority) as http:
                with pytest.raises(HTTPError) as caught:
                    await (await http.post(endpoint(server) + "/", body=b"a" * 8192)).receive()

                # ENHANCE_YOUR_CALM (0xb) surfaced as a 502 from the reset stream.
                assert caught.value.code == 502
                assert "11" in str(caught.value)

class Stub:
    """The little a header block needs from its session to be split apart."""

    class remote:
        initial_window_size = 65535

    transport = None
    limits = None
    observer = None

class TestPseudoHeaders:
    # RFC 9113 section 8.2.1: a field value carrying NUL, CR, or LF makes the
    # message malformed. Regular header values are cleaned by HTTPHeaders, but
    # pseudo-header values (:method, :path, ...) are consumed directly, so a
    # control character in :path would otherwise be a request-splitting or
    # log-injection primitive once the value is reused downstream.

    def connection(self) -> H2Connection:
        return H2Connection(Stub(), 1, role=HTTPBroadRole.SERVER)

    @pytest.mark.parametrize("value", ["/x\r\nx-injected: 1", "/x\nfoo", "/x\rfoo", "/x\x00", "\x7f"])
    def test_a_control_character_in_a_pseudo_header_is_rejected(self, value):
        fields = [(":method", "GET"), (":scheme", "https"), (":authority", "example.com"), (":path", value)]

        with pytest.raises(H2StreamError):
            self.connection().split(fields, trailer=False)

    def test_a_clean_path_is_accepted(self):
        fields = [(":method", "GET"), (":scheme", "https"), (":authority", "example.com"), (":path", "/ok")]
        pseudo, _ = self.connection().split(fields, trailer=False)

        assert pseudo[":path"] == "/ok"

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

class TestECH:
    async def test_the_client_hello_is_encrypted_over_h2(self, server_certificate, authority, ech_keys):
        server_certfile, server_keyfile = server_certificate

        config = HTTPServerConfig(versions=["HTTP/1.1", "HTTP/2.0"])
        config.tls = TLSConfig(certfile=server_certfile, keyfile=server_keyfile, verify_mode=CERT_NONE, echfile=ech_keys.pemfile)

        server = HTTPServer(config=config)

        try:
            await server.listen(Echo(), [(LOCAL, HTTPPort("tcp", TCPPort(0)))])

            client_config = HTTPClientConfig(versions=["HTTP/2.0", "HTTP/1.1"], limits=HTTPClientLimits(timeout_connection=5))
            client_config.tls = TLSConfig(cafile=authority.ca)
            client_config.ech = ech_keys.configlist

            async with HTTPClient(config=client_config) as http:
                connection = await http.get(endpoint(server) + "/hello")
                response = await connection.receive()

                assert response.status_code == 200

                session, _ = next(iter(http.sessions.values()))
                assert session.transport.ech_status.succeeded
                assert session.transport.ech_status.outer_sni == ech_keys.public_name

        finally:
            await server.close(timeout=2)
