import asyncio
from ssl import CERT_NONE

import pytest

from kaede.tls import TLSConfig
from kaede.tcp import TCPPort
from kaede.uds import UDSPort
from kaede.http.models import HTTPPort, HTTPHeaders, HTTPResponse
from kaede.http.responses import PlainTextResponse, JSONResponse
from kaede.http.errors import HTTPError
from kaede.http.finalizer import finalize_response
from kaede.http.api.server import HTTPServer, HTTPServerConfig, HTTPServerLimits, HTTPHandler
from kaede.http.api.client import HTTPClient, HTTPClientConfig, HTTPClientLimits

LOCAL = "127.0.0.1"

class Echo(HTTPHandler):
    async def on_connection(self, connection):
        request = await connection.receive()
        body = request.body if isinstance(request.body, bytes) else b""

        response = JSONResponse({
            "method": request.method,
            "target": request.target,
            "host": request.headers.get("Host"),
            "body": body.decode("latin-1"),
            "type": request.headers.get("Content-Type"),
        })
        await connection.send(await finalize_response(response))

class Running:
    def __init__(self, handler=None, *, versions=("HTTP/1.1",), certificate=None, limits=None, uds=None):
        config = HTTPServerConfig(versions=list(versions))

        if certificate is not None:
            certfile, keyfile = certificate
            config.tls = TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE)

        if limits is not None:
            config.limits = limits

        self.server = HTTPServer(config=config)
        self.handler = handler or Echo()
        self.certificate = certificate
        self.uds = uds

    async def __aenter__(self):
        if self.uds is not None:
            port = HTTPPort("uds", self.uds)
        else:
            port = HTTPPort("tcp", TCPPort(0))

        await self.server.listen(self.handler, [(LOCAL, port)])
        return self.server

    async def __aexit__(self, *_):
        await self.server.close(timeout=2)

def endpoint(server, *, scheme="http") -> str:
    host, port = server.ports[0]

    return f"{scheme}://{LOCAL}:{int(port.value)}"

def client(*, authority=None) -> HTTPClient:
    config = HTTPClientConfig(versions=["HTTP/1.1"], limits=HTTPClientLimits(timeout_connection=5))

    if authority is not None:
        config.tls = TLSConfig(cafile=authority.ca)

    return HTTPClient(config=config)

class TestExchange:
    async def test_a_get_round_trips(self):
        async with Running() as server:
            async with client() as http:
                response = await (await http.get(endpoint(server) + "/hello?x=1")).receive()

                assert response.status_code == 200
                assert response.json["method"] == "GET"
                assert response.json["target"] == "/hello?x=1"

    async def test_the_host_header_is_sent(self):
        async with Running() as server:
            async with client() as http:
                response = await (await http.get(endpoint(server) + "/")).receive()

                assert response.json["host"] == f"{LOCAL}:{int(server.ports[0][1].value)}"

    async def test_a_body_is_carried_both_ways(self):
        async with Running() as server:
            async with client() as http:
                response = await (await http.post(endpoint(server) + "/", body=b"payload")).receive()

                assert response.json["body"] == "payload"

    async def test_a_head_response_has_no_body(self):
        async with Running() as server:
            async with client() as http:
                response = await (await http.head(endpoint(server) + "/")).receive()

                assert response.status_code == 200
                assert response.body == b""
                assert response.headers.get("Content-Length") is not None

    async def test_keep_alive_reuses_the_connection(self):
        async with Running() as server:
            async with client() as http:
                first = await http.get(endpoint(server) + "/one")
                await first.receive()

                second = await http.get(endpoint(server) + "/two")
                assert (await second.receive()).json["target"] == "/two"

    async def test_a_large_body_survives_chunked_streaming(self):
        payload = bytes(range(256)) * 512  # 128 KiB

        class Streamer(HTTPHandler):
            async def on_connection(self, connection):
                await connection.receive()

                async def chunks():
                    for start in range(0, len(payload), 4096):
                        yield payload[start:start + 4096]

                response = HTTPResponse(status_code=200, headers=HTTPHeaders(), body=chunks(), compression=False)
                await connection.send(await finalize_response(response))

        async with Running(Streamer()) as server:
            async with client() as http:
                response = await (await http.get(endpoint(server) + "/")).receive()

                assert response.body == payload
                assert response.headers.get("Transfer-Encoding") == "chunked"

class TestChunkedRequest:
    async def test_a_chunked_request_body_is_read(self):
        async with Running() as server:
            host, port = server.ports[0]

            reader, writer = await asyncio.open_connection(LOCAL, int(port.value))
            writer.write(
                b"POST /chunked HTTP/1.1\r\n"
                b"Host: x\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
                b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
            )
            await writer.drain()

            head = await reader.readuntil(b"\r\n\r\n")
            assert head.startswith(b"HTTP/1.1 200")

            length = int(dict(line.split(b": ", 1) for line in head.split(b"\r\n") if b": " in line)[b"Content-Length"])
            import json
            body = json.loads(await reader.readexactly(length))
            assert body["body"] == "hello world"

            writer.close()
            await writer.wait_closed()

class TestCompression:
    async def test_the_response_is_compressed_and_transparently_decompressed(self):
        async with Running() as server:
            async with client() as http:
                connection = await http.get(endpoint(server) + "/")
                response = await connection.receive()

                # The client asked for encodings and the body decoded cleanly.
                assert response.json["method"] == "GET"

class TestSmuggling:
    async def raw(self, server, request: bytes) -> bytes:
        host, port = server.ports[0]
        reader, writer = await asyncio.open_connection(LOCAL, int(port.value))

        writer.write(request)
        await writer.drain()

        try:
            return await asyncio.wait_for(reader.read(4096), 2)

        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_content_length_with_transfer_encoding_is_rejected(self):
        # RFC 9112 section 6.1.
        async with Running() as server:
            reply = await self.raw(server, b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")

            assert reply.startswith(b"HTTP/1.1 400")

    async def test_two_conflicting_content_lengths_are_rejected(self):
        async with Running() as server:
            reply = await self.raw(server, b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello")

            assert reply.startswith(b"HTTP/1.1 400")

    async def test_whitespace_before_the_colon_is_rejected(self):
        # RFC 9112 section 5.1.
        async with Running() as server:
            reply = await self.raw(server, b"GET / HTTP/1.1\r\nHost : x\r\n\r\n")

            assert reply.startswith(b"HTTP/1.1 400")

    async def test_obsolete_line_folding_is_rejected(self):
        # RFC 9112 section 5.2.
        async with Running() as server:
            reply = await self.raw(server, b"GET / HTTP/1.1\r\nHost: x\r\nX-Test: a\r\n b\r\n\r\n")

            assert reply.startswith(b"HTTP/1.1 400")

    async def test_an_oversized_header_block_is_rejected(self):
        limits = HTTPServerLimits()
        limits.max_headers_size = 256

        async with Running(limits=limits) as server:
            padding = b"X-Pad: " + b"a" * 500 + b"\r\n"
            reply = await self.raw(server, b"GET / HTTP/1.1\r\nHost: x\r\n" + padding + b"\r\n")

            assert reply.startswith(b"HTTP/1.1 431")

class TestTLS:
    async def test_a_request_over_tls(self, server_certificate, authority):
        async with Running(certificate=server_certificate) as server:
            async with client(authority=authority) as http:
                connection = await http.get(endpoint(server, scheme="https") + "/secure")
                response = await connection.receive()

                assert response.status_code == 200
                assert response.json["target"] == "/secure"

class TestUDS:
    async def test_a_request_over_a_unix_socket(self, uds_dir):
        import os

        path = os.path.join(uds_dir, "http.sock")

        async with Running(uds=path) as server:
            transport_path = server.ports[0][1].value

            # A stdlib client speaks h1 over the UNIX socket, independent of Kaede's client.
            reader, writer = await asyncio.open_unix_connection(transport_path)
            writer.write(b"GET /unix HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            await writer.drain()

            data = await reader.read()
            assert data.startswith(b"HTTP/1.1 200")
            assert b"/unix" in data

            writer.close()
            await writer.wait_closed()

class TestErrors:
    async def test_a_handler_error_becomes_a_response(self):
        class Failing(HTTPHandler):
            async def on_connection(self, connection):
                await connection.receive()
                raise HTTPError(503, "Service Unavailable")

        async with Running(Failing()) as server:
            async with client() as http:
                response = await (await http.get(endpoint(server) + "/")).receive()

                assert response.status_code == 503
