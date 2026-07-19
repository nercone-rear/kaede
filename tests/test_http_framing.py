"""Message framing, which is where a disagreement between two parsers becomes a smuggled request.

Every case here is written against the RFC clause it names, not against what Kaede currently
does, so a regression that reintroduces a permissive parse fails the test rather than
redefining it.
"""

import asyncio

import pytest

from kaede.constants import Digits
from kaede.url import URL
from kaede.tcp import TCPPort
from kaede.http.models import HTTPPort, HTTPHeaders, HTTPResponse
from kaede.http.errors import HTTPError
from kaede.http.api.server import HTTPServer, HTTPServerConfig, HTTPHandler

LOCAL = "127.0.0.1"

class Echo(HTTPHandler):
    async def on_connection(self, connection):
        request = await connection.receive()
        body = request.body if isinstance(request.body, bytes) else b""

        await connection.send(HTTPResponse(status_code=200, headers=HTTPHeaders(), body=b"echo:" + body, compression=False))

class Coded(HTTPHandler):
    """Answers with the status code named in the target, over a fixed eleven octet body."""

    async def on_connection(self, connection):
        request = await connection.receive()
        code = int(request.target.strip("/") or 200)

        await connection.send(HTTPResponse(status_code=code, headers=HTTPHeaders(), body=b"hello world", compression=False))

class Running:
    def __init__(self, handler, *, versions=("HTTP/1.1",)):
        self.server = HTTPServer(config=HTTPServerConfig(versions=list(versions)))
        self.handler = handler

    async def __aenter__(self):
        await self.server.listen(self.handler, [(LOCAL, HTTPPort("tcp", TCPPort(0)))])
        return self.server

    async def __aexit__(self, *_):
        await self.server.close(timeout=2)

async def exchange(server, payload: bytes, *, wait: float = 0.5) -> bytes:
    """Send raw octets and read whatever comes back before the peer goes quiet."""
    host, port = server.ports[0][0], int(server.ports[0][1].value)
    reader, writer = await asyncio.open_connection(host, port)

    writer.write(payload)
    await writer.drain()

    out = bytearray()

    try:
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), wait)

            if not chunk:
                break

            out += chunk

    except asyncio.TimeoutError:
        pass

    writer.close()
    return bytes(out)

def status(data: bytes) -> str:
    return data.decode("latin-1").split("\r\n")[0]

def field(data: bytes, name: str):
    lines = data.decode("latin-1").split("\r\n")

    return next((line.split(":", 1)[1].strip() for line in lines if line.lower().startswith(name.lower() + ":")), None)

class TestNumbers:
    """RFC 9112 §7.1 writes chunk-size as 1*HEXDIG and §6.2 writes Content-Length as 1*DIGIT.

    Python's int() accepts a much larger grammar than either, and str.isdigit() accepts
    characters int() then refuses, so neither can stand in for the ABNF.
    """

    @pytest.mark.parametrize("text", ["0x5", "1_0", "+5", "-5", " 5", "5 ", "", "5.0"])
    def test_a_chunk_size_outside_the_abnf_is_refused(self, text):
        assert Digits.hexadecimal(text) is None

    @pytest.mark.parametrize("text,value", [("5", 5), ("ff", 255), ("FF", 255), ("0", 0)])
    def test_a_chunk_size_inside_the_abnf_is_read(self, text, value):
        assert Digits.hexadecimal(text) == value

    @pytest.mark.parametrize("text", ["\xb2", "+5", "1_0", "-5", " 5", ""])
    def test_a_content_length_outside_the_abnf_is_refused(self, text):
        assert Digits.decimal(text) is None

    def test_a_superscript_two_passes_isdigit_but_is_not_a_number(self):
        # The exact pair that made isdigit() and int() disagree and raise out of the parser.
        assert "\xb2".isdigit()
        assert Digits.decimal("\xb2") is None

    @pytest.mark.parametrize("text", ["20", "2000", "\xb2", "+200", ""])
    def test_a_status_code_must_be_three_digits(self, text):
        assert Digits.decimal(text, width=3) is None

class TestAuthority:
    """RFC 3986 §3.2.2 for the uri-host that Host and :authority both have to be."""

    @pytest.mark.parametrize("value", ["a", "example.com", "example.com:8080", "[::1]", "[::1]:443", "a.b-c_d", "example.com:"])
    def test_a_valid_authority_is_accepted(self, value):
        assert URL.authority(value)

    @pytest.mark.parametrize("value", ["ev il", "a:b", "a\tb", "[::1", "[]", "exam\\ple.com", "a:80:80"])
    def test_an_invalid_authority_is_refused(self, value):
        assert not URL.authority(value)

@pytest.mark.asyncio
class TestRequestFraming:
    async def test_an_http_1_0_request_with_transfer_encoding_is_refused(self):
        """RFC 9112 §6.1 treats the framing as faulty and closes after the message.

        A Connection: keep-alive must not keep the connection open, or the bytes after the
        terminating chunk are read as a second request that no upstream proxy ever saw.
        """
        async with Running(Echo()) as server:
            out = await exchange(server, (
                b"POST / HTTP/1.0\r\nHost: a\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"5\r\nHELLO\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: a\r\n\r\n"
            ))

        assert status(out).startswith("HTTP/1.1 400")
        assert out.count(b"200 OK") == 0

    async def test_transfer_encoding_and_content_length_together_are_refused(self):
        # RFC 9112 §6.1: the message is ill formed, and the connection has to close.
        async with Running(Echo()) as server:
            out = await exchange(server, (
                b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: a\r\n\r\n"
            ))

        assert status(out).startswith("HTTP/1.1 400")
        assert out.count(b"200 OK") == 0

    @pytest.mark.parametrize("size", [b"0x5", b"1_0", b"+5", b"-5", b"5 "])
    async def test_a_chunk_size_outside_the_abnf_is_refused_on_the_wire(self, size):
        async with Running(Echo()) as server:
            out = await exchange(server, (
                b"POST / HTTP/1.1\r\nHost: a\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n"
                + size + b"\r\nHELLO\r\n0\r\n\r\n"
            ))

        assert status(out).startswith("HTTP/1.1 400")

    async def test_a_chunk_extension_may_be_preceded_by_whitespace(self):
        # RFC 9112 §7.1.1 writes chunk-ext as *( BWS ";" BWS ... ), so 5 ;name is well formed.
        async with Running(Echo()) as server:
            out = await exchange(server, (
                b"POST / HTTP/1.1\r\nHost: a\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"5 ;name=value\r\nHELLO\r\n0\r\n\r\n"
            ))

        assert status(out).startswith("HTTP/1.1 200")
        assert out.endswith(b"echo:HELLO")

    async def test_a_content_length_outside_the_abnf_answers_400(self):
        # A ValueError escaping the parser produced no response at all and a full traceback.
        async with Running(Echo()) as server:
            out = await exchange(server, b"POST / HTTP/1.1\r\nHost: a\r\nConnection: close\r\nContent-Length: \xb2\r\n\r\n")

        assert status(out).startswith("HTTP/1.1 400")

    async def test_a_forbidden_field_in_a_trailer_section_is_refused(self):
        # RFC 9110 §6.5.1 keeps framing fields out of a trailer section.
        async with Running(Echo()) as server:
            out = await exchange(server, (
                b"POST / HTTP/1.1\r\nHost: a\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"0\r\nContent-Length: 5\r\n\r\n"
            ))

        assert status(out).startswith("HTTP/1.1 400")

@pytest.mark.asyncio
class TestHost:
    """RFC 9112 §3.2 answers 400 to a missing, repeated or invalid Host on an HTTP/1.1 request."""

    async def test_an_http_1_1_request_without_host_is_refused(self):
        async with Running(Echo()) as server:
            out = await exchange(server, b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n")

        assert status(out).startswith("HTTP/1.1 400")

    async def test_a_repeated_host_is_refused(self):
        # Kaede reads the first value and a downstream cache may key on the last one.
        async with Running(Echo()) as server:
            out = await exchange(server, b"GET / HTTP/1.1\r\nHost: a\r\nHost: evil\r\nConnection: close\r\n\r\n")

        assert status(out).startswith("HTTP/1.1 400")

    async def test_an_invalid_host_value_is_refused(self):
        async with Running(Echo()) as server:
            out = await exchange(server, b"GET / HTTP/1.1\r\nHost: ev il\r\nConnection: close\r\n\r\n")

        assert status(out).startswith("HTTP/1.1 400")

    async def test_a_single_valid_host_is_accepted(self):
        async with Running(Echo()) as server:
            out = await exchange(server, b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")

        assert status(out).startswith("HTTP/1.1 200")

    async def test_an_http_1_0_request_without_host_is_accepted(self):
        # §3.2 puts the requirement on HTTP/1.1 only, since HTTP/1.0 predates the field.
        async with Running(Echo()) as server:
            out = await exchange(server, b"GET / HTTP/1.0\r\nConnection: close\r\n\r\n")

        assert status(out).startswith("HTTP/1.1 200")

    async def test_the_request_url_carries_the_authority(self):
        # The URL is built when the request line is read, before the header block arrives,
        # so it has to be recomputed once Host is known or the authority stays empty.
        seen = {}

        class Watch(HTTPHandler):
            async def on_connection(self, connection):
                request = await connection.receive()
                seen["host"] = request.url.host

                await connection.send(HTTPResponse(status_code=200, headers=HTTPHeaders(), body=b"", compression=False))

        async with Running(Watch()) as server:
            await exchange(server, b"GET /p?q=1 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")

        assert seen["host"] == "example.com"

@pytest.mark.asyncio
class TestResponseFraming:
    """RFC 9110 §8.6 on which responses may carry Content-Length, and §6.6.1 on Date."""

    async def test_a_head_response_advertises_the_length_a_get_would_have_sent(self):
        async with Running(Coded()) as server:
            head = await exchange(server, b"HEAD /200 HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
            get = await exchange(server, b"GET /200 HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")

        assert field(get, "Content-Length") == "11"
        assert field(head, "Content-Length") == "11"
        assert not head.endswith(b"hello world") # the body itself is still withheld

    async def test_a_204_carries_no_content_length(self):
        async with Running(Coded()) as server:
            out = await exchange(server, b"GET /204 HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")

        assert status(out).startswith("HTTP/1.1 204")
        assert field(out, "Content-Length") is None

    async def test_a_304_may_carry_the_length_of_its_content(self):
        # §15.4.5 lets a 304 repeat the header fields a 200 would have sent.
        async with Running(Coded()) as server:
            out = await exchange(server, b"GET /304 HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")

        assert status(out).startswith("HTTP/1.1 304")
        assert not out.endswith(b"hello world")

    @pytest.mark.parametrize("code", [200, 301, 404])
    async def test_an_ordinary_response_carries_a_date(self, code):
        # §6.6.1 requires Date on every 2xx, 3xx and 4xx an origin server sends.
        async with Running(Coded()) as server:
            out = await exchange(server, f"GET /{code} HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n".encode())

        assert field(out, "Date") is not None
        assert field(out, "Date").endswith("GMT")

@pytest.mark.asyncio
class TestStartLine:
    async def test_empty_lines_before_the_request_line_are_ignored(self):
        # RFC 9112 §2.2 asks a server to skip them rather than answer them with a 400.
        async with Running(Echo()) as server:
            out = await exchange(server, b"\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")

        assert status(out).startswith("HTTP/1.1 200")

    async def test_a_bare_cr_in_the_request_target_is_refused(self):
        async with Running(Echo()) as server:
            out = await exchange(server, b"GET /a\rb HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")

        assert status(out).startswith("HTTP/1.1 400")

    async def test_a_method_that_is_not_a_token_is_refused(self):
        async with Running(Echo()) as server:
            out = await exchange(server, b"G(ET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")

        assert status(out).startswith("HTTP/1.1 400")
