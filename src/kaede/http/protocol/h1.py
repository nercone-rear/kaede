import os
from typing import Optional, Union, List, Tuple
from collections.abc import AsyncIterator

from ...tcp.errors import TCPError, TCPClosedError, TCPLostError, TCPLimitError, TCPTimeoutError
from ...uds.errors import UDSError, UDSClosedError, UDSLostError, UDSLimitError, UDSTimeoutError
from ...tls.errors import TLSError
from ..models import HTTPBroadRole, HTTPRole, HTTPHeaders, HTTPMessage, HTTPRequest, HTTPResponse
from ..headers import CommaHeader
from ..errors import HTTPError, HTTPReportedViolationError
from ..helpers.compression import compress, decompress
from .connection import HTTPConnection, HTTPState

class H1Connection(HTTPConnection):
    REASONS = {
        100: "Continue", 101: "Switching Protocols",
        200: "OK", 201: "Created", 202: "Accepted", 204: "No Content", 206: "Partial Content",
        301: "Moved Permanently", 302: "Found", 303: "See Other", 304: "Not Modified", 307: "Temporary Redirect", 308: "Permanent Redirect",
        400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 408: "Request Timeout", 411: "Length Required", 413: "Content Too Large", 414: "URI Too Long", 426: "Upgrade Required", 431: "Request Header Fields Too Large",
        500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway", 503: "Service Unavailable", 505: "HTTP Version Not Supported"
    }

    CLOSED = (TCPClosedError, TCPLostError, TCPTimeoutError, UDSClosedError, UDSLostError, UDSTimeoutError)

    def __init__(self, src, dst, *, transport, role: HTTPBroadRole = HTTPBroadRole.SERVER, version="HTTP/1.1", limits=None):
        super().__init__(src, dst, transport=transport, version=version, limits=limits)

        self.role = role

        self.request: Optional[HTTPRequest] = None
        self.response: Optional[HTTPResponse] = None

        self.received = False
        self.replied = False
        self.continued = False

        self.closing = False

    @property
    def reusable(self) -> bool:
        return not self.closing and not self.transport.closed

    async def begin(self) -> bool:
        try:
            line = await self.transport.receive_until(b"\r\n", limit=self.limits.max_startline_size)

        except (TCPLimitError, UDSLimitError):
            raise HTTPError(414, "URI Too Long")

        except H1Connection.CLOSED:
            return False

        self.reset_exchange()
        self.request = self.request_from(line[:-2])
        self.request.headers = await self.head()
        self.frame(self.request.headers, request=True)
        self.state = HTTPState.RECEIVED_HEADERS

        connection = CommaHeader(self.request.headers.get("Connection", "")).raw
        self.closing = any(token.lower() == "close" for token in connection) or (self.request.version == "HTTP/1.0" and not any(token.lower() == "keep-alive" for token in connection))

        return True

    def request_from(self, line: bytes) -> HTTPRequest:
        try:
            method, target, version = line.decode("latin-1").split(" ")

        except ValueError:
            raise HTTPError(400, "Bad Request")

        if version not in ("HTTP/1.0", "HTTP/1.1"):
            raise HTTPError(505, "HTTP Version Not Supported")

        return HTTPRequest(version=version, method=method, target=target, client=self.dst, secure=self.secure, headers=HTTPHeaders())

    @property
    def secure(self) -> bool:
        return hasattr(self.transport, "session")

    async def head(self) -> HTTPHeaders:
        block = bytearray()
        count = 0

        while True:
            try:
                line = await self.transport.receive_until(b"\r\n", limit=self.limits.max_headers_size)

            except (TCPLimitError, UDSLimitError):
                raise HTTPError(431, "Request Header Fields Too Large")

            if line == b"\r\n":
                break

            block += line
            count += 1

            if len(block) > self.limits.max_headers_size or count > self.limits.max_header_count:
                raise HTTPError(431, "Request Header Fields Too Large")

        try:
            return HTTPHeaders.parse(bytes(block), self.version)

        except ValueError as e:
            raise HTTPError(400, f"Bad Request: {e}")

    def frame(self, headers: HTTPHeaders, *, request: bool) -> Tuple[bool, int]:
        te = headers.values("Transfer-Encoding")
        cl = headers.values("Content-Length")

        if te and cl:
            raise HTTPError(400, "Both Transfer-Encoding and Content-Length are present.")

        if te:
            codings = [token.strip().lower() for value in te for token in value.split(",") if token.strip()]

            if codings == ["chunked"]:
                return (True, 0)

            if codings[-1:] == ["chunked"]:
                raise HTTPError(501, "Only the chunked transfer coding is supported.")

            raise HTTPError(400, "Transfer-Encoding does not end in chunked.")

        if cl:
            values = {token.strip() for value in cl for token in value.split(",") if token.strip()}

            if len(values) != 1:
                raise HTTPError(400, "Content-Length is inconsistent.")

            only = next(iter(values))

            if not only.isdigit():
                raise HTTPError(400, "Content-Length is malformed.")

            length = int(only)

            if length > self.limits.max_message_body_size:
                raise HTTPError(413, "Content Too Large")

            return (False, length)

        return (False, 0 if request else -1)

    async def body(self, chunked: bool, length: int) -> bytes:
        if chunked:
            return await self.dechunk()

        if length == 0:
            return b""

        if length < 0:
            return await self.gather()

        try:
            return await self.transport.receive_exactly(length)

        except H1Connection.CLOSED as e:
            raise HTTPError(400, f"The body ended early: {e}")

    async def gather(self) -> bytes:
        data = bytearray()

        while True:
            chunk = await self.transport.receive(65536)

            if not chunk:
                return bytes(data)

            data += chunk

            if len(data) > self.limits.max_message_body_size:
                raise HTTPError(413, "Content Too Large")

    async def dechunk(self) -> bytes:
        data = bytearray()

        while True:
            try:
                line = await self.transport.receive_until(b"\r\n", limit=self.limits.max_chunk_ext_size)

            except (TCPLimitError, UDSLimitError):
                raise HTTPError(400, "A chunk size line is too long.")

            token = line[:-2].split(b";", 1)[0].strip()

            try:
                size = int(token, 16)

            except ValueError:
                raise HTTPError(400, "A chunk size is not hexadecimal.")

            if size < 0:
                raise HTTPError(400, "A chunk size is negative.")

            if size == 0:
                self.trailers = await self.head()
                return bytes(data)

            try:
                chunk = await self.transport.receive_exactly(size)
                crlf = await self.transport.receive_exactly(2)

            except H1Connection.CLOSED as e:
                raise HTTPError(400, f"A chunk ended early: {e}")

            if crlf != b"\r\n":
                raise HTTPError(400, "A chunk is not terminated by CRLF.")

            data += chunk

            if len(data) > self.limits.max_message_body_size:
                raise HTTPError(413, "Content Too Large")

    async def receive_message(self) -> Optional[HTTPMessage]:
        if self.role == HTTPBroadRole.SERVER:
            if self.request is None and not await self.begin():
                return None

            await self.serve_continue()

            chunked, length = self.frame(self.request.headers, request=True)
            self.request.body = await self.body(chunked, length)
            self.absorb(self.request)
            self.received = True
            self.state = HTTPState.RECEIVED

            return self.request

        return await self.take_response()

    async def take_response(self) -> HTTPResponse:
        try:
            line = await self.transport.receive_until(b"\r\n", limit=self.limits.max_startline_size)

        except (TCPLimitError, UDSLimitError):
            raise HTTPError(400, "The status line is too long.")

        parts = line[:-2].decode("latin-1").split(" ", 2)

        if len(parts) < 2 or not parts[1].isdigit():
            raise HTTPError(400, "The status line is malformed.")

        self.response = HTTPResponse(version=parts[0], status_code=int(parts[1]), secure=self.secure, headers=await self.head())

        bodiless = self.response.status_code < 200 or self.response.status_code in (204, 304) or (self.request is not None and self.request.method == "HEAD")
        chunked, length = self.frame(self.response.headers, request=False)

        self.response.body = b"" if bodiless else await self.body(chunked, length)
        self.absorb(self.response)
        self.received = True

        connection = CommaHeader(self.response.headers.get("Connection", "")).raw
        self.closing = any(token.lower() == "close" for token in connection) or (self.response.version == "HTTP/1.0" and not any(token.lower() == "keep-alive" for token in connection)) or length == -1

        return self.response

    def absorb(self, message: HTTPMessage):
        if isinstance(message.body, bytes) and message.body and "Content-Encoding" in message.headers:
            message.compressed = True
            decompress(message, limits=self.limits)

    async def serve_continue(self):
        expect = self.request.headers.get("Expect", "").lower()

        if not self.continued and expect == "100-continue" and self.request.version == "HTTP/1.1":
            self.continued = True
            await self.transport.send(b"HTTP/1.1 100 Continue\r\n\r\n")

    async def send_message(self, message: HTTPMessage, *, final: bool = True):
        if self.role == HTTPBroadRole.SERVER:
            await self.send_response(message)
        else:
            await self.send_request(message)

    async def send_request(self, request: HTTPRequest):
        self.request = request

        target = request.target or (request.url.path or "/") + (f"?{request.url.query}" if request.url.query else "")
        head = f"{request.method} {target} HTTP/1.1\r\n"

        await self.emit(head, request, request.headers or HTTPHeaders(), chunked_ok=True)
        self.replied = True
        self.state = HTTPState.SENT

    async def send_response(self, response: HTTPResponse):
        if response.compression and self.request is not None:
            compress(response, self.request.headers.get("Accept-Encoding", ""), limits=self.limits)

        reason = H1Connection.REASONS.get(response.status_code, "")
        head = f"HTTP/1.1 {response.status_code} {reason}\r\n"

        headers = response.headers or HTTPHeaders()

        if self.closing:
            headers.set("Connection", "close")

        bodiless = response.status_code < 200 or response.status_code in (204, 304) or (self.request is not None and self.request.method == "HEAD")

        await self.emit(head, response, headers, chunked_ok=not bodiless, bodiless=bodiless)
        self.replied = True
        self.state = HTTPState.SENT

    async def emit(self, head: str, message: HTTPMessage, headers: HTTPHeaders, *, chunked_ok: bool, bodiless: bool = False):
        body = None if bodiless else message.body
        streaming = isinstance(body, AsyncIterator)

        if streaming and chunked_ok:
            headers.set("Transfer-Encoding", "chunked")
            headers.remove("Content-Length")
        else:
            payload = self.materialize(body)
            headers.set("Content-Length", str(len(payload)))
            headers.remove("Transfer-Encoding")

        try:
            await self.transport.send(head.encode("latin-1") + headers.build().encode("latin-1") + b"\r\n")

            if bodiless:
                return

            if streaming and chunked_ok:
                await self.stream(message)
            else:
                await self.transport.send(payload)

        except (TCPError, UDSError, TLSError) as e:
            raise HTTPError(500, f"The message could not be sent: {e}")

    def materialize(self, body) -> bytes:
        if body is None:
            return b""

        if isinstance(body, bytes):
            return body

        if isinstance(body, str):
            with open(body, "rb") as f:
                return f.read()

        return bytes(body)

    async def stream(self, message: HTTPMessage):
        async for chunk in message.body:
            if chunk:
                await self.transport.send(b"%x\r\n" % len(chunk) + chunk + b"\r\n")

        trailer = message.trailers.build() if message.trailers else ""
        await self.transport.send(b"0\r\n" + trailer.encode("latin-1") + b"\r\n")

    async def send_raw(self, data: bytes, *, final: bool = True):
        await self.transport.send(data)

    async def receive_raw(self, n: int = -1) -> Optional[bytes]:
        return await self.transport.receive(n)

    async def accept(self):
        return

    async def reject(self):
        self.closing = True

    async def wait(self, value: HTTPState):
        if value in (HTTPState.RECEIVED, HTTPState.RECEIVED_BODY) and not self.received and self.role == HTTPBroadRole.SERVER:
            await self.receive_message()

    async def reset(self):
        self.closing = True

    def reset_exchange(self):
        self.request = None
        self.response = None
        self.received = False
        self.replied = False
        self.continued = False

    async def drain(self):
        if self.role == HTTPBroadRole.SERVER and self.request is not None and not self.received:
            try:
                await self.receive_message()

            except HTTPError:
                self.closing = True

    async def close(self, *, half_close: bool = False, send_pending: bool = False):
        try:
            await self.transport.close(half_close=half_close)

        except (TCPError, UDSError, TLSError):
            pass
