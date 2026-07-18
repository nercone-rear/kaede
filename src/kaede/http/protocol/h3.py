import asyncio
from typing import Optional, Union, List, Dict, Tuple
from collections.abc import AsyncIterator

from ...quic.errors import QUICError, QUICClosedError, QUICStreamError
from ..models import HTTPHeaders, HTTPMessage, HTTPRequest, HTTPResponse
from ..errors import HTTPError
from ..helpers.compression import compress, decompress
from ..helpers.qpack import QPACKEncoder, QPACKDecoder, QPACKError
from .connection import HTTPConnection, HTTPState

class Varint:
    MARKS = {1: 0x00, 2: 0x40, 4: 0x80, 8: 0xC0}

    @staticmethod
    def encode(value: int) -> bytes:
        for length, ceiling in ((1, 0x40), (2, 0x4000), (4, 0x40000000), (8, 0x4000000000000000)):
            if value < ceiling:
                return (value | (Varint.MARKS[length] << (8 * (length - 1)))).to_bytes(length, "big")

        raise ValueError(f"{value} does not fit into a QUIC varint.")

    @staticmethod
    def decode(data: bytes, offset: int = 0) -> Tuple[int, int]:
        length = 1 << (data[offset] >> 6)
        value = data[offset] & 0x3F

        for index in range(1, length):
            value = (value << 8) | data[offset + index]

        return (value, offset + length)

class Stream:
    CONTROL = 0x00
    PUSH    = 0x01
    ENCODER = 0x02
    DECODER = 0x03

class Kind:
    DATA         = 0x0
    HEADERS      = 0x1
    CANCEL_PUSH  = 0x3
    SETTINGS     = 0x4
    PUSH_PROMISE = 0x5
    GOAWAY       = 0x7
    MAX_PUSH_ID  = 0xD

class Setting:
    QPACK_MAX_TABLE_CAPACITY = 0x01
    MAX_FIELD_SECTION_SIZE   = 0x06
    QPACK_BLOCKED_STREAMS    = 0x07

class Code:
    NO_ERROR              = 0x100
    GENERAL_PROTOCOL      = 0x101
    INTERNAL_ERROR        = 0x102
    STREAM_CREATION_ERROR = 0x103
    CLOSED_CRITICAL       = 0x104
    FRAME_UNEXPECTED      = 0x105
    FRAME_ERROR           = 0x106
    EXCESSIVE_LOAD        = 0x107
    MESSAGE_ERROR         = 0x10E

class H3Error(Exception):
    def __init__(self, code: int, message: str = ""):
        self.code = code
        super().__init__(message or f"HTTP/3 error {code:#x}")

class H3Session:
    def __init__(self, connection, *, server: bool, limits):
        self.connection = connection
        self.server = server
        self.limits = limits

        self.encoder = QPACKEncoder()
        self.decoder = QPACKDecoder(limits.max_headers_size * 8)

        self.control = None
        self.qpack_encoder = None
        self.qpack_decoder = None

        self.closing = False

    def settings(self) -> bytes:
        payload = bytearray()

        for identifier, value in ((Setting.QPACK_MAX_TABLE_CAPACITY, 0), (Setting.QPACK_BLOCKED_STREAMS, 0), (Setting.MAX_FIELD_SECTION_SIZE, self.limits.max_headers_size * 8)):
            payload += Varint.encode(identifier) + Varint.encode(value)

        return Varint.encode(Kind.SETTINGS) + Varint.encode(len(payload)) + bytes(payload)

    async def start(self):
        self.control = await self.connection.open(unidirectional=True)
        await self.control.send(Varint.encode(Stream.CONTROL) + self.settings())

        self.qpack_encoder = await self.connection.open(unidirectional=True)
        await self.qpack_encoder.send(Varint.encode(Stream.ENCODER))

        self.qpack_decoder = await self.connection.open(unidirectional=True)
        await self.qpack_decoder.send(Varint.encode(Stream.DECODER))

    async def run(self, handler, server):
        try:
            await self.start()

        except QUICError:
            await self.shutdown()
            return

        tasks = set()

        try:
            while True:
                try:
                    stream = await self.connection.accept()

                except QUICError:
                    break

                if stream.readable and stream.writable:
                    connection = H3Connection(self, stream, server=True)
                    task = asyncio.ensure_future(self.dispatch(connection, handler, server))
                else:
                    task = asyncio.ensure_future(self.consume(stream))

                tasks.add(task)
                task.add_done_callback(tasks.discard)

        finally:
            for task in set(tasks):
                task.cancel()

            await self.shutdown()

    async def dispatch(self, connection: "H3Connection", handler, server):
        try:
            result = handler.on_connection(connection)

            if asyncio.iscoroutine(result) or asyncio.isfuture(result):
                await result

            if not connection.replied:
                await connection.fail(500)

        except HTTPError as e:
            if not connection.replied:
                await connection.fail(e.code)

        except (H3Error, QUICError):
            pass

        except Exception as e:
            asyncio.get_running_loop().call_exception_handler({"message": "Unhandled exception in the HTTP/3 handler", "exception": e})

        finally:
            try:
                await connection.close()

            except QUICError:
                pass

    async def consume(self, stream):
        try:
            kind = await self.varint(stream)

            if kind == Stream.CONTROL:
                await self.control_stream(stream)
            elif kind in (Stream.ENCODER, Stream.DECODER):
                await self.drain(stream)
            elif kind == Stream.PUSH:
                stream.reset(Code.STREAM_CREATION_ERROR)
            else:
                await self.drain(stream)

        except (H3Error, QUICError):
            pass

    async def control_stream(self, stream):
        while True:
            frame = await self.frame(stream)

            if frame is None:
                return

            kind, payload = frame

            if kind == Kind.SETTINGS:
                continue
            elif kind == Kind.GOAWAY:
                self.closing = True
            elif kind in (Kind.DATA, Kind.HEADERS):
                raise H3Error(Code.FRAME_UNEXPECTED, "A request frame arrived on the control stream.")

    async def drain(self, stream):
        while True:
            try:
                if not await stream.receive(65536):
                    return

            except QUICError:
                return

    async def varint(self, stream) -> Optional[int]:
        try:
            first = await stream.receive_exactly(1)

        except QUICError:
            return None

        length = 1 << (first[0] >> 6)
        rest = await stream.receive_exactly(length - 1) if length > 1 else b""

        return Varint.decode(first + rest)[0]

    async def frame(self, stream) -> Optional[Tuple[int, bytes]]:
        kind = await self.varint(stream)

        if kind is None:
            return None

        length = await self.varint(stream)

        if length is None:
            raise H3Error(Code.FRAME_ERROR, "A frame header ended early.")

        if length > self.limits.max_message_body_size:
            raise H3Error(Code.EXCESSIVE_LOAD, "A frame is larger than allowed.")

        payload = await stream.receive_exactly(length) if length else b""

        return (kind, payload)

    async def request(self, message: HTTPRequest) -> "H3Connection":
        stream = await self.connection.open()
        connection = H3Connection(self, stream, server=False)

        await connection.deliver_request(message)
        return connection

    async def shutdown(self):
        self.closing = True

        try:
            await self.connection.close()

        except QUICError:
            pass

class H3Connection(HTTPConnection):
    def __init__(self, session: H3Session, stream, *, server: bool):
        super().__init__(("", None), ("", None), transport=session.connection, version="HTTP/3.0", limits=session.limits)

        self.session = session
        self.stream = stream
        self.server = server

        self.request: Optional[HTTPRequest] = None
        self.response: Optional[HTTPResponse] = None

        self.replied = False

    @property
    def secure(self) -> bool:
        return True

    async def receive_message(self) -> Optional[HTTPMessage]:
        fields: Optional[List[Tuple[str, str]]] = None
        trailers: Optional[List[Tuple[str, str]]] = None
        body = bytearray()

        while True:
            frame = await self.session.frame(self.stream)

            if frame is None:
                break

            kind, payload = frame

            if kind == Kind.HEADERS:
                if fields is None:
                    fields = self.unpack(payload)
                else:
                    trailers = self.unpack(payload)

            elif kind == Kind.DATA:
                body += payload

                if len(body) > self.limits.max_message_body_size:
                    raise H3Error(Code.EXCESSIVE_LOAD, "The message body is larger than allowed.")

            elif kind in (Kind.SETTINGS, Kind.GOAWAY, Kind.CANCEL_PUSH, Kind.MAX_PUSH_ID):
                raise H3Error(Code.FRAME_UNEXPECTED, "A control frame arrived on a request stream.")

        if fields is None:
            raise HTTPError(502, "The request stream carried no header block.")

        message = self.assemble(fields, bytes(body), trailers)
        self.state = HTTPState.RECEIVED

        return message

    def unpack(self, payload: bytes) -> List[Tuple[str, str]]:
        try:
            return self.session.decoder.decode(payload)

        except QPACKError as e:
            raise H3Error(Code.MESSAGE_ERROR, str(e))

    def assemble(self, fields: List[Tuple[str, str]], body: bytes, trailers) -> HTTPMessage:
        pseudo: Dict[str, str] = {}
        regular = HTTPHeaders()
        seen = False

        for name, value in fields:
            if name.startswith(":"):
                if seen:
                    raise H3Error(Code.MESSAGE_ERROR, "A pseudo-header follows a regular header.")

                pseudo[name] = value
            else:
                seen = True

                if name in ("connection", "transfer-encoding", "keep-alive", "upgrade", "proxy-connection"):
                    raise H3Error(Code.MESSAGE_ERROR, f"The connection-specific header {name!r} is forbidden in HTTP/3.")

                regular.append(name, value)

        if self.server:
            for required in (":method", ":scheme", ":path"):
                if required not in pseudo:
                    raise H3Error(Code.MESSAGE_ERROR, f"The request is missing {required}.")

            if ":authority" in pseudo:
                regular.set("Host", pseudo[":authority"], override=False)

            message: HTTPMessage = HTTPRequest(version="HTTP/3.0", method=pseudo[":method"], target=pseudo[":path"], headers=regular, secure=pseudo[":scheme"] == "https")
            self.request = message
        else:
            if ":status" not in pseudo or not pseudo[":status"].isdigit():
                raise H3Error(Code.MESSAGE_ERROR, "The response is missing a valid :status.")

            message = HTTPResponse(version="HTTP/3.0", status_code=int(pseudo[":status"]), headers=regular, secure=True)
            self.response = message

        message.body = body

        if trailers:
            message.trailers = HTTPHeaders([(name, value) for name, value in trailers if not name.startswith(":")])

        self.absorb_encoding(message)
        return message

    def absorb_encoding(self, message: HTTPMessage):
        if isinstance(message.body, bytes) and message.body and "Content-Encoding" in message.headers:
            message.compressed = True
            decompress(message, limits=self.limits)

    async def send_message(self, message: HTTPMessage, *, final: bool = True):
        if self.server:
            await self.send_response(message)
        else:
            await self.deliver_request(message)

    async def deliver_request(self, request: HTTPRequest):
        url = request.url
        authority = request.headers.get("Host", "") or (url.netloc if url else "")

        if request.target:
            path = request.target
        else:
            path = (url.path if url else "/") or "/"

            if url and url.query:
                path += f"?{url.query}"

        pseudo = [
            (":method", request.method),
            (":scheme", "https"),
            (":authority", authority),
            (":path", path),
        ]

        body = self.body_bytes(request)

        if body and request.headers is not None:
            request.headers.set("Content-Length", str(len(body)), override=False)

        await self.frame_out(Kind.HEADERS, self.session.encoder.encode(pseudo + self.regular(request.headers)))

        if body:
            await self.frame_out(Kind.DATA, body)

        self.stream.conclude()
        self.replied = True
        self.state = HTTPState.SENT

    async def send_response(self, response: HTTPResponse):
        if response.compression and self.request is not None:
            compress(response, self.request.headers.get("Accept-Encoding", ""), limits=self.limits)

        fields = [(":status", str(response.status_code))] + self.regular(response.headers)
        bodiless = response.status_code < 200 or response.status_code in (204, 304) or (self.request is not None and self.request.method == "HEAD")

        await self.frame_out(Kind.HEADERS, self.session.encoder.encode(fields))

        if not bodiless and isinstance(response.body, AsyncIterator):
            async for chunk in response.body:
                if chunk:
                    await self.frame_out(Kind.DATA, chunk)

        elif not bodiless:
            body = self.body_bytes(response)

            if body:
                await self.frame_out(Kind.DATA, body)

        self.stream.conclude()
        self.replied = True
        self.state = HTTPState.SENT

    async def frame_out(self, kind: int, payload: bytes):
        await self.stream.send(Varint.encode(kind) + Varint.encode(len(payload)) + payload)

    def regular(self, headers: Optional[HTTPHeaders]) -> List[Tuple[str, str]]:
        if headers is None:
            return []

        skip = {"connection", "transfer-encoding", "keep-alive", "upgrade", "proxy-connection", "host"}

        return [(name.lower(), value) for name, value in headers.items() if name.lower() not in skip]

    def body_bytes(self, message: HTTPMessage) -> bytes:
        body = message.body

        if body is None or isinstance(body, AsyncIterator):
            return b""

        if isinstance(body, bytes):
            return body

        if isinstance(body, str):
            with open(body, "rb") as f:
                return f.read()

        return bytes(body)

    async def fail(self, code: int):
        try:
            await self.send_response(HTTPResponse(version="HTTP/3.0", status_code=code, headers=HTTPHeaders(), body=b"", compression=False))

        except (HTTPError, H3Error, QUICError):
            self.stream.reset(Code.INTERNAL_ERROR)

    async def accept(self):
        return

    async def reject(self):
        self.stream.reset(Code.GENERAL_PROTOCOL)

    async def wait(self, value: HTTPState):
        if value in (HTTPState.RECEIVED, HTTPState.RECEIVED_BODY) and self.request is None and self.server:
            await self.receive_message()

    async def send_raw(self, data: bytes, *, final: bool = True):
        await self.frame_out(Kind.DATA, data)

        if final:
            self.stream.conclude()

    async def receive_raw(self, n: int = -1) -> Optional[bytes]:
        frame = await self.session.frame(self.stream)

        if frame is None:
            return b""

        return frame[1]

    async def close(self, *, half_close: bool = False, send_pending: bool = False):
        try:
            await self.stream.close()

        except QUICError:
            pass
