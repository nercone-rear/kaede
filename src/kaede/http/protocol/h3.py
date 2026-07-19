import asyncio
from typing import Optional, Union, List, Dict, Tuple
from collections.abc import AsyncIterator

from ...url import URL
from ...constants import Digits
from ...quic.errors import QUICError, QUICClosedError, QUICStreamError
from ..models import HTTPBroadRole, HTTPHeaders, HTTPMessage, HTTPRequest, HTTPResponse
from ..errors import HTTPError
from ..finalizer import finalize_response
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

    RESERVED = frozenset({0x02, 0x06, 0x08, 0x09})

class Setting:
    QPACK_MAX_TABLE_CAPACITY = 0x01
    MAX_FIELD_SECTION_SIZE   = 0x06
    QPACK_BLOCKED_STREAMS    = 0x07

    RESERVED = frozenset({0x00, 0x02, 0x03, 0x04, 0x05})

class Code:
    NO_ERROR              = 0x100
    GENERAL_PROTOCOL      = 0x101
    INTERNAL_ERROR        = 0x102
    STREAM_CREATION_ERROR = 0x103
    CLOSED_CRITICAL       = 0x104
    FRAME_UNEXPECTED      = 0x105
    FRAME_ERROR           = 0x106
    EXCESSIVE_LOAD        = 0x107
    ID_ERROR              = 0x108
    SETTINGS_ERROR        = 0x109
    MISSING_SETTINGS      = 0x10A
    REQUEST_REJECTED      = 0x10B
    REQUEST_CANCELLED     = 0x10C
    REQUEST_INCOMPLETE    = 0x10D
    MESSAGE_ERROR         = 0x10E
    CONNECT_ERROR         = 0x10F
    VERSION_FALLBACK      = 0x110

    QPACK_DECOMPRESSION_FAILED = 0x200
    QPACK_ENCODER_STREAM_ERROR = 0x201
    QPACK_DECODER_STREAM_ERROR = 0x202

    STREAMWISE = frozenset({MESSAGE_ERROR, REQUEST_REJECTED, REQUEST_CANCELLED, REQUEST_INCOMPLETE})

class H3Error(Exception):
    def __init__(self, code: int, message: str = ""):
        self.code = code
        super().__init__(message or f"HTTP/3 error {code:#x}")

    @property
    def streamwise(self) -> bool:
        return self.code in Code.STREAMWISE

class H3Session:
    def __init__(self, connection, *, role: HTTPBroadRole, limits, observer=None):
        self.connection = connection
        self.role = role
        self.limits = limits
        self.observer = observer

        self.encoder = QPACKEncoder()
        self.decoder = QPACKDecoder(limits.max_headers_size * 8)

        self.control = None
        self.qpack_encoder = None
        self.qpack_decoder = None

        self.peer_control = None
        self.peer_qpack: Dict[int, object] = {}

        self.settled = False
        self.field_section_ceiling: Optional[int] = None
        self.goaway_id: Optional[int] = None
        self.push_ceiling: Optional[int] = None

        self.closing = False
        self.ended = False

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
                    connection = H3Connection(self, stream, role=self.role)
                    task = asyncio.ensure_future(self.dispatch(connection, handler, server))
                else:
                    task = asyncio.ensure_future(self.consume(stream))

                tasks.add(task)
                task.add_done_callback(tasks.discard)

        finally:
            for task in set(tasks):
                task.cancel()

            await self.shutdown()

    async def fail(self, code: int, message: str = ""):
        if self.ended:
            return

        self.closing = True
        self.ended = True

        try:
            await self.connection.close(code, message[:256])

        except QUICError:
            pass

    async def dispatch(self, connection: "H3Connection", handler, server):
        try:
            result = handler.on_connection(connection)

            if asyncio.iscoroutine(result) or asyncio.isfuture(result):
                await result

            if not connection.replied:
                await connection.fail(500)

        except HTTPError as e:
            if not connection.replied:
                await connection.fail(e.code, e.headers)

        except H3Error as e:
            await self.report(connection, e)

        except QUICError:
            pass

        except Exception as e:
            asyncio.get_running_loop().call_exception_handler({"message": "Unhandled exception in the HTTP/3 handler", "exception": e})

        finally:
            try:
                await connection.close()

            except QUICError:
                pass

    async def report(self, connection: "H3Connection", error: H3Error):
        if error.streamwise:
            connection.stream.reset(error.code)
            return

        await self.fail(error.code, str(error))

    async def consume(self, stream):
        try:
            kind = await self.varint(stream)

            if kind is None:
                return

            if kind == Stream.CONTROL:
                await self.control_stream(stream)

            elif kind in (Stream.ENCODER, Stream.DECODER):
                await self.qpack_stream(stream, kind)

            elif kind == Stream.PUSH:
                raise H3Error(Code.STREAM_CREATION_ERROR, "A push stream arrived where none is allowed.")

            else:
                await self.drain(stream)

        except H3Error as e:
            await self.fail(e.code, str(e))

        except QUICError:
            return

    async def control_stream(self, stream):
        if self.peer_control is not None:
            raise H3Error(Code.STREAM_CREATION_ERROR, "A second control stream arrived.")

        self.peer_control = stream

        while True:
            frame = await self.frame(stream)

            if frame is None:
                if self.ended:
                    return

                raise H3Error(Code.CLOSED_CRITICAL, "The peer closed its control stream.")

            kind, payload = frame

            if kind in Kind.RESERVED:
                raise H3Error(Code.FRAME_UNEXPECTED, f"The reserved frame type {kind:#x} arrived.")

            if not self.settled and kind != Kind.SETTINGS:
                raise H3Error(Code.MISSING_SETTINGS, "The control stream did not open with a SETTINGS frame.")

            if kind == Kind.SETTINGS:
                if self.settled:
                    raise H3Error(Code.FRAME_UNEXPECTED, "A second SETTINGS frame arrived.")

                self.settled = True
                self.apply(payload)

            elif kind == Kind.GOAWAY:
                self.goaway(payload)

            elif kind == Kind.MAX_PUSH_ID:
                self.max_push_id(payload)

            elif kind == Kind.CANCEL_PUSH:
                self.number(payload, "CANCEL_PUSH")
                raise H3Error(Code.ID_ERROR, "A CANCEL_PUSH frame names a push that was never promised.")

            elif kind in (Kind.DATA, Kind.HEADERS, Kind.PUSH_PROMISE):
                raise H3Error(Code.FRAME_UNEXPECTED, "A request frame arrived on the control stream.")

    def apply(self, payload: bytes):
        offset = 0
        seen = set()

        while offset < len(payload):
            try:
                identifier, offset = Varint.decode(payload, offset)
                value, offset = Varint.decode(payload, offset)

            except IndexError:
                raise H3Error(Code.SETTINGS_ERROR, "A SETTINGS frame ends in the middle of a parameter.")

            if identifier in Setting.RESERVED:
                raise H3Error(Code.SETTINGS_ERROR, f"The reserved setting {identifier:#x} arrived.")

            if identifier in seen:
                raise H3Error(Code.SETTINGS_ERROR, f"The setting {identifier:#x} is repeated.")

            seen.add(identifier)

            if identifier == Setting.MAX_FIELD_SECTION_SIZE:
                self.field_section_ceiling = value

    def number(self, payload: bytes, name: str) -> int:
        if not payload:
            raise H3Error(Code.FRAME_ERROR, f"A {name} frame carries no identifier.")

        try:
            value, offset = Varint.decode(payload)

        except IndexError:
            raise H3Error(Code.FRAME_ERROR, f"A {name} frame identifier is truncated.")

        if offset != len(payload):
            raise H3Error(Code.FRAME_ERROR, f"A {name} frame carries trailing bytes.")

        return value

    def goaway(self, payload: bytes):
        value = self.number(payload, "GOAWAY")

        if self.goaway_id is not None and value > self.goaway_id:
            raise H3Error(Code.ID_ERROR, "A GOAWAY identifier increased.")

        self.goaway_id = value
        self.closing = True

    def max_push_id(self, payload: bytes):
        value = self.number(payload, "MAX_PUSH_ID")

        if self.role != HTTPBroadRole.SERVER:
            raise H3Error(Code.FRAME_UNEXPECTED, "A client received a MAX_PUSH_ID frame.")

        if self.push_ceiling is not None and value < self.push_ceiling:
            raise H3Error(Code.ID_ERROR, "A MAX_PUSH_ID frame lowered the limit.")

        self.push_ceiling = value

    async def qpack_stream(self, stream, kind: int):
        if kind in self.peer_qpack:
            raise H3Error(Code.STREAM_CREATION_ERROR, "A second QPACK stream of the same type arrived.")

        self.peer_qpack[kind] = stream
        await self.drain(stream)

        if not self.ended:
            raise H3Error(Code.CLOSED_CRITICAL, "The peer closed a QPACK stream.")

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

        try:
            rest = await stream.receive_exactly(length - 1) if length > 1 else b""

        except QUICError:
            raise H3Error(Code.FRAME_ERROR, "A varint ended before its declared length.")

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

        try:
            payload = await stream.receive_exactly(length) if length else b""

        except QUICError:
            raise H3Error(Code.FRAME_ERROR, "A frame payload ended before its declared length.")

        return (kind, payload)

    async def request(self, message: HTTPRequest) -> "H3Connection":
        stream = await self.connection.open()
        connection = H3Connection(self, stream, role=self.role)

        await connection.send_request(message)
        return connection

    async def shutdown(self):
        self.closing = True
        self.ended = True

        try:
            await self.connection.close()

        except QUICError:
            pass

class H3Connection(HTTPConnection):
    FORBIDDEN = frozenset({"connection", "transfer-encoding", "keep-alive", "upgrade", "proxy-connection"})

    REQUEST_PSEUDO  = frozenset({":method", ":scheme", ":path", ":authority"})
    RESPONSE_PSEUDO = frozenset({":status"})

    def __init__(self, session: H3Session, stream, *, role: HTTPBroadRole):
        super().__init__(("", None), ("", None), transport=session.connection, version="HTTP/3.0", limits=session.limits, observer=session.observer)

        self.session = session
        self.stream = stream
        self.role = role

        self.request: Optional[HTTPRequest] = None
        self.response: Optional[HTTPResponse] = None

        self.buffer = bytearray()
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

            if kind in Kind.RESERVED:
                raise H3Error(Code.FRAME_UNEXPECTED, f"The reserved frame type {kind:#x} arrived on a request stream.")

            if kind == Kind.HEADERS:
                if trailers is not None:
                    raise H3Error(Code.FRAME_UNEXPECTED, "A third HEADERS frame arrived on a request stream.")

                if fields is None:
                    fields = self.unpack(payload)
                else:
                    trailers = self.unpack(payload)

            elif kind == Kind.DATA:
                if fields is None:
                    raise H3Error(Code.FRAME_UNEXPECTED, "A DATA frame arrived before any HEADERS frame.")

                if trailers is not None:
                    raise H3Error(Code.FRAME_UNEXPECTED, "A DATA frame arrived after the trailing HEADERS frame.")

                body += payload

                if len(body) > self.limits.max_message_body_size:
                    raise H3Error(Code.EXCESSIVE_LOAD, "The message body is larger than allowed.")

            elif kind in (Kind.SETTINGS, Kind.GOAWAY, Kind.CANCEL_PUSH, Kind.MAX_PUSH_ID):
                raise H3Error(Code.FRAME_UNEXPECTED, "A control frame arrived on a request stream.")

            elif kind == Kind.PUSH_PROMISE and self.role == HTTPBroadRole.SERVER:
                raise H3Error(Code.FRAME_UNEXPECTED, "A PUSH_PROMISE frame arrived at a server.")

        if fields is None:
            raise H3Error(Code.REQUEST_INCOMPLETE, "The request stream carried no header block.")

        message = self.assemble(fields, bytes(body), trailers)
        self.state = HTTPState.RECEIVED

        return message

    def unpack(self, payload: bytes) -> List[Tuple[str, str]]:
        try:
            return self.session.decoder.decode(payload)

        except QPACKError as e:
            raise H3Error(Code.QPACK_DECOMPRESSION_FAILED, str(e))

    def split(self, fields: List[Tuple[str, str]], *, trailer: bool) -> Tuple[Dict[str, str], HTTPHeaders]:
        pseudo: Dict[str, str] = {}
        regular = HTTPHeaders()
        seen = False

        for name, value in fields:
            if name != name.lower():
                raise H3Error(Code.MESSAGE_ERROR, f"The field name {name!r} is not lowercase.")

            if name.startswith(":"):
                if trailer:
                    raise H3Error(Code.MESSAGE_ERROR, "A trailer section carries a pseudo-header.")

                if seen:
                    raise H3Error(Code.MESSAGE_ERROR, "A pseudo-header follows a regular header.")

                if name in pseudo:
                    raise H3Error(Code.MESSAGE_ERROR, f"The pseudo-header {name} is repeated.")

                if any(ord(character) == 0x7F or ord(character) < 0x20 for character in value):
                    raise H3Error(Code.MESSAGE_ERROR, f"The pseudo-header {name} carries a control character.")

                pseudo[name] = value
                continue

            seen = True

            if name in H3Connection.FORBIDDEN:
                raise H3Error(Code.MESSAGE_ERROR, f"The connection-specific header {name!r} is forbidden in HTTP/3.")

            if name == "te" and value.lower() != "trailers":
                raise H3Error(Code.MESSAGE_ERROR, "The te header may only be 'trailers' in HTTP/3.")

            if HTTPHeaders.spaced(value):
                raise H3Error(Code.MESSAGE_ERROR, f"The value of the {name!r} header is padded with whitespace.")

            try:
                regular.append(name, value)

            except ValueError as e:
                raise H3Error(Code.MESSAGE_ERROR, str(e))

        return (pseudo, regular)

    def trailer(self, fields: List[Tuple[str, str]]) -> HTTPHeaders:
        _, regular = self.split(fields, trailer=True)
        offender = regular.trailing()

        if offender is not None:
            raise H3Error(Code.MESSAGE_ERROR, f"The trailer section carries the forbidden field {offender!r}.")

        return regular

    def assemble(self, fields: List[Tuple[str, str]], body: bytes, trailers) -> HTTPMessage:
        pseudo, regular = self.split(fields, trailer=False)

        if self.role == HTTPBroadRole.SERVER:
            message: HTTPMessage = self.request_from(pseudo, regular)
            self.request = message
        else:
            message = self.response_from(pseudo, regular)
            self.response = message

        message.body = body

        if trailers is not None:
            message.trailers = self.trailer(trailers)

        self.verify(message)
        self.absorb_encoding(message)
        self.observe(message)

        return message

    def request_from(self, pseudo: Dict[str, str], regular: HTTPHeaders) -> HTTPRequest:
        for name in pseudo:
            if name not in H3Connection.REQUEST_PSEUDO:
                raise H3Error(Code.MESSAGE_ERROR, f"{name} is not a valid request pseudo-header.")

        method = pseudo.get(":method")

        if not method:
            raise H3Error(Code.MESSAGE_ERROR, "The request is missing :method.")

        if method == "CONNECT":
            if ":scheme" in pseudo or ":path" in pseudo:
                raise H3Error(Code.MESSAGE_ERROR, "A CONNECT request carries :scheme or :path.")

            if not pseudo.get(":authority"):
                raise H3Error(Code.MESSAGE_ERROR, "A CONNECT request carries no :authority.")
        else:
            for required in (":scheme", ":path"):
                if not pseudo.get(required):
                    raise H3Error(Code.MESSAGE_ERROR, f"The request is missing {required}.")

        self.authority(pseudo, regular)

        return HTTPRequest(version="HTTP/3.0", method=method, target=pseudo.get(":path", ""), headers=regular, secure=pseudo.get(":scheme", "https") == "https")

    def authority(self, pseudo: Dict[str, str], regular: HTTPHeaders):
        given = pseudo.get(":authority")
        hosts = regular.values("Host")

        if len(hosts) > 1:
            raise H3Error(Code.MESSAGE_ERROR, "More than one Host header field line is present.")

        if given is None and not hosts:
            raise H3Error(Code.MESSAGE_ERROR, "The request carries neither :authority nor Host.")

        target = given if given is not None else hosts[0]

        if not target or not URL.authority(target):
            raise H3Error(Code.MESSAGE_ERROR, "The request authority is not valid.")

        if hosts and given is not None and hosts[0] != given:
            raise H3Error(Code.MESSAGE_ERROR, "The Host header field disagrees with :authority.")

        regular.set("Host", target)

    def response_from(self, pseudo: Dict[str, str], regular: HTTPHeaders) -> HTTPResponse:
        for name in pseudo:
            if name not in H3Connection.RESPONSE_PSEUDO:
                raise H3Error(Code.MESSAGE_ERROR, f"{name} is not a valid response pseudo-header.")

        code = Digits.decimal(pseudo.get(":status", ""), width=3)

        if code is None:
            raise H3Error(Code.MESSAGE_ERROR, "The response is missing a valid :status.")

        return HTTPResponse(version="HTTP/3.0", status_code=code, headers=regular, secure=True)

    def bodiless(self, response: HTTPResponse) -> bool:
        return response.status_code < 200 or response.status_code in (204, 304) or (self.request is not None and self.request.method == "HEAD")

    def lengthless(self, response: HTTPResponse) -> bool:
        return response.status_code < 200 or response.status_code == 204

    def verify(self, message: HTTPMessage):
        if isinstance(message, HTTPResponse) and self.bodiless(message):
            return

        declared = {token.strip() for value in message.headers.values("Content-Length") for token in value.split(",") if token.strip()}

        if not declared:
            return

        length = Digits.decimal(next(iter(declared))) if len(declared) == 1 else None

        if length is None:
            raise H3Error(Code.MESSAGE_ERROR, "Content-Length is malformed.")

        if length != len(message.body):
            raise H3Error(Code.MESSAGE_ERROR, "Content-Length does not equal the length of the body received.")

    def absorb_encoding(self, message: HTTPMessage):
        if isinstance(message.body, bytes) and message.body and "Content-Encoding" in message.headers:
            message.compressed = True
            decompress(message, limits=self.limits)

    async def send_message(self, message: HTTPMessage, *, final: bool = True):
        if self.role == HTTPBroadRole.SERVER:
            await self.send_response(message)
        else:
            await self.send_request(message)

    async def send_request(self, request: HTTPRequest):
        url = request.url
        authority = request.headers.get("Host", "") or (url.netloc if url else "")

        if request.target:
            path = request.target
        else:
            path = (url.path if url else "/") or "/"

            if url and url.query:
                path += f"?{url.query}"

        if request.method == "CONNECT":
            pseudo = [(":method", request.method), (":authority", authority)]
        else:
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
        bodiless = self.bodiless(response)

        await finalize_response(response)

        if response.compression and self.request is not None and not bodiless:
            compress(response, self.request.headers.get("Accept-Encoding", ""), limits=self.limits)

        headers = response.headers
        streaming = isinstance(response.body, AsyncIterator)
        payload = b"" if streaming else self.body_bytes(response)

        if streaming or self.lengthless(response):
            headers.remove("Content-Length")
        else:
            headers.set("Content-Length", str(len(payload)))

        await self.frame_out(Kind.HEADERS, self.session.encoder.encode([(":status", str(response.status_code))] + self.regular(headers)))

        if response.status_code < 200:
            return

        if not bodiless and streaming:
            async for chunk in response.body:
                if chunk:
                    await self.frame_out(Kind.DATA, chunk)

        elif not bodiless and payload:
            await self.frame_out(Kind.DATA, payload)

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

    async def fail(self, code: int, headers: Optional[HTTPHeaders] = None):
        try:
            await self.send_response(HTTPResponse(version="HTTP/3.0", status_code=code, headers=headers or HTTPHeaders(), body=b"", compression=False))

        except (HTTPError, H3Error, QUICError):
            await self.reset(Code.INTERNAL_ERROR)

    async def reset(self, code: int = Code.REQUEST_CANCELLED):
        self.stream.reset(code)

    async def accept(self):
        return

    async def reject(self):
        await self.reset(Code.REQUEST_REJECTED)

    async def wait(self, value: HTTPState):
        if value in (HTTPState.RECEIVED, HTTPState.RECEIVED_BODY) and self.request is None and self.role == HTTPBroadRole.SERVER:
            await self.receive_message()

    async def send_raw(self, data: bytes, *, final: bool = True):
        await self.frame_out(Kind.DATA, data)

        if final:
            self.stream.conclude()

    async def receive_raw(self, n: int = -1) -> Optional[bytes]:
        if not self.buffer:
            frame = await self.session.frame(self.stream)

            if frame is None:
                return b""

            self.buffer += frame[1]

        data = bytes(self.buffer if n < 0 else self.buffer[:n])
        del self.buffer[:len(data)]

        return data

    async def close(self, *, half_close: bool = False, send_pending: bool = False):
        try:
            await self.stream.close()

        except QUICError:
            pass
