import asyncio
from typing import Optional, Union, List, Dict, Tuple
from dataclasses import dataclass
from collections.abc import AsyncIterator

from ...tcp.errors import TCPError
from ...uds.errors import UDSError
from ...tls.errors import TLSError
from ..models import HTTPHeaders, HTTPMessage, HTTPRequest, HTTPResponse
from ..errors import HTTPError
from ..helpers.compression import compress, decompress
from ..helpers.hpack import HPACKEncoder, HPACKDecoder, HPACKError
from .connection import HTTPConnection, HTTPState

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

class Frame:
    DATA          = 0x0
    HEADERS       = 0x1
    PRIORITY      = 0x2
    RST_STREAM    = 0x3
    SETTINGS      = 0x4
    PUSH_PROMISE  = 0x5
    PING          = 0x6
    GOAWAY        = 0x7
    WINDOW_UPDATE = 0x8
    CONTINUATION  = 0x9

class Flag:
    END_STREAM  = 0x1
    ACK         = 0x1
    END_HEADERS = 0x4
    PADDED      = 0x8
    PRIORITY    = 0x20

class Code:
    NO_ERROR            = 0x0
    PROTOCOL_ERROR      = 0x1
    INTERNAL_ERROR      = 0x2
    FLOW_CONTROL_ERROR  = 0x3
    SETTINGS_TIMEOUT    = 0x4
    STREAM_CLOSED       = 0x5
    FRAME_SIZE_ERROR    = 0x6
    REFUSED_STREAM      = 0x7
    CANCEL              = 0x8
    COMPRESSION_ERROR   = 0x9
    CONNECT_ERROR       = 0xA
    ENHANCE_YOUR_CALM   = 0xB
    INADEQUATE_SECURITY = 0xC

class H2Error(Exception):
    """A connection level HTTP/2 error, carrying the GOAWAY code."""

    def __init__(self, code: int, message: str = ""):
        self.code = code
        super().__init__(message or f"HTTP/2 error {code}")

class H2StreamError(Exception):
    """A stream level HTTP/2 error, carrying the RST_STREAM code."""

    def __init__(self, code: int, stream: int, message: str = ""):
        self.code = code
        self.stream = stream
        super().__init__(message or f"HTTP/2 stream error {code}")

@dataclass
class H2Frame:
    type: int
    flags: int
    stream: int
    payload: bytes

    def pack(self) -> bytes:
        return len(self.payload).to_bytes(3, "big") + bytes([self.type, self.flags]) + (self.stream & 0x7FFFFFFF).to_bytes(4, "big") + self.payload

@dataclass
class H2Settings:
    header_table_size: int = 4096
    enable_push: int = 0
    max_concurrent_streams: int = 100
    initial_window_size: int = 65535
    max_frame_size: int = 16384
    max_header_list_size: int = 262144

    IDS = {1: "header_table_size", 2: "enable_push", 3: "max_concurrent_streams", 4: "initial_window_size", 5: "max_frame_size", 6: "max_header_list_size"}

    def pack(self) -> bytes:
        payload = bytearray()

        for number, name in H2Settings.IDS.items():
            payload += number.to_bytes(2, "big") + getattr(self, name).to_bytes(4, "big")

        return bytes(payload)

    def apply(self, payload: bytes):
        if len(payload) % 6:
            raise H2Error(Code.FRAME_SIZE_ERROR, "A SETTINGS frame is not a multiple of six bytes.")

        for offset in range(0, len(payload), 6):
            number = int.from_bytes(payload[offset:offset + 2], "big")
            value = int.from_bytes(payload[offset + 2:offset + 6], "big")

            if number == 2 and value not in (0, 1):
                raise H2Error(Code.PROTOCOL_ERROR, "SETTINGS_ENABLE_PUSH must be 0 or 1.")

            if number == 4 and value > 0x7FFFFFFF:
                raise H2Error(Code.FLOW_CONTROL_ERROR, "SETTINGS_INITIAL_WINDOW_SIZE is too large.")

            if number == 5 and not (16384 <= value <= 16777215):
                raise H2Error(Code.PROTOCOL_ERROR, "SETTINGS_MAX_FRAME_SIZE is out of range.")

            if number in H2Settings.IDS:
                setattr(self, H2Settings.IDS[number], value)

class H2Session:
    def __init__(self, transport, *, server: bool, limits, settings: Optional[H2Settings] = None):
        self.transport = transport
        self.server = server
        self.limits = limits

        self.local = settings or H2Settings(max_header_list_size=limits.max_headers_size * 8)
        self.remote = H2Settings()

        self.encoder = HPACKEncoder(self.remote.header_table_size)
        self.decoder = HPACKDecoder(self.local.header_table_size, self.local.max_header_list_size)

        self.streams: Dict[int, "H2Connection"] = {}
        self.arrivals: "asyncio.Queue[Optional[H2Connection]]" = asyncio.Queue()

        self.next_stream = 1 if not server else 2
        self.last_stream = 0
        self.highest_remote = 0

        self.send_window = self.remote.initial_window_size
        self.recv_window = self.local.initial_window_size

        self.writing = asyncio.Lock()
        self.flow = asyncio.Condition()

        self.pending: Optional[Tuple[int, bytes, bool]] = None # a header block still awaiting CONTINUATION frames
        self.closing = False
        self.error: Optional[Exception] = None

    # -- framing ---------------------------------------------------------

    async def write(self, frame: H2Frame):
        async with self.writing:
            try:
                await self.transport.send(frame.pack())

            except (TCPError, UDSError, TLSError) as e:
                raise H2Error(Code.INTERNAL_ERROR, f"The connection could not be written to: {e}")

    async def read(self) -> H2Frame:
        header = await self.transport.receive_exactly(9)
        length = int.from_bytes(header[0:3], "big")

        if length > self.local.max_frame_size:
            raise H2Error(Code.FRAME_SIZE_ERROR, "A frame is larger than the negotiated maximum.")

        payload = await self.transport.receive_exactly(length) if length else b""

        return H2Frame(type=header[3], flags=header[4], stream=int.from_bytes(header[5:9], "big") & 0x7FFFFFFF, payload=payload)

    # -- lifecycle -------------------------------------------------------

    async def start(self):
        if self.server:
            preface = await self.transport.receive_exactly(len(PREFACE))

            if preface != PREFACE:
                raise H2Error(Code.PROTOCOL_ERROR, "The client preface is wrong.")
        else:
            await self.transport.send(PREFACE)

        await self.write(H2Frame(Frame.SETTINGS, 0, 0, self.local.pack()))

    async def run(self, handler, server):
        try:
            await self.start()

        except (H2Error, TCPError, UDSError, TLSError):
            await self.shutdown()
            return

        pump = asyncio.ensure_future(self.pump())
        tasks = set()

        try:
            while True:
                stream = await self.arrivals.get()

                if stream is None:
                    break

                task = asyncio.ensure_future(self.dispatch(stream, handler, server))
                tasks.add(task)
                task.add_done_callback(tasks.discard)

        finally:
            pump.cancel()

            for task in set(tasks):
                task.cancel()

            await self.shutdown()

    async def dispatch(self, stream: "H2Connection", handler, server):
        try:
            result = handler.on_connection(stream)

            if asyncio.iscoroutine(result) or asyncio.isfuture(result):
                await result

            if not stream.replied:
                await stream.fail(500)

        except HTTPError as e:
            if not stream.replied:
                await stream.fail(e.code)

        except (H2Error, H2StreamError, TCPError, UDSError, TLSError):
            pass

        except Exception as e:
            asyncio.get_running_loop().call_exception_handler({"message": "Unhandled exception in the HTTP/2 handler", "exception": e})

            if not stream.replied:
                try:
                    await stream.reset(Code.INTERNAL_ERROR)
                except Exception:
                    pass

        finally:
            self.forget(stream.id)

    async def pump(self):
        try:
            while True:
                frame = await self.read()
                await self.handle(frame)

        except asyncio.CancelledError:
            raise

        except H2Error as e:
            await self.goaway(e.code, str(e))

        except (TCPError, UDSError, TLSError) as e:
            self.error = e

        finally:
            self.wake_all()
            await self.arrivals.put(None)

    async def shutdown(self):
        if not self.closing:
            await self.goaway(Code.NO_ERROR)

        try:
            await self.transport.close()

        except (TCPError, UDSError, TLSError):
            pass

    # -- inbound frames --------------------------------------------------

    async def handle(self, frame: H2Frame):
        if self.pending is not None and frame.type != Frame.CONTINUATION:
            raise H2Error(Code.PROTOCOL_ERROR, "A CONTINUATION frame was expected.")

        dispatch = {
            Frame.DATA: self.on_data,
            Frame.HEADERS: self.on_headers,
            Frame.PRIORITY: self.on_priority,
            Frame.RST_STREAM: self.on_reset,
            Frame.SETTINGS: self.on_settings,
            Frame.PUSH_PROMISE: self.on_push,
            Frame.PING: self.on_ping,
            Frame.GOAWAY: self.on_goaway,
            Frame.WINDOW_UPDATE: self.on_window,
            Frame.CONTINUATION: self.on_continuation,
        }.get(frame.type)

        if dispatch is not None:
            await dispatch(frame)

    def strip(self, frame: H2Frame) -> bytes:
        payload = frame.payload

        if frame.flags & Flag.PADDED:
            if not payload:
                raise H2Error(Code.PROTOCOL_ERROR, "A padded frame has no pad length.")

            pad = payload[0]

            if 1 + pad > len(payload):
                raise H2Error(Code.PROTOCOL_ERROR, "The padding is longer than the frame.")

            payload = payload[1:len(payload) - pad]

        return payload

    async def on_data(self, frame: H2Frame):
        if frame.stream == 0:
            raise H2Error(Code.PROTOCOL_ERROR, "A DATA frame has no stream.")

        self.recv_window -= len(frame.payload)
        stream = self.streams.get(frame.stream)

        if stream is None:
            if frame.stream <= self.highest_remote:
                await self.replenish(0, len(frame.payload))
                return

            raise H2Error(Code.PROTOCOL_ERROR, "A DATA frame names an unopened stream.")

        body = self.strip(frame)
        stream.feed(body)
        await self.replenish(frame.stream, len(frame.payload))

        if frame.flags & Flag.END_STREAM:
            stream.finish()

    async def replenish(self, stream: int, amount: int):
        if amount <= 0:
            return

        await self.write(H2Frame(Frame.WINDOW_UPDATE, 0, 0, amount.to_bytes(4, "big")))
        self.recv_window += amount

        if stream and stream in self.streams:
            await self.write(H2Frame(Frame.WINDOW_UPDATE, 0, stream, amount.to_bytes(4, "big")))

    async def on_headers(self, frame: H2Frame):
        if frame.stream == 0:
            raise H2Error(Code.PROTOCOL_ERROR, "A HEADERS frame has no stream.")

        payload = self.strip(frame)

        if frame.flags & Flag.PRIORITY:
            payload = payload[5:]

        ended = bool(frame.flags & Flag.END_STREAM)

        if frame.flags & Flag.END_HEADERS:
            await self.deliver(frame.stream, payload, ended)
        else:
            self.pending = (frame.stream, payload, ended)

    async def on_continuation(self, frame: H2Frame):
        if self.pending is None or frame.stream != self.pending[0]:
            raise H2Error(Code.PROTOCOL_ERROR, "An unexpected CONTINUATION frame arrived.")

        stream, block, ended = self.pending
        block += frame.payload

        if len(block) > self.local.max_header_list_size:
            raise H2Error(Code.COMPRESSION_ERROR, "The header block is larger than allowed.")

        if frame.flags & Flag.END_HEADERS:
            self.pending = None
            await self.deliver(stream, block, ended)
        else:
            self.pending = (stream, block, ended)

    async def deliver(self, stream: int, block: bytes, ended: bool):
        try:
            fields = self.decoder.decode(block)

        except HPACKError as e:
            raise H2Error(Code.COMPRESSION_ERROR, str(e))

        existing = self.streams.get(stream)

        if existing is not None:
            if existing.headed:
                existing.trailer(fields)
            else:
                existing.headed = True

                try:
                    existing.absorb(fields)

                except H2StreamError as e:
                    await self.reset(e.stream, e.code)
                    return

            if ended:
                existing.finish()

            return

        if not self.server:
            raise H2Error(Code.PROTOCOL_ERROR, "The server opened a stream.")

        if stream % 2 == 0 or stream <= self.highest_remote:
            raise H2Error(Code.PROTOCOL_ERROR, "A HEADERS frame uses an invalid new stream id.")

        if len(self.streams) >= self.local.max_concurrent_streams:
            self.highest_remote = stream
            await self.reset(stream, Code.REFUSED_STREAM)
            return

        self.highest_remote = stream
        connection = H2Connection(self, stream, server=True)
        connection.headed = True
        self.streams[stream] = connection

        try:
            connection.absorb(fields)

        except H2StreamError as e:
            await self.reset(e.stream, e.code)
            return

        if ended:
            connection.finish()

        await self.arrivals.put(connection)

    async def on_priority(self, frame: H2Frame):
        return

    async def on_reset(self, frame: H2Frame):
        if frame.stream == 0 or len(frame.payload) != 4:
            raise H2Error(Code.PROTOCOL_ERROR, "A malformed RST_STREAM frame arrived.")

        stream = self.streams.get(frame.stream)

        if stream is not None:
            stream.abort(int.from_bytes(frame.payload, "big"))

    async def on_settings(self, frame: H2Frame):
        if frame.stream != 0:
            raise H2Error(Code.PROTOCOL_ERROR, "A SETTINGS frame is not on stream zero.")

        if frame.flags & Flag.ACK:
            return

        before = self.remote.initial_window_size
        self.remote.apply(frame.payload)

        delta = self.remote.initial_window_size - before

        if delta:
            for stream in self.streams.values():
                stream.send_window += delta

        self.encoder.capacity = self.remote.header_table_size

        await self.write(H2Frame(Frame.SETTINGS, Flag.ACK, 0, b""))
        await self.wake()

    async def on_push(self, frame: H2Frame):
        raise H2Error(Code.PROTOCOL_ERROR, "Server push is disabled, so PUSH_PROMISE is a protocol error.")

    async def on_ping(self, frame: H2Frame):
        if frame.stream != 0 or len(frame.payload) != 8:
            raise H2Error(Code.PROTOCOL_ERROR, "A malformed PING frame arrived.")

        if not frame.flags & Flag.ACK:
            await self.write(H2Frame(Frame.PING, Flag.ACK, 0, frame.payload))

    async def on_goaway(self, frame: H2Frame):
        self.closing = True
        self.wake_all()

    async def on_window(self, frame: H2Frame):
        if len(frame.payload) != 4:
            raise H2Error(Code.FRAME_SIZE_ERROR, "A malformed WINDOW_UPDATE frame arrived.")

        increment = int.from_bytes(frame.payload, "big") & 0x7FFFFFFF

        if increment == 0:
            if frame.stream:
                await self.reset(frame.stream, Code.PROTOCOL_ERROR)
                return

            raise H2Error(Code.PROTOCOL_ERROR, "A WINDOW_UPDATE increment of zero arrived.")

        if frame.stream == 0:
            self.send_window += increment
        elif frame.stream in self.streams:
            self.streams[frame.stream].send_window += increment

        await self.wake()

    # -- flow control ----------------------------------------------------

    async def wake(self):
        async with self.flow:
            self.flow.notify_all()

    def wake_all(self):
        for stream in self.streams.values():
            stream.wake()

    async def goaway(self, code: int, message: str = ""):
        if self.closing:
            return

        self.closing = True

        try:
            await self.write(H2Frame(Frame.GOAWAY, 0, 0, self.highest_remote.to_bytes(4, "big") + code.to_bytes(4, "big") + message.encode()[:256]))

        except (H2Error, TCPError, UDSError, TLSError):
            pass

    async def reset(self, stream: int, code: int):
        try:
            await self.write(H2Frame(Frame.RST_STREAM, 0, stream, code.to_bytes(4, "big")))

        except (H2Error, TCPError, UDSError, TLSError):
            pass

        if stream in self.streams:
            self.streams[stream].abort(code)

    def forget(self, stream: int):
        self.streams.pop(stream, None)

    # -- outbound requests (client) --------------------------------------

    async def request(self, message: HTTPRequest) -> "H2Connection":
        if self.closing or self.error is not None:
            raise HTTPError(502, "The HTTP/2 connection is no longer usable.")

        stream = self.next_stream
        self.next_stream += 2

        connection = H2Connection(self, stream, server=False)
        self.streams[stream] = connection

        await connection.deliver_request(message)
        return connection

    async def send_headers(self, stream: int, fields: List[Tuple[str, str]], *, end_stream: bool):
        block = self.encoder.encode(fields)
        limit = self.remote.max_frame_size

        flags = Flag.END_HEADERS | (Flag.END_STREAM if end_stream else 0)

        if len(block) <= limit:
            await self.write(H2Frame(Frame.HEADERS, flags, stream, block))
            return

        await self.write(H2Frame(Frame.HEADERS, (Flag.END_STREAM if end_stream else 0), stream, block[:limit]))

        for offset in range(limit, len(block), limit):
            piece = block[offset:offset + limit]
            last = offset + limit >= len(block)
            await self.write(H2Frame(Frame.CONTINUATION, Flag.END_HEADERS if last else 0, stream, piece))

    async def send_data(self, stream: "H2Connection", data: bytes, *, end_stream: bool):
        offset = 0

        while offset < len(data) or (end_stream and offset == 0 and not data):
            room = await self.allow(stream, len(data) - offset)
            piece = data[offset:offset + room]
            offset += len(piece)

            last = end_stream and offset >= len(data)
            await self.write(H2Frame(Frame.DATA, Flag.END_STREAM if last else 0, stream.id, piece))

            if not data:
                break

    async def allow(self, stream: "H2Connection", want: int) -> int:
        async with self.flow:
            while True:
                if self.error is not None or self.closing or stream.reset_code is not None:
                    raise HTTPError(502, "The HTTP/2 stream cannot send any more data.")

                room = min(want, self.send_window, stream.send_window, self.remote.max_frame_size)

                if room > 0 or want == 0:
                    self.send_window -= max(room, 0)
                    stream.send_window -= max(room, 0)
                    return max(room, 0)

                await self.flow.wait()

class H2Connection(HTTPConnection):
    def __init__(self, session: H2Session, stream: int, *, server: bool):
        super().__init__(("", None), ("", None), transport=session.transport, version="HTTP/2.0", limits=session.limits)

        self.session = session
        self.id = stream
        self.server = server

        self.headers: List[Tuple[str, str]] = []
        self.trailers: List[Tuple[str, str]] = []
        self.buffer = bytearray()

        self.request: Optional[HTTPRequest] = None
        self.response: Optional[HTTPResponse] = None

        self.headed = False
        self.ended = False
        self.replied = False
        self.reset_code: Optional[int] = None

        self.send_window = session.remote.initial_window_size
        self.ready: Optional[asyncio.Future] = None

    @property
    def secure(self) -> bool:
        return hasattr(self.session.transport, "session")

    def wake(self):
        if self.ready is not None and not self.ready.done():
            self.ready.set_result(None)

    def feed(self, data: bytes):
        self.buffer += data
        self.wake()

    def finish(self):
        self.ended = True
        self.wake()

    def trailer(self, fields: List[Tuple[str, str]]):
        self.trailers = fields

    def abort(self, code: int):
        self.reset_code = code
        self.ended = True
        self.wake()

    def absorb(self, fields: List[Tuple[str, str]]):
        pseudo, regular = self.split(fields)

        if self.server:
            self.request = self.request_from(pseudo, regular)
        else:
            self.response = self.response_from(pseudo, regular)

    def split(self, fields: List[Tuple[str, str]]) -> Tuple[Dict[str, str], HTTPHeaders]:
        pseudo: Dict[str, str] = {}
        regular = HTTPHeaders()
        seen_regular = False

        for name, value in fields:
            if name.startswith(":"):
                if seen_regular:
                    raise H2StreamError(Code.PROTOCOL_ERROR, self.id, "A pseudo-header follows a regular header.")

                if name in pseudo:
                    raise H2StreamError(Code.PROTOCOL_ERROR, self.id, f"The pseudo-header {name} is repeated.")

                pseudo[name] = value
            else:
                seen_regular = True

                if name in ("connection", "transfer-encoding", "keep-alive", "upgrade", "proxy-connection"):
                    raise H2StreamError(Code.PROTOCOL_ERROR, self.id, f"The connection-specific header {name!r} is forbidden in HTTP/2.")

                if name == "te" and value.lower() != "trailers":
                    raise H2StreamError(Code.PROTOCOL_ERROR, self.id, "The te header may only be 'trailers' in HTTP/2.")

                if name != name.lower():
                    raise H2StreamError(Code.PROTOCOL_ERROR, self.id, "A header field name is not lowercase.")

                regular.append(name, value)

        return (pseudo, regular)

    def request_from(self, pseudo: Dict[str, str], regular: HTTPHeaders) -> HTTPRequest:
        for required in (":method", ":scheme", ":path"):
            if required not in pseudo:
                raise H2StreamError(Code.PROTOCOL_ERROR, self.id, f"The request is missing {required}.")

        for name in pseudo:
            if name not in (":method", ":scheme", ":path", ":authority"):
                raise H2StreamError(Code.PROTOCOL_ERROR, self.id, f"{name} is not a valid request pseudo-header.")

        if not pseudo[":path"]:
            raise H2StreamError(Code.PROTOCOL_ERROR, self.id, "The :path pseudo-header is empty.")

        if ":authority" in pseudo:
            regular.set("Host", pseudo[":authority"], override=False)

        request = HTTPRequest(version="HTTP/2.0", method=pseudo[":method"], target=pseudo[":path"], headers=regular, secure=pseudo[":scheme"] == "https")
        return request

    def response_from(self, pseudo: Dict[str, str], regular: HTTPHeaders) -> HTTPResponse:
        if ":status" not in pseudo or not pseudo[":status"].isdigit():
            raise H2StreamError(Code.PROTOCOL_ERROR, self.id, "The response is missing a valid :status.")

        return HTTPResponse(version="HTTP/2.0", status_code=int(pseudo[":status"]), headers=regular, secure=self.secure)

    # -- receiving -------------------------------------------------------

    async def receive_message(self) -> Optional[HTTPMessage]:
        while not self.ended:
            self.ready = asyncio.get_running_loop().create_future()

            try:
                await self.ready
            finally:
                self.ready = None

        if self.reset_code is not None:
            raise HTTPError(502, f"The peer reset the stream with code {self.reset_code}.")

        message = self.request if self.server else self.response

        if message is None:
            raise HTTPError(502, "The stream ended without a complete message.")

        message.body = bytes(self.buffer)
        self.buffer.clear()

        if self.trailers:
            message.trailers = HTTPHeaders(self.trailers)

        self.absorb_encoding(message)
        self.state = HTTPState.RECEIVED

        if not self.server:
            self.session.forget(self.id)

        return message

    def absorb_encoding(self, message: HTTPMessage):
        if isinstance(message.body, bytes) and message.body and "Content-Encoding" in message.headers:
            message.compressed = True
            decompress(message, limits=self.limits)

    # -- sending ---------------------------------------------------------

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
            (":scheme", "https" if request.secure else "http"),
            (":authority", authority),
            (":path", path),
        ]

        fields = pseudo + self.regular(request.headers)
        body = self.body_bytes(request)

        if body and request.headers is not None:
            request.headers.set("Content-Length", str(len(body)), override=False)
            fields = pseudo + self.regular(request.headers)

        await self.session.send_headers(self.id, fields, end_stream=not body)

        if body:
            await self.session.send_data(self, body, end_stream=True)

        self.replied = True
        self.state = HTTPState.SENT

    async def send_response(self, response: HTTPResponse):
        if response.compression and self.request is not None:
            compress(response, self.request.headers.get("Accept-Encoding", ""), limits=self.limits)

        fields = [(":status", str(response.status_code))] + self.regular(response.headers)
        bodiless = response.status_code < 200 or response.status_code in (204, 304) or (self.request is not None and self.request.method == "HEAD")

        body = b"" if bodiless else self.body_bytes(response)

        await self.session.send_headers(self.id, fields, end_stream=not body and not isinstance(response.body, AsyncIterator))

        if not bodiless and isinstance(response.body, AsyncIterator):
            async for chunk in response.body:
                if chunk:
                    await self.session.send_data(self, chunk, end_stream=False)

            await self.session.send_data(self, b"", end_stream=True)

        elif body:
            await self.session.send_data(self, body, end_stream=True)

        self.replied = True
        self.state = HTTPState.SENT

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
            await self.send_response(HTTPResponse(version="HTTP/2.0", status_code=code, headers=HTTPHeaders(), body=b"", compression=False))

        except (HTTPError, H2Error, H2StreamError, TCPError, UDSError, TLSError):
            await self.reset(Code.INTERNAL_ERROR)

    async def reset(self, code: int = Code.CANCEL):
        self.reset_code = code
        await self.session.reset(self.id, code)

    async def accept(self):
        return

    async def reject(self):
        await self.reset(Code.REFUSED_STREAM)

    async def wait(self, value: HTTPState):
        if value in (HTTPState.RECEIVED, HTTPState.RECEIVED_BODY) and self.request is None and self.server:
            await self.receive_message()

        while value in (HTTPState.RECEIVED, HTTPState.RECEIVED_BODY) and not self.ended:
            await self.receive_message()

    async def send_raw(self, data: bytes, *, final: bool = True):
        await self.session.send_data(self, data, end_stream=final)

    async def receive_raw(self, n: int = -1) -> Optional[bytes]:
        while not self.buffer and not self.ended:
            self.ready = asyncio.get_running_loop().create_future()

            try:
                await self.ready
            finally:
                self.ready = None

        data = bytes(self.buffer if n < 0 else self.buffer[:n])
        del self.buffer[:len(data)]

        return data

    async def close(self, *, half_close: bool = False, send_pending: bool = False):
        self.session.forget(self.id)
