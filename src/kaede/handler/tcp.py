from __future__ import annotations

import os
import asyncio
import ipaddress
from typing import Literal

from ..api import ClientHandler, ServerHandler
from ..http import H1, H2, H2WSUpgrade
from ..tls import TLSInfo, TLSContext, RecordTLS
from ..models import Request, Response, Headers
from ..process import process_request
from ..websocket import WebSocket, WebSocketProtocolError, compute_accept, parse_frames
from .common import parse_peername, negotiate_websocket, MAX_RESPONSE_HEADER_SIZE, StreamState, dispatch_event, consume_response
from .tls_transport import TLSTransport, tls_start, tls_feed

class H2WebSocketTransport:
    def __init__(self, h2: H2, stream_id: int, transport: asyncio.Transport):
        self.h2 = h2
        self.stream_id = stream_id
        self.transport = transport

    def write(self, data: bytes):
        if self.transport.is_closing():
            return
        out = self.h2.websocket_send(self.stream_id, data)
        if out:
            self.transport.write(out)

    def close(self):
        out = self.h2.websocket_close(self.stream_id)
        if out and not self.transport.is_closing():
            self.transport.write(out)

class TCPServerProtocol(asyncio.Protocol):
    def __init__(self, handler: ServerHandler):
        self.handler = handler

        self.transport: asyncio.Transport | TLSTransport | None = None
        self.raw_transport: asyncio.Transport | None = None
        self.tls_engine: RecordTLS | None = None
        self.buffer = bytearray()

        self.websocket: WebSocket | None = None
        self.websocket_buffer: bytearray = bytearray()
        self.websocket_pending: bool = False

        self.client: tuple = (ipaddress.IPv4Address("0.0.0.0"), 0)
        self.secure: bool = False

        self.h2: H2 | None = None
        self.tls: TLSInfo | None = None

        self.continue_sent: bool = False
        self.reading_paused: bool = False

        self.keep_alive: bool = True
        self.keep_alive_handle: asyncio.TimerHandle | None = None

        self.request_queue: asyncio.Queue[tuple[Request, bool] | None] = asyncio.Queue()
        self.request_consumer: asyncio.Task | None = None

        self.inflight: int = 0

    def reset_keepalive(self):
        if self.keep_alive_handle is not None:
            self.keep_alive_handle.cancel()
            self.keep_alive_handle = None

        if self.transport is not None and self.keep_alive and self.websocket is None and self.inflight == 0:
            self.keep_alive_handle = asyncio.get_running_loop().call_later(self.handler.config.keepalive_timeout, self.on_keepalive_timeout)

    def cancel_keepalive(self):
        if self.keep_alive_handle is not None:
            self.keep_alive_handle.cancel()
            self.keep_alive_handle = None

    def on_keepalive_timeout(self):
        self.keep_alive_handle = None

        if self.transport is not None and not self.transport.is_closing():
            self.transport.close()

    def connection_made(self, transport: asyncio.BaseTransport):
        self.raw_transport = transport
        self.transport = transport
        self.client = parse_peername(transport)

        if self.handler.shutdown:
            transport.close()
            return

        if isinstance(transport, asyncio.Transport):
            self.handler.active_transports.add(transport)

        if self.handler.listener.kind == "https":
            self.tls_engine = self.handler.tls_server_context().connection()
            self.transport = TLSTransport(transport, self.tls_engine)
        else:
            self.secure = False

        self.reset_keepalive()

    def on_tls_established(self):
        engine = self.tls_engine
        self.secure = True
        self.tls = engine.info()

        if engine.selected_alpn() == "h2" and "h2" in self.handler.config.protocols:
            self.h2 = H2(connection_id=os.urandom(8), max_body_size=self.handler.config.max_body_size, max_concurrent_streams=self.handler.config.max_concurrent_streams, max_stream_resets=self.handler.config.max_stream_resets)
            self.transport.write(self.h2.initiate())

        elif "http/1.1" not in self.handler.config.protocols:
            self.transport.close()

    def data_received(self, data: bytes):
        if self.transport is None:
            return

        if self.tls_engine is None:
            self.feed_plaintext(data)
            return

        engine = self.tls_engine
        try:
            became_ready, plaintext = tls_feed(engine, self.raw_transport, data)
        except Exception:
            self.transport.close()
            return

        if became_ready:
            self.on_tls_established()
            if self.transport is None or self.transport.is_closing():
                return

        if plaintext:
            self.feed_plaintext(plaintext)

        if engine.closed and self.transport is not None and not self.transport.is_closing():
            self.transport.close()

    def feed_plaintext(self, data: bytes):
        if self.transport is None:
            return

        self.reset_keepalive()

        if self.websocket is not None:
            self.websocket_buffer.extend(data)

            try:
                frames = parse_frames(self.websocket_buffer, self.handler.config.max_websocket_message_size)
            except WebSocketProtocolError:
                self.websocket.close_transport(1002)
                return
            except ValueError:
                self.websocket.close_transport(1009)
                return

            for frame in frames:
                self.websocket.feed_frame(frame)

            return

        if self.websocket_pending:
            self.buffer.extend(data)
            return

        if self.h2 is None and "http/1.1" not in self.handler.config.protocols:
            self.transport.close()
            return

        if self.h2 is not None:
            out, requests, websocket_upgrades, closed = self.h2.receive(data, client=self.client, secure=self.secure, tls=self.tls)
            if out:
                self.transport.write(out)

            for request in requests:
                self.handler.create_task(self.h2_respond(request))

            for websocket_upgrade in websocket_upgrades:
                self.handler.create_task(self.h2_websocket_respond(websocket_upgrade))

            if closed:
                goaway = self.h2.close()
                if goaway:
                    self.transport.write(goaway)
                self.transport.close()

            return

        self.buffer.extend(data)

        while True:
            head_end = self.buffer.find(b"\r\n\r\n")

            if head_end == -1:
                if len(self.buffer) > self.handler.config.max_header_size:
                    self.send_error(431, "Request Header Fields Too Large")
                    self.transport.close()
                return

            if head_end > self.handler.config.max_header_size:
                self.send_error(431, "Request Header Fields Too Large")
                self.transport.close()
                return

            body_start = head_end + 4

            malformed = False
            expect_continue = False

            transfer_encodings: list[bytes] = []
            content_lengths: list[bytes] = []

            for line in bytes(self.buffer[:head_end]).split(b"\r\n")[1:]:
                if line[:1] in (b" ", b"\t"):
                    malformed = True
                    break

                name_b, sep_b, value_b = line.partition(b":")
                if not sep_b:
                    malformed = True
                    break

                name = name_b.strip().lower()
                value = value_b.strip()

                if name == b"transfer-encoding":
                    transfer_encodings.append(value.lower())

                elif name == b"content-length":
                    content_lengths.append(value)

                elif name == b"expect" and value.lower() == b"100-continue":
                    expect_continue = True

            if malformed or len(transfer_encodings) > 1 or len(content_lengths) > 1:
                self.send_error(400, "Bad Request")
                self.transport.close()
                return

            is_chunked = False

            transfer_encoding_raw = transfer_encodings[0] if transfer_encodings else b""
            content_length_raw = content_lengths[0] if content_lengths else None

            if transfer_encoding_raw:
                te_tokens = [t.strip() for t in transfer_encoding_raw.split(b",") if t.strip()]

                if te_tokens[-1:] != [b"chunked"] or te_tokens.count(b"chunked") != 1:
                    self.send_error(400, "Bad Request")
                    self.transport.close()
                    return

                is_chunked = True

            if is_chunked and content_length_raw is not None:
                self.send_error(400, "Bad Request")
                self.transport.close()
                return

            if is_chunked:
                try:
                    scan = H1.scan_chunked(bytes(self.buffer[body_start:]), max_body_size=self.handler.config.max_body_size)
                except ValueError:
                    self.send_error(400, "Bad Request")
                    self.transport.close()
                    return

                if scan is None:
                    if len(self.buffer) - body_start > self.handler.config.max_body_size:
                        self.send_error(413, "Payload Too Large")
                        self.transport.close()
                        return

                    self.send_continue(expect_continue)
                    return
                consumed = body_start + scan[1]

            elif content_length_raw is not None:
                if not (content_length_raw.isascii() and content_length_raw.isdigit()):
                    self.send_error(400, "Bad Request")
                    self.transport.close()
                    return

                expected = int(content_length_raw)
                if expected > self.handler.config.max_body_size:
                    self.send_error(413, "Payload Too Large")
                    self.transport.close()
                    return

                if len(self.buffer) - body_start < expected:
                    self.send_continue(expect_continue)
                    return

                consumed = body_start + expected

            else:
                consumed = body_start

            try:
                request = H1.parse_request(bytes(self.buffer[:consumed]), client=self.client, scheme="https" if self.secure else "http", secure=self.secure, tls=self.tls, max_body_size=self.handler.config.max_body_size)
            except (ValueError, UnicodeDecodeError):
                self.transport.close()
                return

            del self.buffer[:consumed]
            self.continue_sent = False

            keep_alive = not "close" in (request.headers.get("Connection") or "").lower()

            if self.request_consumer is None:
                self.request_consumer = self.handler.create_task(self.h1_consume_requests())

            self.request_queue.put_nowait((request, keep_alive))

            if request.is_websocket_upgrade:
                self.websocket_pending = True
                return

            if not keep_alive:
                return

            if not self.reading_paused and self.request_queue.qsize() >= self.handler.config.max_pipeline_buffer_len:
                self.reading_paused = True
                self.transport.pause_reading()
                return

    def connection_lost(self, exc: BaseException | None):
        if self.keep_alive_handle is not None:
            self.keep_alive_handle.cancel()
            self.keep_alive_handle = None

        self.transport = None
        raw = self.raw_transport
        self.raw_transport = None

        if raw is not None:
            self.handler.active_transports.discard(raw)

        if self.h2 is not None:
            for queue in self.h2.websocket_streams.values():
                queue.put_nowait(None)
            self.h2.flow_control_event.set()
            self.h2 = None

        if self.websocket is not None and not self.websocket.closed:
            self.websocket.queue.put_nowait(None)

        self.request_queue.put_nowait(None)

        self.buffer.clear()

    def send_continue(self, expect_continue: bool):
        if expect_continue and not self.continue_sent and self.transport is not None and not self.transport.is_closing():
            self.continue_sent = True
            self.transport.write(b"HTTP/1.1 100 Continue\r\n\r\n")

    def send_error(self, status: int, phrase: str):
        if self.transport is not None and not self.transport.is_closing():
            self.transport.write(f"HTTP/1.1 {status} {phrase}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".encode("latin-1"))

    async def run_websocket(self, request: Request, ws: WebSocket):
        self.handler.active_websockets.add(ws)
        try:
            await self.handler.callback.on_websocket(request, ws)
        except Exception:
            pass
        finally:
            self.handler.active_websockets.discard(ws)
            if not ws.closed:
                await ws.close(1011)

    async def h1_respond(self, request: Request):
        if self.transport is None:
            return

        if request.is_websocket_upgrade:
            if self.handler.shutdown:
                self.transport.write(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Connection: close\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                self.transport.close()
                return

            await self.h1_websocket_upgrade(request, request.headers.get("Sec-WebSocket-Key", "").strip())
            return

        response = await process_request(request, callback=self.handler.callback, config=self.handler.config)

        if self.handler.shutdown:
            response.headers.set("Connection", "close")
            self.keep_alive = False

        if "h3" in self.handler.config.protocols and self.handler.config.bind_quic:
            _, _, h3_port = self.handler.config.bind_quic[0].rpartition(':')
            response.headers.set("Alt-Svc", f"h3=\":{int(h3_port)}\"", override=False)

        if response.is_streaming:
            await self.h1_stream(response)
            return

        result = H1.build_response(response)

        if isinstance(result, tuple):
            head, alt_body = result
            self.transport.write(head)

            if alt_body is not None:
                await self.h1_send_file(alt_body, response.file_range)

        else:
            self.transport.write(result)

        if not self.keep_alive:
            self.transport.close()

    async def h1_stream(self, response: Response):
        if self.transport is None:
            return

        self.transport.write(H1.build_response_head(response))

        try:
            async for chunk in response.body:
                if chunk and self.transport is not None:
                    self.transport.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")

        finally:
            if self.transport is not None:
                self.transport.write(b"0\r\n\r\n")
                if not self.keep_alive:
                    self.transport.close()

    async def h1_send_file(self, path: os.PathLike, file_range: tuple[int, int] | None = None):
        if self.transport is None:
            return
        loop = asyncio.get_running_loop()

        try:
            fp = await loop.run_in_executor(None, lambda: open(os.fspath(path), "rb"))
        except OSError:
            if self.transport is not None and not self.transport.is_closing():
                self.transport.close()
            return

        try:
            remaining = None
            if file_range is not None:
                start, end = file_range
                await loop.run_in_executor(None, fp.seek, start)
                remaining = end - start + 1

            while self.transport is not None:
                size = 65536 if remaining is None else min(65536, remaining)
                if size <= 0:
                    break
                chunk = await loop.run_in_executor(None, fp.read, size)
                if not chunk:
                    break
                self.transport.write(chunk)
                if remaining is not None:
                    remaining -= len(chunk)
        finally:
            await loop.run_in_executor(None, fp.close)

    async def h1_consume_requests(self):
        while True:
            item = await self.request_queue.get()
            if item is None or self.transport is None:
                break

            self.cancel_keepalive()

            request, keep_alive = item
            self.keep_alive = keep_alive

            await self.h1_respond(request)

            if self.websocket is not None:
                break
            if not self.keep_alive or self.transport is None:
                break

            if self.reading_paused and self.request_queue.qsize() < self.handler.config.max_pipeline_buffer_len // 2 and not self.transport.is_closing():
                self.reading_paused = False
                self.transport.resume_reading()

            self.reset_keepalive()

    async def h1_websocket_upgrade(self, request: Request, ws_key: str):
        if self.transport is None:
            return

        subprotocol, deflate = negotiate_websocket(request, self.handler.callback.websocket_subprotocols)
        accept = compute_accept(ws_key)

        lines = [
            b"HTTP/1.1 101 Switching Protocols\r\n",
            b"Upgrade: websocket\r\n",
            b"Connection: Upgrade\r\n",
            b"Sec-WebSocket-Accept: " + accept.encode() + b"\r\n"
        ]
        if subprotocol:
            lines.append(b"Sec-WebSocket-Protocol: " + subprotocol.encode() + b"\r\n")
        if deflate is not None:
            lines.append(b"Sec-WebSocket-Extensions: " + deflate.response_header().encode() + b"\r\n")
        lines.append(b"\r\n")

        self.transport.write(b"".join(lines))
        ws = WebSocket(self.transport, subprotocol=subprotocol, deflate=deflate, max_message_size=self.handler.config.max_websocket_message_size)
        self.websocket = ws

        self.websocket_buffer = self.buffer
        self.buffer = bytearray()
        self.websocket_pending = False

        self.handler.create_task(self.run_websocket(request, ws))

        if self.websocket_buffer:
            try:
                frames = parse_frames(self.websocket_buffer, self.handler.config.max_websocket_message_size)
            except WebSocketProtocolError:
                ws.close_transport(1002)
                return
            except ValueError:
                ws.close_transport(1009)
                return
            for frame in frames:
                ws.feed_frame(frame)

    async def h2_respond(self, request: Request):
        if self.transport is None or self.h2 is None or request.h2 is None:
            return

        self.inflight += 1
        self.cancel_keepalive()
        try:
            response = await process_request(request, callback=self.handler.callback, config=self.handler.config)

            if "h3" in self.handler.config.protocols and self.handler.config.bind_quic:
                _, _, h3_port = self.handler.config.bind_quic[0].rpartition(':')
                response.headers.set("Alt-Svc", f"h3=\":{int(h3_port)}\"", override=False)

            if response.is_streaming:
                await self.h2_stream(request.h2.stream_id, response)
                return

            out, alt_body = self.h2.send_response(request.h2.stream_id, response)

            if out:
                self.transport.write(out)

            if alt_body is not None:
                await self.h2_send_file(request.h2.stream_id, alt_body, response.file_range)

        finally:
            self.inflight -= 1
            if self.inflight == 0 and self.transport is not None:
                self.reset_keepalive()

    async def h2_stream(self, stream_id: int, response: Response):
        if self.transport is None or self.h2 is None:
            return

        out = self.h2.send_response_headers(stream_id, response)
        if out:
            self.transport.write(out)

        try:
            async for chunk in response.body:
                if chunk and self.transport is not None and self.h2 is not None:
                    out = self.h2.send_chunk(stream_id, chunk, end_stream=False)
                    if out:
                        self.transport.write(out)
                    await self.h2_drain_window(stream_id)

        finally:
            if self.h2 is not None and self.transport is not None:
                out = self.h2.send_chunk(stream_id, b"", end_stream=True)
                if out:
                    self.transport.write(out)

    async def h2_send_file(self, stream_id: int, path: os.PathLike, file_range: tuple[int, int] | None = None):
        if self.transport is None or self.h2 is None:
            return
        loop = asyncio.get_running_loop()

        try:
            fp = await loop.run_in_executor(None, lambda: open(os.fspath(path), "rb"))
        except OSError:
            out = self.h2.send_chunk(stream_id, b"", end_stream=True)
            if out and self.transport is not None:
                self.transport.write(out)
            return

        sent_any = False
        try:
            remaining = None
            if file_range is not None:
                start, end = file_range
                await loop.run_in_executor(None, fp.seek, start)
                remaining = end - start + 1

            pending = await loop.run_in_executor(None, fp.read, 65536 if remaining is None else min(65536, remaining))
            while pending and self.transport is not None and self.h2 is not None:
                if remaining is not None:
                    remaining -= len(pending)
                size = 65536 if remaining is None else min(65536, remaining)
                nxt = await loop.run_in_executor(None, fp.read, size) if size > 0 else b""
                is_last = not nxt
                out = self.h2.send_chunk(stream_id, pending, end_stream=is_last)
                if out and self.transport:
                    self.transport.write(out)
                sent_any = True
                pending = nxt
                await self.h2_drain_window(stream_id)

        finally:
            await loop.run_in_executor(None, fp.close)

        if not sent_any and self.h2 is not None:
            out = self.h2.send_chunk(stream_id, b"", end_stream=True)
            if out and self.transport:
                self.transport.write(out)

    async def h2_websocket_read(self, stream_id: int, ws: WebSocket):
        if self.h2 is None:
            return

        queue = self.h2.websocket_streams.get(stream_id)
        if queue is None:
            return

        buf = bytearray()

        while True:
            chunk = await queue.get()
            if chunk is None:
                ws.queue.put_nowait(None)
                break

            buf.extend(chunk)
            try:
                frames = parse_frames(buf, self.handler.config.max_websocket_message_size)
            except WebSocketProtocolError:
                ws.close_transport(1002)
                break
            except ValueError:
                ws.close_transport(1009)
                break
            for frame in frames:
                ws.feed_frame(frame)

    async def h2_websocket_respond(self, upgrade: H2WSUpgrade):
        if self.transport is None or self.h2 is None:
            return

        subprotocol, deflate = negotiate_websocket(upgrade.request, self.handler.callback.websocket_subprotocols)

        out = self.h2.websocket_accept(upgrade.stream_id, subprotocol=subprotocol, extensions=deflate.response_header() if deflate is not None else None)
        if out:
            self.transport.write(out)

        ws_transport = H2WebSocketTransport(self.h2, upgrade.stream_id, self.transport)
        ws = WebSocket(ws_transport, require_masking=False, subprotocol=subprotocol, deflate=deflate, max_message_size=self.handler.config.max_websocket_message_size)

        self.inflight += 1
        self.cancel_keepalive()
        try:
            self.handler.create_task(self.h2_websocket_read(upgrade.stream_id, ws))
            await self.run_websocket(upgrade.request, ws)
        finally:
            self.inflight -= 1
            if self.inflight == 0 and self.transport is not None:
                self.reset_keepalive()

    async def h2_drain_window(self, stream_id: int):
        while self.h2 is not None and self.transport is not None and not self.transport.is_closing():
            if self.h2.stream_buffered(stream_id) <= self.handler.config.max_stream_buffer_size:
                return

            self.h2.flow_control_event.clear()

            if self.h2.stream_buffered(stream_id) <= self.handler.config.max_stream_buffer_size:
                return

            await self.h2.flow_control_event.wait()

class TCPClientProtocol(asyncio.Protocol):
    def __init__(self, handler: ClientHandler, key: tuple, authority: str, tls_context: TLSContext | None = None, server_name: str | None = None):
        self.handler = handler
        self.key = key
        self.authority = authority

        self.transport: asyncio.Transport | TLSTransport | None = None
        self.raw_transport: asyncio.Transport | None = None
        self.tls_context = tls_context
        self.server_name = server_name
        self.tls_engine: RecordTLS | None = None
        self.tls_ready = False
        self.ready: asyncio.Future = asyncio.get_running_loop().create_future()
        self.closed = False

        self.mode: Literal["h1", "h2"] = "h1"
        self.multiplexed = False

        # HTTP/1.1
        self.buffer = bytearray()
        self.current: StreamState | None = None
        self.method = "GET"
        self.state = "idle"
        self.remaining = 0
        self.chunk_remaining = 0
        self.headers: Headers | None = None
        self.reusable = False

        # HTTP/2
        self.h2: H2 | None = None
        self.h2_settings: asyncio.Event = asyncio.Event()
        self.streams: dict[int, StreamState] = {}

    def connection_made(self, transport: asyncio.BaseTransport):
        self.raw_transport = transport

        if self.tls_context is not None:
            self.tls_engine = self.tls_context.connection(self.server_name)
            self.transport = TLSTransport(transport, self.tls_engine)
            try:
                tls_start(self.tls_engine, transport)
            except Exception as exc:
                if not self.ready.done():
                    self.ready.set_exception(exc)
                transport.close()
            return

        self.transport = transport
        if not self.ready.done():
            self.ready.set_result(None)

    def on_tls_established(self):
        self.tls_ready = True

        if self.tls_engine.selected_alpn() == "h2":
            self.mode = "h2"
            self.multiplexed = True
            self.h2 = H2(client_side=True, max_body_size=self.handler.config.max_body_size, max_concurrent_streams=self.handler.config.max_concurrent_streams)
            self.transport.write(self.h2.initiate())

        if not self.ready.done():
            self.ready.set_result(None)

    def data_received(self, data: bytes):
        if self.tls_engine is None:
            self.feed_decrypted(data)
            return

        engine = self.tls_engine
        try:
            became_ready, plaintext = tls_feed(engine, self.raw_transport, data)
        except Exception as exc:
            if not self.ready.done():
                self.ready.set_exception(exc)
            self.close()
            return

        if became_ready:
            self.on_tls_established()

        if plaintext:
            self.feed_decrypted(plaintext)

        if engine.closed:
            self.close()

    def feed_decrypted(self, data: bytes):
        if self.mode == "h2":
            self.feed_h2(data)
        else:
            self.feed_h1(data)

    def connection_lost(self, exc: BaseException | None):
        self.closed = True
        self.transport = None

        if self.h2 is not None:
            for queue in self.h2.websocket_streams.values():
                queue.put_nowait(None)
            for state in list(self.streams.values()):
                state.fail(exc or ConnectionError("connection closed"))

        if self.current is not None:
            if self.state == "close":
                self.current.finish()
            elif not self.current.ended:
                self.current.fail(exc or ConnectionError("connection closed"))
            self.current = None

    def is_open(self) -> bool:
        return self.transport is not None and not self.closed

    def keepalive(self) -> bool:
        if self.headers is None:
            return False
        return "close" not in (self.headers.get("Connection") or "").lower()

    def close(self):
        if self.transport is not None and not self.transport.is_closing():
            self.transport.close()

    async def request(self, request: Request, streaming: bool) -> Response:
        if self.mode == "h2":
            return await self.h2_request(request, streaming)
        return await self.h1_request(request, streaming)

    def feed_h1(self, data: bytes):
        self.buffer.extend(data)

        while self.current is not None:
            if self.state == "head":
                idx = self.buffer.find(b"\r\n\r\n")
                if idx == -1:
                    if len(self.buffer) > MAX_RESPONSE_HEADER_SIZE:
                        self.fail_h1(ValueError("response header too large"))
                    return

                head = bytes(self.buffer[:idx])
                del self.buffer[:idx + 4]

                try:
                    status, _, headers = H1.parse_response_head(head)
                except ValueError as exc:
                    self.fail_h1(exc)
                    return

                if 100 <= status < 200 and status != 101:
                    continue

                self.headers = headers

                if H1.response_has_no_body(status, self.method):
                    self.current.set_headers(status, headers)
                    self.finish_h1()
                    return

                transfer_encoding = (headers.get("Transfer-Encoding") or "").lower()
                content_length = headers.get("Content-Length")

                if transfer_encoding:
                    te_tokens = [t.strip() for t in transfer_encoding.split(",") if t.strip()]

                    if te_tokens[-1:] != ["chunked"]:
                        self.fail_h1(ValueError("invalid Transfer-Encoding"))
                        return

                    self.current.set_headers(status, headers)
                    self.state = "chunk-size"

                elif content_length is not None:
                    if isinstance(content_length, list) or not (content_length.isascii() and content_length.isdigit()):
                        self.fail_h1(ValueError("invalid Content-Length"))
                        return

                    self.remaining = int(content_length)
                    self.current.set_headers(status, headers)

                    if self.remaining == 0:
                        self.finish_h1()
                        return

                    self.state = "length"

                else:
                    self.current.set_headers(status, headers)
                    self.state = "close"

            elif self.state == "length":
                if not self.buffer:
                    return

                take = min(self.remaining, len(self.buffer))
                self.current.push(bytes(self.buffer[:take]))

                del self.buffer[:take]
                self.remaining -= take

                if self.remaining == 0:
                    self.finish_h1()
                    return

                return

            elif self.state == "close":
                if self.buffer:
                    self.current.push(bytes(self.buffer))
                    self.buffer.clear()

                return

            elif self.state in ("chunk-size", "chunk-data", "chunk-data-crlf", "chunk-trailer"):
                if not self.feed_h1_chunked():
                    return

            else:
                return

    def feed_h1_chunked(self) -> bool:
        if self.state == "chunk-size":
            end = self.buffer.find(b"\r\n")
            if end == -1:
                return False

            line = bytes(self.buffer[:end]).split(b";", 1)[0].strip()
            del self.buffer[:end + 2]

            try:
                size = int(line, 16)

            except ValueError:
                self.fail_h1(ValueError("invalid chunk size"))
                return False

            if size < 0:
                self.fail_h1(ValueError("negative chunk size"))
                return False

            if size == 0:
                self.state = "chunk-trailer"
                return True

            self.chunk_remaining = size
            self.state = "chunk-data"
            return True

        if self.state == "chunk-data":
            if not self.buffer:
                return False

            take = min(self.chunk_remaining, len(self.buffer))
            self.current.push(bytes(self.buffer[:take]))

            del self.buffer[:take]
            self.chunk_remaining -= take

            if self.chunk_remaining == 0:
                self.state = "chunk-data-crlf"

            return True

        if self.state == "chunk-data-crlf":
            if len(self.buffer) < 2:
                return False

            if bytes(self.buffer[:2]) != b"\r\n":
                self.fail_h1(ValueError("malformed chunk terminator"))
                return False

            del self.buffer[:2]

            self.state = "chunk-size"
            return True

        if self.state == "chunk-trailer":
            end = self.buffer.find(b"\r\n")
            if end == -1:
                return False

            is_empty = end == 0

            del self.buffer[:end + 2]

            if is_empty:
                self.finish_h1()
                return False

            return True

        return False

    async def h1_request(self, request: Request, streaming: bool) -> Response:
        if self.transport is None:
            raise ConnectionError("connection is not available")

        self.method = request.method
        self.reusable = False
        self.current = StreamState(asyncio.get_running_loop(), self.handler.config.max_body_size)
        self.headers = None
        self.state = "head"

        if request.body:
            request.headers.set("Content-Length", str(len(request.body)), override=True)

        elif request.method in ("POST", "PUT", "PATCH", "DELETE"):
            request.headers.set("Content-Length", "0", override=False)

        request.headers.set("Connection", "keep-alive", override=False)

        self.transport.write(H1.build_request(request))

        def on_done():
            self.handler.release_h1(self)

        try:
            return await consume_response(self.current, streaming, "HTTP/1.1", self.handler.config.read_timeout, on_done)
        except BaseException:
            self.close()
            self.handler.discard(self)
            raise

    def finish_h1(self):
        if self.current is not None:
            self.current.finish()
        self.reusable = self.is_open() and self.keepalive()
        self.current = None
        self.state = "idle"

    def fail_h1(self, exc: BaseException):
        if self.current is not None:
            self.current.fail(exc)
            self.current = None
        self.reusable = False
        self.state = "idle"
        self.close()

    def feed_h2(self, data: bytes):
        if self.h2 is None or self.transport is None:
            return

        out, events, closed = self.h2.receive_response(data)
        if out:
            self.transport.write(out)

        for event in events:
            if event[0] == "settings":
                self.h2_settings.set()
                continue
            dispatch_event(self.streams, event)

        if closed:
            self.close()

    async def h2_request(self, request: Request, streaming: bool) -> Response:
        if self.h2 is None or self.transport is None:
            raise ConnectionError("connection is not available")

        stream_id, out = self.h2.send_request(request, self.authority)
        state = StreamState(asyncio.get_running_loop(), self.handler.config.max_body_size)
        self.streams[stream_id] = state

        if out:
            self.transport.write(out)

        def on_done():
            self.streams.pop(stream_id, None)

        try:
            return await consume_response(state, streaming, "HTTP/2.0", self.handler.config.read_timeout, on_done)
        except BaseException:
            self.streams.pop(stream_id, None)
            raise

    async def h2_websocket_read(self, stream_id: int, ws: WebSocket):
        if self.h2 is None:
            return
        queue = self.h2.websocket_streams.get(stream_id)
        if queue is None:
            return

        buf = bytearray()
        while True:
            chunk = await queue.get()
            if chunk is None:
                ws.queue.put_nowait(None)
                break

            buf.extend(chunk)

            try:
                frames = parse_frames(buf, self.handler.config.max_websocket_message_size)
            except WebSocketProtocolError:
                ws.close_transport(1002)
                break
            except ValueError:
                ws.close_transport(1009)
                break

            for frame in frames:
                ws.feed_frame(frame)

    async def websocket(self, request: Request, subprotocols: list[str] | None) -> WebSocket:
        if self.h2 is None or self.transport is None:
            raise ConnectionError("connection is not available")

        await asyncio.wait_for(self.h2_settings.wait(), self.handler.config.read_timeout)

        stream_id, out = self.h2.send_connect_websocket(request, self.authority, subprotocols)
        state = StreamState(asyncio.get_running_loop(), self.handler.config.max_body_size)
        self.streams[stream_id] = state

        if out:
            self.transport.write(out)

        try:
            status, headers = await asyncio.wait_for(state.header_future, self.handler.config.read_timeout)
        finally:
            self.streams.pop(stream_id, None)

        if status != 200:
            self.h2.discard_send(stream_id)
            raise ConnectionError(f"websocket upgrade rejected with status {status}")

        subprotocol = (headers.get("Sec-WebSocket-Protocol") or "").strip() or None
        ws = WebSocket(H2ClientWSTransport(self, stream_id), require_masking=False, mask_frames=True, subprotocol=subprotocol, max_message_size=self.handler.config.max_websocket_message_size)

        self.handler.create_task(self.h2_websocket_read(stream_id, ws))
        return ws

class H2ClientWSTransport:
    def __init__(self, conn: TCPClientProtocol, stream_id: int):
        self.conn = conn
        self.stream_id = stream_id

    def write(self, data: bytes):
        if self.conn.h2 is None or self.conn.transport is None:
            return
        out = self.conn.h2.send_body_chunk(self.stream_id, data, end_stream=False)
        if out:
            self.conn.transport.write(out)

    def close(self):
        if self.conn.h2 is None or self.conn.transport is None:
            return
        out = self.conn.h2.websocket_close(self.stream_id)
        if out:
            self.conn.transport.write(out)

class WSClientProtocol(asyncio.Protocol):
    def __init__(self, loop: asyncio.AbstractEventLoop, max_message_size: int, tls_context: TLSContext | None = None, server_name: str | None = None):
        self.transport: asyncio.Transport | TLSTransport | None = None
        self.raw_transport: asyncio.Transport | None = None
        self.tls_context = tls_context
        self.server_name = server_name
        self.tls_engine: RecordTLS | None = None
        self.tls_ready = False
        self.ready: asyncio.Future = loop.create_future()
        self.buffer = bytearray()
        self.handshake: asyncio.Future = loop.create_future()
        self.ws: WebSocket | None = None
        self.max_message_size = max_message_size

    def connection_made(self, transport: asyncio.BaseTransport):
        self.raw_transport = transport

        if self.tls_context is not None:
            self.tls_engine = self.tls_context.connection(self.server_name)
            self.transport = TLSTransport(transport, self.tls_engine)
            try:
                tls_start(self.tls_engine, transport)
            except Exception as exc:
                if not self.ready.done():
                    self.ready.set_exception(exc)
                transport.close()
            return

        self.transport = transport
        if not self.ready.done():
            self.ready.set_result(None)

    def data_received(self, data: bytes):
        if self.tls_engine is None:
            self.feed_decrypted(data)
            return

        engine = self.tls_engine
        try:
            became_ready, plaintext = tls_feed(engine, self.raw_transport, data)
        except Exception as exc:
            if not self.ready.done():
                self.ready.set_exception(exc)
            elif not self.handshake.done():
                self.handshake.set_exception(exc)
            if self.transport is not None:
                self.transport.close()
            return

        if became_ready and not self.ready.done():
            self.tls_ready = True
            self.ready.set_result(None)

        if plaintext:
            self.feed_decrypted(plaintext)

        if engine.closed and self.transport is not None and not self.transport.is_closing():
            self.transport.close()

    def feed_decrypted(self, data: bytes):
        if self.ws is None:
            self.buffer.extend(data)
            idx = self.buffer.find(b"\r\n\r\n")
            if idx == -1:
                if len(self.buffer) > MAX_RESPONSE_HEADER_SIZE and not self.handshake.done():
                    self.handshake.set_exception(ValueError("websocket handshake header too large"))
                return
            head = bytes(self.buffer[:idx])
            del self.buffer[:idx + 4]
            if not self.handshake.done():
                self.handshake.set_result(head)
            return

        self.buffer.extend(data)
        try:
            frames = parse_frames(self.buffer, self.max_message_size)
        except WebSocketProtocolError:
            self.ws.close_transport(1002)
            return
        except ValueError:
            self.ws.close_transport(1009)
            return
        for frame in frames:
            self.ws.feed_frame(frame)

    def activate(self, ws: WebSocket):
        self.ws = ws
        if self.buffer:
            try:
                frames = parse_frames(self.buffer, self.max_message_size)
            except WebSocketProtocolError:
                ws.close_transport(1002)
                return
            except ValueError:
                ws.close_transport(1009)
                return
            for frame in frames:
                ws.feed_frame(frame)

    def connection_lost(self, exc: BaseException | None):
        if not self.handshake.done():
            self.handshake.set_exception(exc or ConnectionError("connection closed during websocket handshake"))
        if self.ws is not None and not self.ws.closed:
            self.ws.queue.put_nowait(None)
