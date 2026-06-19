from __future__ import annotations

import asyncio
import ipaddress
from typing import AsyncIterator

from ..http.models import Request, Response, Headers
from ..websocket import PerMessageDeflate

MAX_RESPONSE_HEADER_SIZE = 64 * 1024

def parse_peername(transport: asyncio.BaseTransport) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    peer = transport.get_extra_info("peername")
    if not peer:
        return (ipaddress.IPv4Address("0.0.0.0"), 0)
    host, port = peer[0], peer[1]
    try:
        return (ipaddress.ip_address(host), int(port))
    except ValueError:
        return (ipaddress.IPv4Address("0.0.0.0"), int(port))

def negotiate_websocket(request: Request, subprotocols: list[str]) -> tuple[str | None, PerMessageDeflate | None]:
    offered_raw = request.headers.get("Sec-WebSocket-Protocol") or ""
    offered_str = offered_raw if isinstance(offered_raw, str) else (offered_raw[0] if offered_raw else "")
    offered = [p.strip() for p in offered_str.split(",") if p.strip()] if offered_str else []
    subprotocol: str | None = next((subprotocol for subprotocol in offered if subprotocol in subprotocols), None)

    ext_raw = request.headers.get("Sec-WebSocket-Extensions") or ""
    ext_str = ext_raw if isinstance(ext_raw, str) else (ext_raw[0] if ext_raw else "")
    deflate = PerMessageDeflate.from_client_offer(ext_str) if ext_str else None

    return subprotocol, deflate

class StreamState:
    def __init__(self, loop: asyncio.AbstractEventLoop, max_body_size: int | None):
        self.loop = loop
        self.max_body_size = max_body_size
        self.header_future: asyncio.Future = loop.create_future()
        self.queue: asyncio.Queue[bytes | None] = asyncio.Queue()
        self.size = 0
        self.failed: BaseException | None = None
        self.ended = False

    def set_headers(self, status: int, headers: Headers):
        if not self.header_future.done():
            self.header_future.set_result((status, headers))

    def push(self, chunk: bytes):
        if self.failed is not None:
            return
        self.size += len(chunk)
        if self.max_body_size is not None and self.size > self.max_body_size:
            self.fail(ValueError("response body exceeds max_body_size"))
            return
        self.queue.put_nowait(chunk)

    def finish(self):
        if self.ended:
            return
        self.ended = True
        if not self.header_future.done():
            self.header_future.set_exception(ConnectionError("connection closed before response headers"))
        self.queue.put_nowait(None)

    def fail(self, exc: BaseException):
        if self.failed is not None:
            return
        self.failed = exc
        if not self.header_future.done():
            self.header_future.set_exception(exc)
        self.queue.put_nowait(None)

def dispatch_event(streams: dict[int, StreamState], event: tuple):
    kind = event[0]

    if kind == "response":
        _, stream_id, status, headers = event
        state = streams.get(stream_id)
        if state is not None:
            state.set_headers(status, headers)

    elif kind == "data":
        _, stream_id, chunk = event
        state = streams.get(stream_id)
        if state is not None:
            state.push(chunk)

    elif kind == "end":
        _, stream_id = event
        state = streams.get(stream_id)
        if state is not None:
            state.finish()

    elif kind == "reset":
        _, stream_id = event
        state = streams.get(stream_id)
        if state is not None:
            state.fail(ConnectionError("stream reset by peer"))

    elif kind == "close":
        for state in list(streams.values()):
            state.fail(ConnectionError("connection closed by peer"))

async def consume_response(state: StreamState, streaming: bool, protocol: str, read_timeout: float, on_done) -> Response:
    status, headers = await asyncio.wait_for(state.header_future, read_timeout)

    if streaming:
        async def body_iter() -> AsyncIterator[bytes]:
            try:
                while True:
                    chunk = await state.queue.get()
                    if chunk is None:
                        break
                    yield chunk
                if state.failed is not None:
                    raise state.failed
            finally:
                on_done()

        return Response(body=body_iter(), status_code=status, headers=headers, protocol=protocol)

    body = bytearray()
    while True:
        chunk = await asyncio.wait_for(state.queue.get(), read_timeout)
        if chunk is None:
            break
        body.extend(chunk)

    if state.failed is not None:
        on_done()
        raise state.failed

    on_done()

    return Response(body=bytes(body), status_code=status, headers=headers, protocol=protocol)
