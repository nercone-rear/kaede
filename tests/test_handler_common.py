import asyncio
import ipaddress
import pytest

from kaede.handler.common import (
    parse_peername,
    negotiate_websocket,
    StreamState,
    dispatch_event,
    consume_response,
    MAX_RESPONSE_HEADER_SIZE,
)
from kaede.models import Request, Response, Headers
from kaede.websocket import PerMessageDeflate


class MockTransport:
    def __init__(self, peername=None):
        self._peername = peername

    def get_extra_info(self, key, default=None):
        if key == "peername":
            return self._peername
        return default


class TestParsePeername:
    def test_ipv4(self):
        transport = MockTransport(("127.0.0.1", 12345))
        addr, port = parse_peername(transport)
        assert addr == ipaddress.IPv4Address("127.0.0.1")
        assert port == 12345

    def test_ipv6(self):
        transport = MockTransport(("::1", 8080, 0, 0))
        addr, port = parse_peername(transport)
        assert addr == ipaddress.IPv6Address("::1")
        assert port == 8080

    def test_no_peer_returns_default(self):
        transport = MockTransport(None)
        addr, port = parse_peername(transport)
        assert addr == ipaddress.IPv4Address("0.0.0.0")
        assert port == 0

    def test_empty_peer_returns_default(self):
        transport = MockTransport(())
        addr, port = parse_peername(transport)
        assert addr == ipaddress.IPv4Address("0.0.0.0")
        assert port == 0

    def test_invalid_ip_falls_back_to_default(self):
        transport = MockTransport(("not-an-ip", 80))
        addr, port = parse_peername(transport)
        assert addr == ipaddress.IPv4Address("0.0.0.0")
        assert port == 80


class TestNegotiateWebSocket:
    def _make_request(self, **header_kv):
        h = Headers({})
        for k, v in header_kv.items():
            h.set(k, v)
        return Request(method="GET", target="/ws", headers=h)

    def test_no_offered_subprotocol(self):
        req = self._make_request()
        subprotocol, deflate = negotiate_websocket(req, ["chat"])
        assert subprotocol is None

    def test_matching_subprotocol(self):
        req = self._make_request(**{"Sec-WebSocket-Protocol": "chat"})
        subprotocol, deflate = negotiate_websocket(req, ["chat", "echo"])
        assert subprotocol == "chat"

    def test_first_matching_subprotocol_wins(self):
        req = self._make_request(**{"Sec-WebSocket-Protocol": "echo, chat"})
        subprotocol, deflate = negotiate_websocket(req, ["chat", "echo"])
        assert subprotocol == "echo"

    def test_no_match_returns_none(self):
        req = self._make_request(**{"Sec-WebSocket-Protocol": "unknown"})
        subprotocol, deflate = negotiate_websocket(req, ["chat"])
        assert subprotocol is None

    def test_no_extension_returns_none_deflate(self):
        req = self._make_request()
        _, deflate = negotiate_websocket(req, [])
        assert deflate is None

    def test_permessage_deflate_extension(self):
        req = self._make_request(**{"Sec-WebSocket-Extensions": "permessage-deflate"})
        _, deflate = negotiate_websocket(req, [])
        assert isinstance(deflate, PerMessageDeflate)

    def test_unrecognized_extension_returns_none(self):
        req = self._make_request(**{"Sec-WebSocket-Extensions": "x-unknown-ext"})
        _, deflate = negotiate_websocket(req, [])
        assert deflate is None

    def test_empty_server_subprotocols_list(self):
        req = self._make_request(**{"Sec-WebSocket-Protocol": "chat"})
        subprotocol, _ = negotiate_websocket(req, [])
        assert subprotocol is None


class TestStreamState:
    def _state(self, max_body_size=None):
        loop = asyncio.get_running_loop()
        return StreamState(loop, max_body_size)

    async def test_set_headers_resolves_future(self):
        state = self._state()
        headers = Headers({})
        state.set_headers(200, headers)
        status, h = await state.header_future
        assert status == 200

    async def test_set_headers_idempotent(self):
        state = self._state()
        state.set_headers(200, Headers({}))
        state.set_headers(404, Headers({}))  # second call should be no-op
        status, _ = await state.header_future
        assert status == 200

    async def test_push_adds_to_queue(self):
        state = self._state()
        state.push(b"hello")
        assert not state.queue.empty()

    async def test_push_exceeds_max_body_size_fails(self):
        state = self._state(max_body_size=10)
        state.set_headers(200, Headers({}))
        state.push(b"x" * 11)
        assert state.failed is not None

    async def test_finish_marks_ended(self):
        state = self._state()
        state.set_headers(200, Headers({}))
        state.finish()
        assert state.ended

    async def test_finish_without_headers_raises_connection_error(self):
        state = self._state()
        state.finish()
        with pytest.raises((ConnectionError, asyncio.CancelledError)):
            await asyncio.wait_for(state.header_future, timeout=0.1)

    async def test_finish_enqueues_none(self):
        state = self._state()
        state.set_headers(200, Headers({}))
        state.finish()
        sentinel = state.queue.get_nowait()
        assert sentinel is None

    async def test_fail_sets_exception_on_future(self):
        state = self._state()
        exc = ValueError("test error")
        state.fail(exc)
        assert state.header_future.exception() is exc

    async def test_fail_enqueues_none(self):
        state = self._state()
        state.fail(ValueError("err"))
        sentinel = state.queue.get_nowait()
        assert sentinel is None

    async def test_fail_idempotent(self):
        state = self._state()
        exc1 = ValueError("first")
        exc2 = ValueError("second")
        state.fail(exc1)
        state.fail(exc2)
        assert state.failed is exc1

    async def test_max_body_size_tracks_cumulative_size(self):
        state = self._state(max_body_size=20)
        state.set_headers(200, Headers({}))
        state.push(b"x" * 10)  # 10 bytes, within limit
        assert state.failed is None
        state.push(b"y" * 11)  # 10+11=21 bytes, exceeds limit
        assert state.failed is not None


class TestDispatchEvent:
    def _state(self):
        loop = asyncio.get_running_loop()
        return StreamState(loop, None)

    async def test_response_event_calls_set_headers(self):
        state = self._state()
        streams = {1: state}
        h = Headers({})
        dispatch_event(streams, ("response", 1, 200, h))
        assert state.header_future.done()
        assert state.header_future.result()[0] == 200

    async def test_data_event_pushes_chunk(self):
        state = self._state()
        state.set_headers(200, Headers({}))
        streams = {1: state}
        dispatch_event(streams, ("data", 1, b"hello"))
        assert not state.queue.empty()

    async def test_end_event_calls_finish(self):
        state = self._state()
        state.set_headers(200, Headers({}))
        streams = {1: state}
        dispatch_event(streams, ("end", 1))
        assert state.ended

    async def test_reset_event_calls_fail(self):
        state = self._state()
        streams = {1: state}
        dispatch_event(streams, ("reset", 1))
        assert state.failed is not None

    async def test_close_event_fails_all_streams(self):
        s1 = self._state()
        s2 = self._state()
        streams = {1: s1, 2: s2}
        dispatch_event(streams, ("close", 0))
        assert s1.failed is not None
        assert s2.failed is not None

    async def test_unknown_stream_id_ignored(self):
        streams = {}
        dispatch_event(streams, ("response", 99, 200, Headers({})))
        # Should not raise

    async def test_response_event_sets_headers_object(self):
        state = self._state()
        streams = {5: state}
        h = Headers({"x-test": "val"})
        dispatch_event(streams, ("response", 5, 201, h))
        _, headers = state.header_future.result()
        assert headers.get("x-test") == "val"


class TestConsumeResponse:
    def _state_with_response(self, chunks, status=200, max_body_size=None):
        loop = asyncio.get_running_loop()
        state = StreamState(loop, max_body_size)
        state.set_headers(status, Headers({"content-type": "text/plain"}))
        for chunk in chunks:
            state.push(chunk)
        state.finish()
        return state

    async def test_non_streaming_assembles_body(self):
        state = self._state_with_response([b"hello", b" world"])
        called = []
        resp = await consume_response(state, False, "HTTP/1.1", 5.0, lambda: called.append(True))
        assert resp.body == b"hello world"
        assert resp.status_code == 200
        assert called

    async def test_non_streaming_on_done_called(self):
        state = self._state_with_response([b"data"])
        done = []
        await consume_response(state, False, "HTTP/1.1", 5.0, lambda: done.append(True))
        assert done == [True]

    async def test_non_streaming_protocol_propagated(self):
        state = self._state_with_response([b"x"])
        resp = await consume_response(state, False, "HTTP/2.0", 5.0, lambda: None)
        assert resp.protocol == "HTTP/2.0"

    async def test_non_streaming_empty_body_is_none(self):
        state = self._state_with_response([])
        resp = await consume_response(state, False, "HTTP/1.1", 5.0, lambda: None)
        assert resp.body is None

    async def test_streaming_returns_async_iterator(self):
        state = self._state_with_response([b"chunk1", b"chunk2"])
        resp = await consume_response(state, True, "HTTP/1.1", 5.0, lambda: None)
        assert resp.is_streaming
        chunks = []
        async for chunk in resp.body:
            chunks.append(chunk)
        assert b"".join(chunks) == b"chunk1chunk2"

    async def test_streaming_on_done_called_after_iteration(self):
        state = self._state_with_response([b"x"])
        done = []
        resp = await consume_response(state, True, "HTTP/1.1", 5.0, lambda: done.append(True))
        assert not done  # not called yet
        async for _ in resp.body:
            pass
        assert done == [True]

    async def test_failed_state_raises_after_non_streaming_read(self):
        loop = asyncio.get_running_loop()
        state = StreamState(loop, None)
        state.set_headers(200, Headers({}))
        state.fail(ConnectionError("stream failed"))
        with pytest.raises(ConnectionError):
            await consume_response(state, False, "HTTP/1.1", 5.0, lambda: None)

    async def test_status_propagated(self):
        state = self._state_with_response([], status=404)
        resp = await consume_response(state, False, "HTTP/1.1", 5.0, lambda: None)
        assert resp.status_code == 404
