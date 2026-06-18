import socket
import struct
import pytest

from kaede.models import Listener, Callback, Request, Response
from kaede.http.h2 import H2Info, H2WSUpgrade
from kaede.http.h3 import H3Info, H3WSUpgrade
from kaede.websocket import WebSocket, Opcode, parse_frames, build_frame


class MockTransport:
    def __init__(self):
        self.written: list[bytes] = []
        self.closed_called = False

    def write(self, data: bytes):
        self.written.append(data)

    def close(self):
        self.closed_called = True


class TestListener:
    def test_kind_http(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener = Listener(sock=sock, kind="http")
            assert listener.kind == "http"
        finally:
            sock.close()

    def test_kind_https(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener = Listener(sock=sock, kind="https")
            assert listener.kind == "https"
        finally:
            sock.close()

    def test_kind_quic(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            listener = Listener(sock=sock, kind="quic")
            assert listener.kind == "quic"
        finally:
            sock.close()

    def test_kind_unix(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener = Listener(sock=sock, kind="unix")
            assert listener.kind == "unix"
        finally:
            sock.close()

    def test_sock_field(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener = Listener(sock=sock, kind="http")
            assert listener.sock is sock
        finally:
            sock.close()


class TestCallback:
    def test_websocket_subprotocols_default_empty(self):
        cb = Callback()
        assert cb.websocket_subprotocols == []

    async def test_on_request_returns_response(self):
        cb = Callback()
        req = Request(method="GET", target="/")
        resp = await cb.on_request(req)
        assert isinstance(resp, Response)

    async def test_on_request_body_contains_hello_world(self):
        cb = Callback()
        req = Request(method="GET", target="/")
        resp = await cb.on_request(req)
        assert resp.body is not None
        assert b"Hello, World!" in resp.body

    async def test_on_request_content_type_text(self):
        cb = Callback()
        req = Request(method="GET", target="/")
        resp = await cb.on_request(req)
        assert resp.content_type == "text/plain"

    async def test_on_websocket_closes_with_1008(self):
        cb = Callback()
        req = Request(method="GET", target="/ws")
        transport = MockTransport()
        ws = WebSocket(transport, require_masking=False)
        await cb.on_websocket(req, ws)
        assert ws.closed is True
        assert len(transport.written) > 0
        frames = parse_frames(bytearray(transport.written[0]))
        assert len(frames) > 0
        assert frames[0].opcode == Opcode.CLOSE
        code = struct.unpack(">H", frames[0].payload[:2])[0]
        assert code == 1008

    async def test_on_websocket_wrote_close_frame(self):
        cb = Callback()
        req = Request(method="GET", target="/ws")
        transport = MockTransport()
        ws = WebSocket(transport, require_masking=False)
        await cb.on_websocket(req, ws)
        assert len(transport.written) > 0

    async def test_on_websocket_enqueues_none(self):
        cb = Callback()
        req = Request(method="GET", target="/ws")
        transport = MockTransport()
        ws = WebSocket(transport, require_masking=False)
        await cb.on_websocket(req, ws)
        sentinel = ws.queue.get_nowait()
        assert sentinel is None


class TestH2Info:
    def test_connection_id_field(self):
        info = H2Info(connection_id=b"\x01\x02\x03\x04", stream_id=1)
        assert info.connection_id == b"\x01\x02\x03\x04"

    def test_stream_id_field(self):
        info = H2Info(connection_id=b"", stream_id=5)
        assert info.stream_id == 5

    def test_random_connection_id(self):
        import os
        cid = os.urandom(8)
        info = H2Info(connection_id=cid, stream_id=3)
        assert info.connection_id == cid

    def test_stream_id_zero(self):
        info = H2Info(connection_id=b"", stream_id=0)
        assert info.stream_id == 0


class TestH2WSUpgrade:
    def test_stream_id_field(self):
        req = Request(method="GET", target="/ws")
        upgrade = H2WSUpgrade(stream_id=7, request=req)
        assert upgrade.stream_id == 7

    def test_request_field(self):
        req = Request(method="GET", target="/ws")
        upgrade = H2WSUpgrade(stream_id=7, request=req)
        assert upgrade.request is req

    def test_stream_id_various(self):
        req = Request(method="GET", target="/ws")
        for sid in (1, 3, 5, 100):
            upgrade = H2WSUpgrade(stream_id=sid, request=req)
            assert upgrade.stream_id == sid


class TestH3Info:
    def test_connection_id_field(self):
        info = H3Info(connection_id=b"\xAB\xCD", stream_id=1)
        assert info.connection_id == b"\xAB\xCD"

    def test_stream_id_field(self):
        info = H3Info(connection_id=b"", stream_id=4)
        assert info.stream_id == 4

    def test_empty_connection_id(self):
        info = H3Info(connection_id=b"", stream_id=0)
        assert info.connection_id == b""


class TestH3WSUpgrade:
    def test_stream_id_field(self):
        req = Request(method="GET", target="/ws")
        upgrade = H3WSUpgrade(stream_id=9, request=req)
        assert upgrade.stream_id == 9

    def test_request_field(self):
        req = Request(method="GET", target="/ws")
        upgrade = H3WSUpgrade(stream_id=9, request=req)
        assert upgrade.request is req
