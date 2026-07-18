import struct

import pytest

from kaede.tcp import TCPPort
from kaede.http.models import HTTPPort
from kaede.http.errors import WebSocketError
from kaede.http.websocket import WSFrame, WSConnection, Opcode
from kaede.http.api.server import HTTPServer, HTTPServerConfig, HTTPHandler
from kaede.http.api.client import HTTPClient, HTTPClientConfig

LOCAL = "127.0.0.1"

class TestHandshake:
    def test_the_accept_key_matches_the_rfc(self):
        # RFC 6455 section 1.3.
        assert WSFrame.accept("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

class TestFrames:
    def test_a_short_unmasked_frame(self):
        frame = WSFrame.build(Opcode.TEXT, b"Hello")

        assert frame == b"\x81\x05Hello"

    def test_a_masked_frame_unmasks_to_the_payload(self):
        frame = WSFrame.build(Opcode.BINARY, b"payload", mask=True)

        assert frame[0] == 0x82
        assert frame[1] & 0x80 # the mask bit
        key = frame[2:6]
        unmasked = bytes(byte ^ key[index % 4] for index, byte in enumerate(frame[6:]))
        assert unmasked == b"payload"

    def test_length_boundaries(self):
        assert WSFrame.build(Opcode.BINARY, b"x" * 125)[1] & 0x7F == 125
        assert WSFrame.build(Opcode.BINARY, b"x" * 126)[1] & 0x7F == 126 # 16-bit length follows
        assert WSFrame.build(Opcode.BINARY, b"x" * 70000)[1] & 0x7F == 127 # 64-bit length follows

class Stream:
    """An in-memory duplex pair standing in for a transport, so the frame codec
    can be exercised without a socket."""

    def __init__(self):
        self.inbound = bytearray()
        self.sent = bytearray()
        self.closed = False

    def load(self, data: bytes):
        self.inbound += data

    async def receive_exactly(self, n: int) -> bytes:
        if len(self.inbound) < n:
            from kaede.tcp.errors import TCPClosedError
            raise TCPClosedError("out of data")

        data = bytes(self.inbound[:n])
        del self.inbound[:n]
        return data

    async def send(self, data: bytes):
        self.sent += data

    async def close(self, half_close: bool = False):
        self.closed = True

class TestReading:
    async def test_a_masked_text_message_is_read(self):
        stream = Stream()
        stream.load(WSFrame.build(Opcode.TEXT, "hello".encode(), mask=True))

        ws = WSConnection(("", None), ("", None), transport=stream, server=True)
        assert await ws.read() == "hello"

    async def test_a_fragmented_message_reassembles(self):
        stream = Stream()
        stream.load(WSFrame.build(Opcode.TEXT, b"Hel", fin=False, mask=True))
        stream.load(WSFrame.build(Opcode.CONTINUATION, b"lo", fin=True, mask=True))

        ws = WSConnection(("", None), ("", None), transport=stream, server=True)
        assert await ws.read() == "Hello"

    async def test_a_ping_is_answered_with_a_pong(self):
        stream = Stream()
        stream.load(WSFrame.build(Opcode.PING, b"ka", mask=True))
        stream.load(WSFrame.build(Opcode.TEXT, b"hi", mask=True))

        ws = WSConnection(("", None), ("", None), transport=stream, server=True)
        assert await ws.read() == "hi"

        fin, opcode, payload, masked = await WSFrame.read(Streamed(stream.sent), limit=1000)
        assert opcode == Opcode.PONG and payload == b"ka"

    async def test_a_close_frame_ends_the_stream(self):
        stream = Stream()
        stream.load(WSFrame.build(Opcode.CLOSE, struct.pack(">H", 1000), mask=True))

        ws = WSConnection(("", None), ("", None), transport=stream, server=True)
        assert await ws.read() is None

    async def test_an_unmasked_client_frame_is_rejected(self):
        # RFC 6455 section 5.1.
        stream = Stream()
        stream.load(WSFrame.build(Opcode.TEXT, b"hi", mask=False))

        ws = WSConnection(("", None), ("", None), transport=stream, server=True)

        with pytest.raises(WebSocketError):
            await ws.read()

    async def test_an_oversized_control_frame_is_rejected(self):
        stream = Stream()
        # Hand-build a masked PING claiming 126 bytes (control frames cap at 125).
        stream.load(b"\x89\xfe" + struct.pack(">H", 126) + b"\x00\x00\x00\x00" + b"x" * 126)

        ws = WSConnection(("", None), ("", None), transport=stream, server=True)

        with pytest.raises(WebSocketError):
            await ws.read()

    async def test_invalid_utf8_text_is_rejected(self):
        stream = Stream()
        stream.load(WSFrame.build(Opcode.TEXT, b"\xff\xfe", mask=True))

        ws = WSConnection(("", None), ("", None), transport=stream, server=True)

        with pytest.raises(WebSocketError):
            await ws.read()

class Streamed:
    """A read-only view of an already-serialized byte string."""

    def __init__(self, data: bytes):
        self.data = bytearray(data)

    async def receive_exactly(self, n: int) -> bytes:
        data = bytes(self.data[:n])
        del self.data[:n]
        return data

class TestLoopback:
    async def test_echo_over_a_real_connection(self):
        class WS(HTTPHandler):
            async def on_websocket(self, ws):
                while True:
                    message = await ws.read()

                    if message is None:
                        break

                    await ws.write(("echo:" + message) if isinstance(message, str) else (b"echo:" + message))

        server = HTTPServer(config=HTTPServerConfig(versions=["HTTP/1.1"]))
        await server.listen(WS(), [(LOCAL, HTTPPort("tcp", TCPPort(0)))])
        host, port = server.ports[0]

        try:
            async with HTTPClient(config=HTTPClientConfig(versions=["HTTP/1.1"])) as client:
                ws = await client.websocket(f"ws://{LOCAL}:{int(port.value)}/chat")

                await ws.write("hello")
                assert await ws.read() == "echo:hello"

                await ws.write(b"bytes")
                assert await ws.read() == b"echo:bytes"

                await ws.close(1000)

        finally:
            await server.close(timeout=2)

    async def test_a_missing_version_is_refused(self):
        import asyncio

        server = HTTPServer(config=HTTPServerConfig(versions=["HTTP/1.1"]))
        await server.listen(HTTPHandler(), [(LOCAL, HTTPPort("tcp", TCPPort(0)))])
        host, port = server.ports[0]

        try:
            reader, writer = await asyncio.open_connection(LOCAL, int(port.value))
            writer.write(b"GET /chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: abc\r\n\r\n")
            await writer.drain()

            reply = await asyncio.wait_for(reader.read(200), 2)
            assert reply.startswith(b"HTTP/1.1 426")

            writer.close()
            await writer.wait_closed()

        finally:
            await server.close(timeout=2)
