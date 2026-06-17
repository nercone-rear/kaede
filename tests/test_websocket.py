import struct
import pytest
from kaede.websocket import Opcode, build_frame, parse_frames, compute_accept, check_accept, generate_key, PerMessageDeflate, WebSocket, WebSocketProtocolError

class TestAccept:
    def test_compute_accept_rfc_example(self):
        result = compute_accept("dGhlIHNhbXBsZSBub25jZQ==")
        assert result == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

    def test_check_accept_valid(self):
        key = "dGhlIHNhbXBsZSBub25jZQ=="
        accept = compute_accept(key)
        assert check_accept(key, accept) is True

    def test_check_accept_wrong(self):
        assert check_accept("key1", compute_accept("key2")) is False

    def test_check_accept_strips_whitespace(self):
        key = "dGhlIHNhbXBsZSBub25jZQ=="
        accept = "  " + compute_accept(key) + "  "
        assert check_accept(key, accept) is True

    def test_generate_key_is_base64(self):
        import base64
        key = generate_key()
        decoded = base64.b64decode(key)
        assert len(decoded) == 16

class TestBuildFrame:
    def test_text_frame_small(self):
        frame = build_frame(Opcode.TEXT, b"hello")
        assert frame[0] == 0x81
        assert frame[1] == 5
        assert frame[2:] == b"hello"

    def test_binary_frame(self):
        frame = build_frame(Opcode.BINARY, b"\x00\x01\x02")
        assert frame[0] == 0x82

    def test_close_frame(self):
        payload = struct.pack(">H", 1000)
        frame = build_frame(Opcode.CLOSE, payload)
        assert frame[0] == 0x88

    def test_ping_frame(self):
        frame = build_frame(Opcode.PING, b"ping")
        assert frame[0] == 0x89

    def test_pong_frame(self):
        frame = build_frame(Opcode.PONG, b"pong")
        assert frame[0] == 0x8A

    def test_medium_payload_length(self):
        payload = b"x" * 126
        frame = build_frame(Opcode.BINARY, payload)
        assert frame[1] == 126
        length = struct.unpack_from(">H", frame, 2)[0]
        assert length == 126

    def test_large_payload_length(self):
        payload = b"x" * 65536
        frame = build_frame(Opcode.BINARY, payload)
        assert frame[1] == 127
        length = struct.unpack_from(">Q", frame, 2)[0]
        assert length == 65536

    def test_masked_frame(self):
        frame = build_frame(Opcode.TEXT, b"hello", mask=True)
        assert frame[1] & 0x80
        assert len(frame) == 2 + 4 + 5

    def test_non_fin_frame(self):
        frame = build_frame(Opcode.TEXT, b"frag", fin=False)
        assert not (frame[0] & 0x80)

    def test_rsv1_frame(self):
        frame = build_frame(Opcode.TEXT, b"compressed", rsv1=True)
        assert frame[0] & 0x40

class TestParseFrames:
    def test_single_text_frame(self):
        buf = bytearray(build_frame(Opcode.TEXT, b"hello"))
        frames = parse_frames(buf)
        assert len(frames) == 1
        assert frames[0].opcode == Opcode.TEXT
        assert frames[0].payload == b"hello"
        assert frames[0].fin is True

    def test_multiple_frames(self):
        data = bytearray(build_frame(Opcode.TEXT, b"first") + build_frame(Opcode.BINARY, b"second"))
        frames = parse_frames(data)
        assert len(frames) == 2
        assert frames[0].payload == b"first"
        assert frames[1].payload == b"second"

    def test_masked_frame_decoded(self):
        buf = bytearray(build_frame(Opcode.TEXT, b"hello", mask=True))
        frames = parse_frames(buf)
        assert frames[0].payload == b"hello"
        assert frames[0].masked is True

    def test_incomplete_frame_returns_empty(self):
        buf = bytearray(b"\x81")
        frames = parse_frames(buf)
        assert frames == []

    def test_medium_length_frame(self):
        payload = b"x" * 200
        buf = bytearray(build_frame(Opcode.BINARY, payload))
        frames = parse_frames(buf)
        assert frames[0].payload == payload

    def test_large_length_frame(self):
        payload = b"x" * 70000
        buf = bytearray(build_frame(Opcode.BINARY, payload))
        frames = parse_frames(buf)
        assert frames[0].payload == payload

    def test_unknown_opcode_raises(self):
        buf = bytearray(b"\x83\x00")
        with pytest.raises(WebSocketProtocolError, match="unknown websocket opcode"):
            parse_frames(buf)

    def test_max_payload_exceeded(self):
        payload = b"x" * 200
        buf = bytearray(build_frame(Opcode.TEXT, payload))
        with pytest.raises(ValueError, match="max message size"):
            parse_frames(buf, max_payload_size=100)

    def test_buffer_consumed_after_parse(self):
        buf = bytearray(build_frame(Opcode.TEXT, b"hi"))
        parse_frames(buf)
        assert len(buf) == 0

class TestPerMessageDeflate:
    def test_compress_decompress_roundtrip(self):
        pmd = PerMessageDeflate()
        original = b"hello world hello world hello world"
        compressed = pmd.compress(original)
        decompressed = pmd.decompress(compressed)
        assert decompressed == original

    def test_compressed_smaller_than_original(self):
        pmd = PerMessageDeflate()
        data = b"aaaa" * 1000
        assert len(pmd.compress(data)) < len(data)

    def test_response_header_format(self):
        pmd = PerMessageDeflate(server_no_context_takeover=True, client_no_context_takeover=False)
        header = pmd.response_header()
        assert header.startswith("permessage-deflate")
        assert "server_no_context_takeover" in header

    def test_max_size_exceeded(self):
        pmd = PerMessageDeflate(client_no_context_takeover=True)
        data = b"x" * 10000
        compressed = pmd.compress(data)
        with pytest.raises(ValueError, match="max message size"):
            pmd.decompress(compressed, max_size=100)

    def test_from_client_offer_basic(self):
        pmd = PerMessageDeflate.from_client_offer("permessage-deflate")
        assert pmd is not None

    def test_from_client_offer_with_params(self):
        pmd = PerMessageDeflate.from_client_offer("permessage-deflate; client_no_context_takeover; server_max_window_bits=12")
        assert pmd is not None
        assert pmd.client_no_context_takeover is True
        assert pmd.server_max_window_bits == 12

    def test_from_client_offer_no_match(self):
        pmd = PerMessageDeflate.from_client_offer("identity")
        assert pmd is None

    def test_window_bits_clamped(self):
        pmd = PerMessageDeflate.from_client_offer("permessage-deflate; server_max_window_bits=99")
        assert pmd.server_max_window_bits == 15

class MockTransport:
    def __init__(self):
        self.written: list[bytes] = []
        self.closed_called = False

    def write(self, data: bytes):
        self.written.append(data)

    def close(self):
        self.closed_called = True

class TestWebSocket:
    def _make_ws(self, **kwargs):
        transport = MockTransport()
        ws = WebSocket(transport, **kwargs)
        return ws, transport

    def test_feed_text_message(self):
        ws, _ = self._make_ws(require_masking=False)
        frame = build_frame(Opcode.TEXT, b"hello", mask=False)
        ws.feed_frame(parse_frames(bytearray(frame))[0])
        msg = ws.queue.get_nowait()
        assert msg == b"hello"

    def test_feed_binary_message(self):
        ws, _ = self._make_ws(require_masking=False)
        frame = build_frame(Opcode.BINARY, b"\x01\x02\x03", mask=False)
        ws.feed_frame(parse_frames(bytearray(frame))[0])
        msg = ws.queue.get_nowait()
        assert msg == b"\x01\x02\x03"

    def test_unmasked_when_masking_required(self):
        ws, transport = self._make_ws(require_masking=True)
        frame = build_frame(Opcode.TEXT, b"hello", mask=False)
        ws.feed_frame(parse_frames(bytearray(frame))[0])
        assert ws.closed is True
        assert transport.closed_called is True
        assert transport.written

    def test_ping_sends_pong(self):
        ws, transport = self._make_ws(require_masking=False)
        frame = build_frame(Opcode.PING, b"data", mask=False)
        ws.feed_frame(parse_frames(bytearray(frame))[0])
        assert len(transport.written) == 1
        pong_frame = parse_frames(bytearray(transport.written[0]))
        assert pong_frame[0].opcode == Opcode.PONG
        assert pong_frame[0].payload == b"data"

    def test_close_frame_echoes(self):
        ws, transport = self._make_ws(require_masking=False)
        payload = struct.pack(">H", 1000)
        frame = build_frame(Opcode.CLOSE, payload, mask=False)
        ws.feed_frame(parse_frames(bytearray(frame))[0])
        assert ws.closed is True
        assert transport.written
        echo = parse_frames(bytearray(transport.written[0]))
        assert echo[0].opcode == Opcode.CLOSE
        assert echo[0].payload[:2] == payload

    def test_fragmented_message(self):
        ws, _ = self._make_ws(require_masking=False)
        f1 = bytearray(build_frame(Opcode.TEXT, b"hel", fin=False, mask=False))
        f2 = bytearray(build_frame(Opcode.CONTINUATION, b"lo", fin=True, mask=False))
        ws.feed_frame(parse_frames(f1)[0])
        ws.feed_frame(parse_frames(f2)[0])
        msg = ws.queue.get_nowait()
        assert msg == b"hello"

    def test_close_enqueues_none(self):
        ws, _ = self._make_ws(require_masking=False)
        frame = build_frame(Opcode.CLOSE, struct.pack(">H", 1000), mask=False)
        ws.feed_frame(parse_frames(bytearray(frame))[0])
        sentinel = ws.queue.get_nowait()
        assert sentinel is None

    def test_rsv_other_causes_close(self):
        ws, transport = self._make_ws(require_masking=False)
        raw = bytearray(build_frame(Opcode.TEXT, b"x", mask=False))
        raw[0] |= 0x20
        frames = parse_frames(raw)
        ws.feed_frame(frames[0])
        assert ws.closed is True

    @pytest.mark.asyncio
    async def test_send_text(self):
        ws, transport = self._make_ws(require_masking=False)
        await ws.send("hello")
        assert len(transport.written) == 1
        frames = parse_frames(bytearray(transport.written[0]))
        assert frames[0].opcode == Opcode.TEXT
        assert frames[0].payload == b"hello"

    @pytest.mark.asyncio
    async def test_send_bytes(self):
        ws, transport = self._make_ws(require_masking=False)
        await ws.send(b"\x01\x02\x03")
        frames = parse_frames(bytearray(transport.written[0]))
        assert frames[0].opcode == Opcode.BINARY

    @pytest.mark.asyncio
    async def test_send_no_op_when_closed(self):
        ws, transport = self._make_ws(require_masking=False)
        ws.closed = True
        await ws.send("hello")
        assert not transport.written

    @pytest.mark.asyncio
    async def test_close_sends_close_frame(self):
        ws, transport = self._make_ws(require_masking=False)
        await ws.close(1000, "bye")
        assert ws.closed is True
        assert transport.written
        frames = parse_frames(bytearray(transport.written[0]))
        assert frames[0].opcode == Opcode.CLOSE

    @pytest.mark.asyncio
    async def test_ping(self):
        ws, transport = self._make_ws(require_masking=False)
        await ws.ping(b"test")
        assert transport.written
        frames = parse_frames(bytearray(transport.written[0]))
        assert frames[0].opcode == Opcode.PING

    @pytest.mark.asyncio
    async def test_receive(self):
        ws, _ = self._make_ws(require_masking=False)
        ws.queue.put_nowait(b"message")
        msg = await ws.receive()
        assert msg == b"message"

    def test_deflate_compress_decompress(self):
        pmd = PerMessageDeflate()
        ws, transport = self._make_ws(require_masking=False, deflate=pmd)
        data = b"hello world" * 20
        compressed = pmd.compress(data)
        raw = bytearray(build_frame(Opcode.TEXT, compressed, rsv1=True, mask=False))
        frames = parse_frames(raw)
        ws.feed_frame(frames[0])
        msg = ws.queue.get_nowait()
        assert msg == data
