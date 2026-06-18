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

    def test_empty_payload(self):
        frame = build_frame(Opcode.TEXT, b"")
        assert frame[0] == 0x81
        assert frame[1] == 0

    def test_exactly_125_bytes_is_single_byte_length(self):
        payload = b"x" * 125
        frame = build_frame(Opcode.BINARY, payload)
        assert frame[1] == 125

    def test_exactly_126_bytes_is_medium_length(self):
        payload = b"x" * 126
        frame = build_frame(Opcode.BINARY, payload)
        assert frame[1] == 126
        assert struct.unpack_from(">H", frame, 2)[0] == 126

    def test_exactly_65535_bytes_is_medium_max(self):
        payload = b"x" * 65535
        frame = build_frame(Opcode.BINARY, payload)
        assert frame[1] == 126
        assert struct.unpack_from(">H", frame, 2)[0] == 65535

    def test_fin_bit_set_by_default(self):
        frame = build_frame(Opcode.TEXT, b"hi")
        assert frame[0] & 0x80

    def test_no_rsv_by_default(self):
        frame = build_frame(Opcode.TEXT, b"hi")
        assert not (frame[0] & 0x70)

    def test_continuation_opcode(self):
        frame = build_frame(Opcode.CONTINUATION, b"cont")
        assert frame[0] & 0x0F == 0x00

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

    def test_incomplete_medium_length_header(self):
        buf = bytearray(b"\x82\x7e\x00")
        frames = parse_frames(buf)
        assert frames == []

    def test_incomplete_large_length_header(self):
        buf = bytearray(b"\x82\x7f\x00\x00\x00\x00\x00\x00\x00")
        frames = parse_frames(buf)
        assert frames == []

    def test_rsv1_preserved_in_frame(self):
        raw = bytearray(build_frame(Opcode.TEXT, b"data", rsv1=True))
        frames = parse_frames(raw)
        assert frames[0].rsv1 is True

    def test_fin_false_preserved(self):
        raw = bytearray(build_frame(Opcode.TEXT, b"frag", fin=False))
        frames = parse_frames(raw)
        assert frames[0].fin is False

    def test_partial_second_frame_leaves_first_only(self):
        complete = build_frame(Opcode.TEXT, b"first")
        incomplete = b"\x81"
        buf = bytearray(complete + incomplete)
        frames = parse_frames(buf)
        assert len(frames) == 1
        assert frames[0].payload == b"first"
        assert len(buf) == 1

    def test_masked_bit_preserved(self):
        buf = bytearray(build_frame(Opcode.TEXT, b"masked", mask=True))
        frames = parse_frames(buf)
        assert frames[0].masked is True

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

    def test_context_reuse_server_false(self):
        pmd = PerMessageDeflate(server_no_context_takeover=False)
        data = b"repeated repeated repeated" * 50
        c1 = pmd.compress(data)
        assert pmd.compress_context is not None
        c2 = pmd.compress(data)
        assert pmd.compress_context is not None
        assert pmd.decompress(c1) == data
        assert pmd.decompress(c2) == data

    def test_no_context_takeover_true_creates_new_ctx_each_time(self):
        pmd = PerMessageDeflate(server_no_context_takeover=True)
        data = b"hello" * 100
        c1 = pmd.compress(data)
        c2 = pmd.compress(data)
        assert pmd.compress_context is None

    def test_decompress_context_reuse(self):
        pmd = PerMessageDeflate(client_no_context_takeover=False)
        data = b"hello world" * 10
        compressed = pmd.compress(data)
        out1 = pmd.decompress(compressed)
        compressed2 = pmd.compress(data)
        out2 = pmd.decompress(compressed2)
        assert out1 == data
        assert out2 == data

    def test_response_header_client_no_context_takeover(self):
        pmd = PerMessageDeflate(server_no_context_takeover=False, client_no_context_takeover=True)
        header = pmd.response_header()
        assert "client_no_context_takeover" in header
        assert "server_no_context_takeover" not in header

    def test_response_header_custom_window_bits(self):
        pmd = PerMessageDeflate(server_max_window_bits=12, client_max_window_bits=10)
        header = pmd.response_header()
        assert "server_max_window_bits=12" in header
        assert "client_max_window_bits=10" in header

    def test_from_client_offer_multiple_offers_first_wins(self):
        offer = "identity, permessage-deflate; server_max_window_bits=12"
        pmd = PerMessageDeflate.from_client_offer(offer)
        assert pmd is not None
        assert pmd.server_max_window_bits == 12

    def test_from_client_offer_invalid_window_bits_uses_default(self):
        pmd = PerMessageDeflate.from_client_offer("permessage-deflate; server_max_window_bits=abc")
        assert pmd is not None
        assert pmd.server_max_window_bits == 15

    def test_compress_then_decompress_large(self):
        pmd = PerMessageDeflate()
        data = b"large data block " * 5000
        compressed = pmd.compress(data)
        result = pmd.decompress(compressed)
        assert result == data

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

    def test_control_frame_not_fin_closes_with_1002(self):
        ws, transport = self._make_ws(require_masking=False)
        frame = parse_frames(bytearray(build_frame(Opcode.PING, b"ping", fin=False, mask=False)))[0]
        ws.feed_frame(frame)
        assert ws.closed is True

    def test_ping_payload_too_large_closes_1002(self):
        ws, transport = self._make_ws(require_masking=False)
        big_payload = b"x" * 126
        raw = bytearray(build_frame(Opcode.PING, big_payload, mask=False))
        frames = parse_frames(raw)
        ws.feed_frame(frames[0])
        assert ws.closed is True

    def test_continuation_without_prior_frame_closes(self):
        ws, transport = self._make_ws(require_masking=False)
        frame = parse_frames(bytearray(build_frame(Opcode.CONTINUATION, b"data", mask=False)))[0]
        ws.feed_frame(frame)
        assert ws.closed is True

    def test_text_frame_while_fragments_pending_closes(self):
        ws, _ = self._make_ws(require_masking=False)
        f1 = bytearray(build_frame(Opcode.TEXT, b"start", fin=False, mask=False))
        ws.feed_frame(parse_frames(f1)[0])
        f2 = bytearray(build_frame(Opcode.TEXT, b"new_start", fin=True, mask=False))
        ws.feed_frame(parse_frames(f2)[0])
        assert ws.closed is True

    def test_rsv1_without_deflate_closes(self):
        ws, transport = self._make_ws(require_masking=False)
        raw = bytearray(build_frame(Opcode.TEXT, b"compressed", rsv1=True, mask=False))
        ws.feed_frame(parse_frames(raw)[0])
        assert ws.closed is True

    def test_max_message_size_continuation_closes(self):
        ws, _ = self._make_ws(require_masking=False, max_message_size=10)
        f1 = bytearray(build_frame(Opcode.TEXT, b"hello", fin=False, mask=False))
        ws.feed_frame(parse_frames(f1)[0])
        f2 = bytearray(build_frame(Opcode.CONTINUATION, b" world!!!", fin=True, mask=False))
        ws.feed_frame(parse_frames(f2)[0])
        assert ws.closed is True

    def test_pong_frame_not_enqueued(self):
        ws, _ = self._make_ws(require_masking=False)
        frame = parse_frames(bytearray(build_frame(Opcode.PONG, b"pong", mask=False)))[0]
        ws.feed_frame(frame)
        assert ws.queue.empty()

    @pytest.mark.asyncio
    async def test_close_already_closed_is_noop(self):
        ws, transport = self._make_ws(require_masking=False)
        ws.closed = True
        await ws.close(1000, "bye")
        assert not transport.written

    @pytest.mark.asyncio
    async def test_close_with_reason_encodes_message(self):
        ws, transport = self._make_ws(require_masking=False)
        await ws.close(1001, "going away")
        assert transport.written
        frame = parse_frames(bytearray(transport.written[0]))[0]
        assert frame.opcode == Opcode.CLOSE
        assert frame.payload[2:].decode("utf-8") == "going away"

    @pytest.mark.asyncio
    async def test_ping_closed_is_noop(self):
        ws, transport = self._make_ws(require_masking=False)
        ws.closed = True
        await ws.ping(b"test")
        assert not transport.written

    @pytest.mark.asyncio
    async def test_send_text_with_deflate(self):
        pmd = PerMessageDeflate()
        ws, transport = self._make_ws(require_masking=False, deflate=pmd)
        await ws.send("hello deflate")
        assert len(transport.written) == 1
        frame = parse_frames(bytearray(transport.written[0]))[0]
        assert frame.opcode == Opcode.TEXT
        assert frame.rsv1 is True

    @pytest.mark.asyncio
    async def test_send_bytes_with_deflate(self):
        pmd = PerMessageDeflate()
        ws, transport = self._make_ws(require_masking=False, deflate=pmd)
        await ws.send(b"\x01\x02\x03")
        assert transport.written
        frame = parse_frames(bytearray(transport.written[0]))[0]
        assert frame.opcode == Opcode.BINARY
        assert frame.rsv1 is True

    def test_close_frame_empty_payload_echoes_empty(self):
        ws, transport = self._make_ws(require_masking=False)
        frame = parse_frames(bytearray(build_frame(Opcode.CLOSE, b"", mask=False)))[0]
        ws.feed_frame(frame)
        assert ws.closed is True
        echo = parse_frames(bytearray(transport.written[0]))
        assert echo[0].opcode == Opcode.CLOSE
        assert echo[0].payload == b""
