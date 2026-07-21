"""WSCloseCode frames and frame length encoding, from RFC 6455 §5.2, §5.5.1 and §7.4."""

import struct

import pytest

from kaede.tcp.errors import TCPClosedError
from kaede.http.errors import WebSocketError
from kaede.http.websocket import WSCloseCode, WSOpCode, WSFrame, WSConnection

class Wire:
    """A transport that hands out prepared octets and keeps whatever is written to it.

    Running out of octets raises the same error a real TCP connection raises at EOF, so the
    code under test takes the path it would take against a peer that stopped talking.
    """

    def __init__(self, incoming: bytes = b""):
        self.incoming = bytearray(incoming)
        self.written = bytearray()
        self.closed = False

    async def receive_exactly(self, count: int) -> bytes:
        if len(self.incoming) < count:
            raise TCPClosedError("the peer sent nothing more")

        chunk = bytes(self.incoming[:count])
        del self.incoming[:count]

        return chunk

    async def send(self, data: bytes):
        self.written += data

    async def close(self, **_):
        self.closed = True

def sent(wire: Wire):
    """The opcode and payload of the single frame written to the wire, if any."""
    if not wire.written:
        return None

    payload = wire.written[2:] if wire.written[1] & 0x80 == 0 else wire.written[6:]
    masked = bool(wire.written[1] & 0x80)

    if masked:
        key = wire.written[2:6]
        payload = bytes(byte ^ key[index % 4] for index, byte in enumerate(payload))

    return (wire.written[0] & 0x0F, bytes(payload))

def code(wire: Wire):
    frame = sent(wire)

    return struct.unpack(">H", frame[1][:2])[0] if frame and len(frame[1]) >= 2 else None

class TestCloseCodes:
    """§7.4.1 marks 1005, 1006 and 1015 as codes that MUST NOT appear in a close frame."""

    @pytest.mark.parametrize("value", [1005, 1006, 1015, 1004, 0, 999, 5000, 2999])
    def test_a_forbidden_code_is_not_sendable(self, value):
        assert not WSCloseCode.sendable(value)

    @pytest.mark.parametrize("value", [1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 3000, 4999])
    def test_an_allowed_code_is_sendable(self, value):
        assert WSCloseCode.sendable(value)

    @pytest.mark.parametrize("value", [1005, 1006, 1015, 1004, 999, 5000])
    def test_a_forbidden_code_is_not_receivable(self, value):
        assert not WSCloseCode.receivable(value)

class TestCloseFrames:
    async def test_a_forbidden_code_is_never_written_to_the_wire(self):
        wire = Wire()
        connection = WSConnection(("", None), ("", None), transport=wire, server=True)

        await connection.close(WSCloseCode.ABNORMAL, "transport failed")

        assert code(wire) != WSCloseCode.ABNORMAL
        assert WSCloseCode.sendable(code(wire))

    async def test_a_peer_close_carrying_a_forbidden_code_is_refused(self):
        """The exact case that echoed 1006 straight back: a code that can only ever describe
        a local observation, arriving in a frame that by definition was received."""
        wire = Wire()
        connection = WSConnection(("", None), ("", None), transport=wire, server=True)

        with pytest.raises(WebSocketError):
            await connection.acknowledge(struct.pack(">H", 1006))

        assert code(wire) == WSCloseCode.PROTOCOL

    async def test_a_peer_close_is_echoed_with_its_own_code(self):
        wire = Wire()
        connection = WSConnection(("", None), ("", None), transport=wire, server=True)

        await connection.acknowledge(struct.pack(">H", 1001))

        assert code(wire) == 1001

    async def test_an_empty_peer_close_is_answered_normally(self):
        # §7.1.5: no code means 1005 locally, which may not go back onto the wire.
        wire = Wire()
        connection = WSConnection(("", None), ("", None), transport=wire, server=True)

        await connection.acknowledge(b"")

        assert code(wire) == WSCloseCode.NORMAL

    async def test_a_one_octet_close_body_is_a_protocol_error(self):
        # §5.5.1: the body is either empty or at least a two octet code.
        wire = Wire()
        connection = WSConnection(("", None), ("", None), transport=wire, server=True)

        with pytest.raises(WebSocketError):
            await connection.acknowledge(b"\x03")

        assert code(wire) == WSCloseCode.PROTOCOL

    async def test_a_close_reason_that_is_not_utf_8_is_refused(self):
        wire = Wire()
        connection = WSConnection(("", None), ("", None), transport=wire, server=True)

        with pytest.raises(WebSocketError):
            await connection.acknowledge(struct.pack(">H", 1000) + b"\xff\xfe")

        assert code(wire) == WSCloseCode.INVALID

class TestCloseReason:
    """§5.5 caps a control frame payload at 125 octets, and §5.5.1 requires valid UTF-8."""

    def test_a_long_reason_is_trimmed_to_fit(self):
        assert len(WSCloseCode.clip("x" * 300)) == 123

    def test_a_reason_is_never_cut_through_a_character(self):
        # Three octets each, so a plain 123 octet slice would land inside the 41st character.
        clipped = WSCloseCode.clip("あ" * 60)

        assert len(clipped) <= 123
        assert clipped.decode() == "あ" * 41

    def test_a_short_reason_is_untouched(self):
        assert WSCloseCode.clip("bye") == b"bye"

class TestLengthEncoding:
    """§5.2 requires the minimal length encoding, so a length has to use the shortest form."""

    async def read(self, payload: bytes):
        return await WSFrame.read(Wire(payload), limit=1 << 20)

    async def test_a_short_length_written_in_the_two_octet_form_is_refused(self):
        # 0x7E says a 16 bit length follows, but 5 fits in the 7 bit field.
        with pytest.raises(WebSocketError):
            await self.read(b"\x81\xfe\x00\x05Hello")

    async def test_a_short_length_written_in_the_eight_octet_form_is_refused(self):
        with pytest.raises(WebSocketError):
            await self.read(b"\x81\xff\x00\x00\x00\x00\x00\x00\x00\x05Hello")

    async def test_a_length_with_the_top_bit_set_is_refused(self):
        # §5.2: the most significant bit of a 64 bit length MUST be 0.
        with pytest.raises(WebSocketError):
            await self.read(b"\x81\xff\xff\xff\xff\xff\xff\xff\xff\xff")

    async def test_the_minimal_form_is_accepted(self):
        fin, opcode, payload, masked = await self.read(b"\x81\x05Hello")

        assert (fin, opcode, payload, masked) == (True, WSOpCode.TEXT, b"Hello", False)

    async def test_the_two_octet_form_is_accepted_where_it_is_needed(self):
        body = b"x" * 200
        fin, opcode, payload, masked = await self.read(b"\x81\x7e\x00\xc8" + body)

        assert payload == body
