"""The HTTP/3 control stream and the error reporting around it.

RFC 9114 §6.2.1 and §7.2 put several requirements on the control stream that were absent,
and every one of them was unreachable anyway: consume() ended in `except (H3Error, QUICError):
pass`, so a diagnosis made anywhere on a unidirectional stream was discarded. These tests
check both halves, the detection and the reporting.
"""

import pytest

from kaede.quic.errors import QUICError, QUICClosedError
from kaede.http.models import HTTPLimits
from kaede.http.protocol.h3 import H3Session, H3Error, Varint, Stream, Kind, Setting, Code

def frame(kind: int, payload: bytes = b"") -> bytes:
    return Varint.encode(kind) + Varint.encode(len(payload)) + payload

def settings(*pairs) -> bytes:
    payload = b"".join(Varint.encode(identifier) + Varint.encode(value) for identifier, value in pairs)

    return frame(Kind.SETTINGS, payload)

class Unidirectional:
    """A peer-opened unidirectional stream that hands out prepared octets and then ends."""

    readable = True
    writable = False

    def __init__(self, data: bytes):
        self.data = bytearray(data)
        self.reset_code = None

    async def receive_exactly(self, count: int) -> bytes:
        if len(self.data) < count:
            raise QUICClosedError("the stream ended")

        chunk = bytes(self.data[:count])
        del self.data[:count]

        return chunk

    async def receive(self, count: int) -> bytes:
        chunk = bytes(self.data[:count])
        del self.data[:count]

        return chunk

    def reset(self, code: int = 0):
        self.reset_code = code

class Connection:
    """A QUIC connection that only records how it was closed."""

    def __init__(self):
        self.code = None
        self.reason = None

    async def close(self, code: int = 0, reason: str = "", **_):
        self.code, self.reason = code, reason

def session(server=True) -> H3Session:
    built = H3Session.__new__(H3Session)
    H3Session.__init__(built, Connection(), server=server, limits=HTTPLimits())

    return built

async def drive(data: bytes, *, server=True):
    """Run consume() over a prepared control stream and report how the connection ended."""
    built = session(server)
    await built.consume(Unidirectional(data))

    return built

class TestErrorReporting:
    """The reporting itself, which is what made every other rule below inert."""

    async def test_a_fault_closes_the_connection_with_its_code(self):
        built = await drive(Varint.encode(Stream.CONTROL) + settings() + frame(Kind.HEADERS, b"\x00"))

        assert built.connection.code == Code.FRAME_UNEXPECTED

    async def test_a_clean_stream_does_not_invent_an_error(self):
        # §6.2.3: an unknown unidirectional stream type may simply be abandoned.
        built = await drive(Varint.encode(0x21) + b"whatever")

        assert built.connection.code is None

class TestSettings:
    async def test_the_control_stream_must_open_with_settings(self):
        # §6.2.1: H3_MISSING_SETTINGS if any other frame comes first.
        built = await drive(Varint.encode(Stream.CONTROL) + frame(Kind.GOAWAY, Varint.encode(0)))

        assert built.connection.code == Code.MISSING_SETTINGS

    async def test_a_second_settings_frame_is_refused(self):
        # §7.2.4: H3_FRAME_UNEXPECTED.
        built = await drive(Varint.encode(Stream.CONTROL) + settings() + settings())

        assert built.connection.code == Code.FRAME_UNEXPECTED

    async def test_the_payload_is_parsed(self):
        built = await drive(Varint.encode(Stream.CONTROL) + settings((Setting.MAX_FIELD_SECTION_SIZE, 4096)))

        assert built.settled
        assert built.field_section_ceiling == 4096

    @pytest.mark.parametrize("identifier", [0x00, 0x02, 0x03, 0x04, 0x05])
    async def test_a_reserved_setting_identifier_is_refused(self, identifier):
        # §7.2.4.1: the HTTP/2 identifiers are reserved and are a connection error here.
        built = await drive(Varint.encode(Stream.CONTROL) + settings((identifier, 1)))

        assert built.connection.code == Code.SETTINGS_ERROR

    async def test_a_repeated_setting_is_refused(self):
        built = await drive(Varint.encode(Stream.CONTROL) + settings((Setting.QPACK_BLOCKED_STREAMS, 0), (Setting.QPACK_BLOCKED_STREAMS, 1)))

        assert built.connection.code == Code.SETTINGS_ERROR

    async def test_a_truncated_parameter_is_refused(self):
        built = await drive(Varint.encode(Stream.CONTROL) + frame(Kind.SETTINGS, Varint.encode(Setting.QPACK_BLOCKED_STREAMS)))

        assert built.connection.code == Code.SETTINGS_ERROR

class TestCriticalStreams:
    async def test_closing_the_control_stream_ends_the_connection(self):
        """§6.2.1: H3_CLOSED_CRITICAL_STREAM. The code was defined and never once referenced."""
        built = await drive(Varint.encode(Stream.CONTROL) + settings())

        assert built.connection.code == Code.CLOSED_CRITICAL

    async def test_a_second_control_stream_is_refused(self):
        # §6.2.1: H3_STREAM_CREATION_ERROR. Two control streams otherwise ran side by side,
        # each writing its own view of the connection state.
        built = session()
        built.peer_control = object()

        await built.consume(Unidirectional(Varint.encode(Stream.CONTROL) + settings()))

        assert built.connection.code == Code.STREAM_CREATION_ERROR

    async def test_closing_a_qpack_stream_ends_the_connection(self):
        built = await drive(Varint.encode(Stream.ENCODER))

        assert built.connection.code == Code.CLOSED_CRITICAL

    async def test_a_second_qpack_stream_of_one_type_is_refused(self):
        built = session()
        built.peer_qpack[Stream.ENCODER] = object()

        await built.consume(Unidirectional(Varint.encode(Stream.ENCODER)))

        assert built.connection.code == Code.STREAM_CREATION_ERROR

    async def test_a_push_stream_is_refused(self):
        # §6.2.2: a push stream is only legal after MAX_PUSH_ID, which Kaede never sends.
        built = await drive(Varint.encode(Stream.PUSH))

        assert built.connection.code == Code.STREAM_CREATION_ERROR

class TestControlFrames:
    @pytest.mark.parametrize("kind", sorted(Kind.RESERVED))
    async def test_a_reserved_http_2_frame_type_is_refused(self, kind):
        # §7.2.8: the HTTP/2 frame types are reserved and are H3_FRAME_UNEXPECTED.
        built = await drive(Varint.encode(Stream.CONTROL) + settings() + frame(kind))

        assert built.connection.code == Code.FRAME_UNEXPECTED

    @pytest.mark.parametrize("kind", [Kind.DATA, Kind.HEADERS])
    async def test_a_request_frame_on_the_control_stream_is_refused(self, kind):
        built = await drive(Varint.encode(Stream.CONTROL) + settings() + frame(kind, b"\x00"))

        assert built.connection.code == Code.FRAME_UNEXPECTED

    async def test_a_goaway_identifier_may_not_increase(self):
        # §5.2: a later GOAWAY may only narrow what the peer will still handle.
        body = settings() + frame(Kind.GOAWAY, Varint.encode(4)) + frame(Kind.GOAWAY, Varint.encode(8))
        built = await drive(Varint.encode(Stream.CONTROL) + body)

        assert built.connection.code == Code.ID_ERROR

    async def test_a_goaway_identifier_may_decrease(self):
        body = settings() + frame(Kind.GOAWAY, Varint.encode(8)) + frame(Kind.GOAWAY, Varint.encode(4))
        built = await drive(Varint.encode(Stream.CONTROL) + body)

        assert built.goaway_id == 4
        assert built.closing

    async def test_a_goaway_without_an_identifier_is_a_frame_error(self):
        built = await drive(Varint.encode(Stream.CONTROL) + settings() + frame(Kind.GOAWAY))

        assert built.connection.code == Code.FRAME_ERROR

    async def test_a_goaway_with_trailing_bytes_is_a_frame_error(self):
        # §7.1: the payload has to match what the frame type says it holds.
        built = await drive(Varint.encode(Stream.CONTROL) + settings() + frame(Kind.GOAWAY, Varint.encode(4) + b"\x00"))

        assert built.connection.code == Code.FRAME_ERROR

    async def test_a_max_push_id_may_not_decrease(self):
        body = settings() + frame(Kind.MAX_PUSH_ID, Varint.encode(8)) + frame(Kind.MAX_PUSH_ID, Varint.encode(4))
        built = await drive(Varint.encode(Stream.CONTROL) + body)

        assert built.connection.code == Code.ID_ERROR

    async def test_a_client_receiving_max_push_id_refuses_it(self):
        # §7.2.7: only a client sends MAX_PUSH_ID, so a client receiving one is a fault.
        built = await drive(Varint.encode(Stream.CONTROL) + settings() + frame(Kind.MAX_PUSH_ID, Varint.encode(8)), server=False)

        assert built.connection.code == Code.FRAME_UNEXPECTED

    async def test_a_cancel_push_naming_no_promise_is_refused(self):
        # Kaede never promises a push, so no identifier here can name a real one.
        built = await drive(Varint.encode(Stream.CONTROL) + settings() + frame(Kind.CANCEL_PUSH, Varint.encode(0)))

        assert built.connection.code == Code.ID_ERROR

class TestFrameIntegrity:
    async def test_a_payload_shorter_than_its_length_is_a_frame_error(self):
        """§7.1: a frame that stops short of its declared length is a frame error, not the
        ordinary end of the stream, so it must not be read as a complete frame."""
        truncated = Varint.encode(Kind.SETTINGS) + Varint.encode(16) + b"\x01\x00"
        built = await drive(Varint.encode(Stream.CONTROL) + truncated)

        assert built.connection.code == Code.FRAME_ERROR
