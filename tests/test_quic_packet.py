import pytest

from kaede.quic.models import QUICPacket

# RFC 9000 section 17 fixes the two header shapes. A long header (section 17.2)
# states the version and both connection id lengths; a short header (section
# 17.3) states none of them and expects the receiver to know how long the
# identifiers it handed out are. Everything below is built from those layouts
# rather than from anything Kaede produces, so a parser that drifts fails.

def long(kind=0, version=1, destination=b"", source=b""):
    """A long header laid out as RFC 9000 section 17.2 describes it."""

    first = 0x80 | 0x40 | ((kind & 0x03) << 4)

    return (bytes([first]) + version.to_bytes(4, "big")
            + bytes([len(destination)]) + destination
            + bytes([len(source)]) + source
            + b"payload")

def short(destination=b""):
    """A short header laid out as RFC 9000 section 17.3 describes it."""

    return bytes([0x40]) + destination + b"payload"

class TestLongHeader:
    def test_reads_both_identifiers(self):
        packet = QUICPacket.read(long(destination=b"\x01\x02\x03\x04", source=b"\xaa\xbb"))

        assert packet.long
        assert packet.destination == b"\x01\x02\x03\x04"
        assert packet.source == b"\xaa\xbb"

    def test_reads_the_version(self):
        # RFC 9000 section 15 registers QUIC version 1 as 0x00000001.
        assert QUICPacket.read(long(version=1, destination=b"\x01")).version == 1

    @pytest.mark.parametrize("kind", [QUICPacket.INITIAL, QUICPacket.ZERO_RTT, QUICPacket.HANDSHAKE, QUICPacket.RETRY])
    def test_reads_the_packet_type(self, kind):
        assert QUICPacket.read(long(kind=kind, destination=b"\x01")).kind == kind

    def test_the_types_are_the_four_the_specification_lists(self):
        assert [QUICPacket.INITIAL, QUICPacket.ZERO_RTT, QUICPacket.HANDSHAKE, QUICPacket.RETRY] == [0, 1, 2, 3]

    def test_only_an_initial_starts_a_connection(self):
        assert QUICPacket.read(long(kind=QUICPacket.INITIAL, destination=b"\x01")).initial
        assert not QUICPacket.read(long(kind=QUICPacket.HANDSHAKE, destination=b"\x01")).initial
        assert not QUICPacket.read(long(kind=QUICPacket.RETRY, destination=b"\x01")).initial

    def test_a_version_negotiation_packet_is_not_an_initial(self):
        # RFC 9000 section 17.2.1: version zero is Version Negotiation, whose
        # type bits carry no packet type at all.
        packet = QUICPacket.read(long(kind=QUICPacket.INITIAL, version=0, destination=b"\x01"))

        assert packet.version == 0
        assert not packet.initial

    def test_reads_an_empty_identifier(self):
        # A zero length connection id is legal: the peer is saying it needs none.
        packet = QUICPacket.read(long(destination=b"", source=b""))

        assert packet.destination == b""
        assert packet.source == b""

    def test_reads_the_longest_identifier_allowed(self):
        # RFC 9000 section 17.2: at most 20 bytes.
        identifier = bytes(range(20))
        packet = QUICPacket.read(long(destination=identifier, source=identifier))

        assert packet.destination == identifier
        assert packet.source == identifier

    def test_refuses_an_identifier_longer_than_allowed(self):
        data = bytes([0xC0]) + (1).to_bytes(4, "big") + bytes([21]) + bytes(21) + bytes([0]) + b"payload"

        assert QUICPacket.read(data) is None

    def test_refuses_a_length_that_runs_past_the_end(self):
        data = bytes([0xC0]) + (1).to_bytes(4, "big") + bytes([8]) + b"\x01\x02"

        assert QUICPacket.read(data) is None

    def test_refuses_a_header_cut_short(self):
        assert QUICPacket.read(bytes([0xC0]) + b"\x00\x00") is None

    def test_the_source_is_read_after_the_destination(self):
        # Getting the order wrong would route by the wrong identifier, which is
        # the sort of mistake that only shows up once a peer moves.
        packet = QUICPacket.read(long(destination=b"\xde\xad", source=b"\xbe\xef\xbe\xef"))

        assert packet.destination == b"\xde\xad"
        assert packet.source == b"\xbe\xef\xbe\xef"

class TestShortHeader:
    def test_reads_the_identifier_at_the_length_given(self):
        identifier = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        packet = QUICPacket.read(short(identifier), len(identifier))

        assert not packet.long
        assert packet.destination == identifier

    def test_takes_only_as_many_bytes_as_asked_for(self):
        # The identifier is followed by the packet number and the payload, none
        # of which belongs to it.
        packet = QUICPacket.read(short(b"\x01\x02\x03\x04\x05\x06\x07\x08"), 4)

        assert packet.destination == b"\x01\x02\x03\x04"

    def test_needs_a_length_to_read_anything(self):
        # Nothing in the packet says how long the identifier is.
        assert QUICPacket.read(short(b"\x01\x02\x03\x04"), 0) is None

    def test_refuses_a_length_longer_than_the_datagram(self):
        assert QUICPacket.read(bytes([0x40]) + b"\x01\x02", 8) is None

    def test_is_never_an_initial(self):
        assert not QUICPacket.read(short(b"\x01\x02\x03\x04"), 4).initial

class TestRefusals:
    @pytest.mark.parametrize("data", [b"", b"\x40", b"\xc0"])
    def test_refuses_what_is_too_small_to_be_a_packet(self, data):
        assert QUICPacket.read(data, 8) is None

    def test_the_form_bit_decides_which_shape_is_read(self):
        # RFC 9000 section 17: the top bit of the first byte, and nothing else,
        # says which of the two headers follows.
        assert QUICPacket.read(long(destination=b"\x01"), 8).long
        assert not QUICPacket.read(short(b"\x01\x02\x03\x04\x05\x06\x07\x08"), 8).long
