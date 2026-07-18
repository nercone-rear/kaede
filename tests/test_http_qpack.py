import pytest

from kaede.http.helpers.qpack import QPACKEncoder, QPACKDecoder, QPACKError, STATIC
from kaede.http.protocol.h3 import Varint

class TestStaticTable:
    def test_the_table_matches_the_rfc(self):
        assert len(STATIC) == 99
        assert STATIC[0] == (":authority", "")
        assert STATIC[1] == (":path", "/")
        assert STATIC[98] == ("x-frame-options", "sameorigin")

class TestEncoder:
    def test_the_prefix_is_always_zero(self):
        # RFC 9204: Required Insert Count 0 and Delta Base 0, since no dynamic table is used.
        assert QPACKEncoder().encode([])[:2] == b"\x00\x00"

    def test_an_exact_static_match_is_indexed(self):
        # RFC 9204 section 4.5.2: :path / is static index 1, encoded 0xC1.
        assert QPACKEncoder().encode([(":path", "/")]) == b"\x00\x00\xc1"

    def test_round_trips_through_the_decoder(self):
        headers = [
            (":method", "GET"), (":scheme", "https"), (":path", "/index.html"),
            (":authority", "example.com"), ("x-custom", "value"), ("accept", "*/*"),
        ]

        assert QPACKDecoder().decode(QPACKEncoder().encode(headers)) == headers

    def test_a_secret_is_never_indexed(self):
        block = QPACKEncoder().encode([("authorization", "Bearer token")])

        # The literal name reference with the never-index bit set (0 1 N T).
        assert block[2] & 0x60 == 0x60

class TestDecoder:
    def test_a_nonzero_required_insert_count_is_rejected(self):
        # RFC 9204 section 3.2.3: with no dynamic table, RIC must be zero.
        with pytest.raises(QPACKError):
            QPACKDecoder().decode(b"\x01\x00\xc1")

    def test_a_dynamic_reference_is_rejected(self):
        # A relative-index field line (0x00 pattern) references the dynamic table.
        with pytest.raises(QPACKError):
            QPACKDecoder().decode(b"\x00\x00\x00")

    def test_an_out_of_range_static_index_is_rejected(self):
        with pytest.raises(QPACKError):
            QPACKDecoder().decode(b"\x00\x00" + b"\xff\x64") # indexed static index way past 98

class TestVarint:
    # RFC 9000 section 16 sample values.
    def test_encoding_picks_the_shortest_form(self):
        assert Varint.encode(0) == b"\x00"
        assert Varint.encode(37) == b"\x25"
        assert Varint.encode(15293) == b"\x7b\xbd"
        assert Varint.encode(494878333) == b"\x9d\x7f\x3e\x7d"

    def test_decoding_reverses_it(self):
        for value in (0, 37, 63, 64, 15293, 494878333, 151288809941952652):
            assert Varint.decode(Varint.encode(value)) == (value, len(Varint.encode(value)))

    def test_the_two_byte_sample_decodes(self):
        assert Varint.decode(b"\x7b\xbd")[0] == 15293
