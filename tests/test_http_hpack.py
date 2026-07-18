import pytest

from kaede.http.helpers.hpack import Huffman, HPACKEncoder, HPACKDecoder, Coding, HPACKError, STATIC

class TestHuffman:
    # RFC 7541 Appendix C string vectors.
    def test_known_strings(self):
        assert Huffman.encode(b"www.example.com").hex() == "f1e3c2e5f23a6ba0ab90f4ff"
        assert Huffman.encode(b"no-cache").hex() == "a8eb10649cbf"
        assert Huffman.encode(b"custom-key").hex() == "25a849e95ba97d7f"
        assert Huffman.encode(b"custom-value").hex() == "25a849e95bb8e8b4bf"

    def test_round_trips_every_byte(self):
        data = bytes(range(256))
        assert Huffman.decode(Huffman.encode(data)) == data

    def test_decoding_reverses_the_known_strings(self):
        assert Huffman.decode(bytes.fromhex("f1e3c2e5f23a6ba0ab90f4ff")) == b"www.example.com"
        assert Huffman.decode(bytes.fromhex("aec3771a4b")) == b"private"

    def test_a_non_eos_padding_is_rejected(self):
        # RFC 7541 section 5.2: padding must be the EOS prefix (all ones).
        with pytest.raises(HPACKError):
            Huffman.decode(bytes.fromhex("f1e3c2e5f23a6ba0ab90f4fe")) # last bit flipped to 0

    def test_padding_longer_than_seven_bits_is_rejected(self):
        with pytest.raises(HPACKError):
            Huffman.decode(Huffman.encode(b"0") + b"\xff") # a whole extra padding byte

class TestInteger:
    # RFC 7541 Appendix C.1.
    def test_encoding(self):
        assert Coding.integer(10, 5, 0xE0).hex() == "ea"
        assert Coding.integer(1337, 5).hex() == "1f9a0a"
        assert Coding.integer(42, 8).hex() == "2a"

    def test_decoding(self):
        assert Coding.read_integer(bytes.fromhex("0a"), 0, 5) == (10, 1)
        assert Coding.read_integer(bytes.fromhex("1f9a0a"), 0, 5) == (1337, 3)

    def test_an_unbounded_integer_is_rejected(self):
        with pytest.raises(HPACKError):
            Coding.read_integer(b"\x1f" + b"\x80" * 20, 0, 5)

class TestStaticTable:
    def test_the_table_matches_the_rfc(self):
        assert len(STATIC) == 61
        assert STATIC[0] == (":authority", "")
        assert STATIC[1] == (":method", "GET")
        assert STATIC[60] == ("www-authenticate", "")

class TestDecoder:
    def test_c_3_1_literal_and_indexed(self):
        # RFC 7541 C.3.1: first request without Huffman.
        decoder = HPACKDecoder()
        fields = decoder.decode(bytes.fromhex("828684410f7777772e6578616d706c652e636f6d"))

        assert fields == [(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "www.example.com")]

    def test_c_3_uses_the_dynamic_table_across_requests(self):
        decoder = HPACKDecoder()
        decoder.decode(bytes.fromhex("828684410f7777772e6578616d706c652e636f6d"))
        second = decoder.decode(bytes.fromhex("828684be58086e6f2d6361636865"))

        assert (":authority", "www.example.com") in second
        assert ("cache-control", "no-cache") in second

    def test_c_4_1_huffman_coded(self):
        # RFC 7541 C.4.1: first request with Huffman.
        decoder = HPACKDecoder()
        fields = decoder.decode(bytes.fromhex("828684418cf1e3c2e5f23a6ba0ab90f4ff"))

        assert fields == [(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "www.example.com")]

    def test_index_zero_is_rejected(self):
        with pytest.raises(HPACKError):
            HPACKDecoder().decode(b"\x80")

    def test_an_oversized_size_update_is_rejected(self):
        # A dynamic table size update may not exceed SETTINGS_HEADER_TABLE_SIZE.
        with pytest.raises(HPACKError):
            HPACKDecoder(capacity=256).decode(bytes.fromhex("3fe10f")) # size update to 4096

class TestEncoder:
    def test_the_encoder_round_trips_through_the_decoder(self):
        headers = [
            (":method", "GET"), (":scheme", "https"), (":path", "/index.html"),
            (":authority", "example.com"), ("accept", "*/*"), ("user-agent", "kaede"),
        ]

        assert HPACKDecoder().decode(HPACKEncoder().encode(headers)) == headers

    def test_indexed_fields_are_used_for_static_matches(self):
        block = HPACKEncoder().encode([(":method", "GET")])

        assert block == b"\x82" # index 2

    def test_a_secret_is_never_indexed(self):
        block = HPACKEncoder().encode([("authorization", "Bearer x")])

        # RFC 7541 section 6.2.3: the never-indexed literal uses the 0x10 pattern.
        assert block[0] & 0xF0 == 0x10

    def test_dynamic_table_evicts_to_capacity(self):
        decoder = HPACKDecoder(capacity=64)
        # Two incremental-indexing literals; the table can hold only one.
        decoder.decode(HPACKEncoderWithIndexing().block("x-a", "1") + HPACKEncoderWithIndexing().block("x-b", "2"))

        assert decoder.table.size <= 64

class HPACKEncoderWithIndexing:
    """A minimal literal-with-incremental-indexing encoder, only for exercising
    the decoder's dynamic table in a test."""

    def block(self, name: str, value: str) -> bytes:
        return Coding.integer(0, 6, 0x40) + Coding.string(name, huffman=False) + Coding.string(value, huffman=False)
