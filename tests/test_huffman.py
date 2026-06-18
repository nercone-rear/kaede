import pytest
from kaede.huffman import huffman_encode, huffman_decode


class TestHuffmanRoundtrip:
    def test_empty(self):
        assert huffman_decode(huffman_encode(b"")) == b""

    def test_single_ascii_chars(self):
        for ch in b"Hello, World!":
            data = bytes([ch])
            assert huffman_decode(huffman_encode(data)) == data

    def test_common_string(self):
        data = b"www.example.com"
        assert huffman_decode(huffman_encode(data)) == data

    def test_all_printable_ascii(self):
        data = bytes(range(32, 127))
        assert huffman_decode(huffman_encode(data)) == data

    def test_all_byte_values(self):
        data = bytes(range(256))
        assert huffman_decode(huffman_encode(data)) == data

    def test_repeated_bytes(self):
        data = b"aaaaaaaaaaaa" * 100
        assert huffman_decode(huffman_encode(data)) == data

    def test_http_header_value(self):
        data = b"application/json; charset=utf-8"
        assert huffman_decode(huffman_encode(data)) == data

    def test_high_bytes(self):
        data = bytes(range(128, 256))
        assert huffman_decode(huffman_encode(data)) == data


class TestHuffmanEncode:
    def test_empty_returns_empty(self):
        assert huffman_encode(b"") == b""

    def test_output_is_bytes(self):
        assert isinstance(huffman_encode(b"hello"), bytes)

    def test_known_encoding_a(self):
        # 'a' = 97, code=(0x3, 5 bits), padding=3 → 0b00011_111 = 0x1f
        assert huffman_encode(b"a") == b"\x1f"

    def test_compressed_not_longer_than_input_for_common_ascii(self):
        data = b"www.example.com"
        # HPACK Huffman compresses typical ASCII by ~30-40%
        assert len(huffman_encode(data)) < len(data)

    def test_output_length_multiple_of_byte(self):
        # encoded output is always whole bytes (padded)
        result = huffman_encode(b"test string")
        assert isinstance(result, bytes)
        assert len(result) > 0


class TestHuffmanDecode:
    def test_empty_returns_empty(self):
        assert huffman_decode(b"") == b""

    def test_output_is_bytes(self):
        assert isinstance(huffman_decode(huffman_encode(b"abc")), bytes)

    def test_known_decode_a(self):
        # Verify 0x1f decodes back to 'a'
        assert huffman_decode(b"\x1f") == b"a"

    def test_invalid_padding_raises(self):
        # b"\x1e" = 0b00011110: 'a' uses bits 4-3, then bits 2-0 = 110 ≠ 111
        with pytest.raises(RuntimeError, match="invalid padding"):
            huffman_decode(b"\x1e")

    def test_incomplete_symbol_raises(self):
        # b"\xff\xff" = 16 one-bits; no valid HPACK symbol spans all 16 bits
        with pytest.raises(RuntimeError, match="incomplete symbol"):
            huffman_decode(b"\xff\xff")

    def test_too_long_code_raises(self):
        # A byte string that causes current_bits to exceed 30 before matching
        # Use a carefully crafted byte string where prefix grows past 30 bits.
        # All-ones data forces the accumulator to grow until limit.
        with pytest.raises(RuntimeError):
            huffman_decode(b"\xff\xff\xff\xff\xff")
