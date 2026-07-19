import pytest

from kaede.http.helpers.qpack import QPACKEncoder, QPACKDecoder, QPACKError, STATIC, STATIC_INDEX
from kaede.http.protocol.h3 import Varint

# RFC 9204 Appendix A, taken from the XML source of the document rather than from its
# plain-text rendering. The rendering wraps long values across two rows, and the wrap point
# is not recoverable: index 52 breaks after "text/html;" where the value has a space, and
# index 54 breaks after "text/" where it does not. Transcribing the drawn table is what put
# ten truncated values into the implementation, so the check has to come from the source.
RFC_STATIC = [
    (':authority', ''),
    (':path', '/'),
    ('age', '0'),
    ('content-disposition', ''),
    ('content-length', '0'),
    ('cookie', ''),
    ('date', ''),
    ('etag', ''),
    ('if-modified-since', ''),
    ('if-none-match', ''),
    ('last-modified', ''),
    ('link', ''),
    ('location', ''),
    ('referer', ''),
    ('set-cookie', ''),
    (':method', 'CONNECT'),
    (':method', 'DELETE'),
    (':method', 'GET'),
    (':method', 'HEAD'),
    (':method', 'OPTIONS'),
    (':method', 'POST'),
    (':method', 'PUT'),
    (':scheme', 'http'),
    (':scheme', 'https'),
    (':status', '103'),
    (':status', '200'),
    (':status', '304'),
    (':status', '404'),
    (':status', '503'),
    ('accept', '*/*'),
    ('accept', 'application/dns-message'),
    ('accept-encoding', 'gzip, deflate, br'),
    ('accept-ranges', 'bytes'),
    ('access-control-allow-headers', 'cache-control'),
    ('access-control-allow-headers', 'content-type'),
    ('access-control-allow-origin', '*'),
    ('cache-control', 'max-age=0'),
    ('cache-control', 'max-age=2592000'),
    ('cache-control', 'max-age=604800'),
    ('cache-control', 'no-cache'),
    ('cache-control', 'no-store'),
    ('cache-control', 'public, max-age=31536000'),
    ('content-encoding', 'br'),
    ('content-encoding', 'gzip'),
    ('content-type', 'application/dns-message'),
    ('content-type', 'application/javascript'),
    ('content-type', 'application/json'),
    ('content-type', 'application/x-www-form-urlencoded'),
    ('content-type', 'image/gif'),
    ('content-type', 'image/jpeg'),
    ('content-type', 'image/png'),
    ('content-type', 'text/css'),
    ('content-type', 'text/html; charset=utf-8'),
    ('content-type', 'text/plain'),
    ('content-type', 'text/plain;charset=utf-8'),
    ('range', 'bytes=0-'),
    ('strict-transport-security', 'max-age=31536000'),
    ('strict-transport-security', 'max-age=31536000; includesubdomains'),
    ('strict-transport-security', 'max-age=31536000; includesubdomains; preload'),
    ('vary', 'accept-encoding'),
    ('vary', 'origin'),
    ('x-content-type-options', 'nosniff'),
    ('x-xss-protection', '1; mode=block'),
    (':status', '100'),
    (':status', '204'),
    (':status', '206'),
    (':status', '302'),
    (':status', '400'),
    (':status', '403'),
    (':status', '421'),
    (':status', '425'),
    (':status', '500'),
    ('accept-language', ''),
    ('access-control-allow-credentials', 'FALSE'),
    ('access-control-allow-credentials', 'TRUE'),
    ('access-control-allow-headers', '*'),
    ('access-control-allow-methods', 'get'),
    ('access-control-allow-methods', 'get, post, options'),
    ('access-control-allow-methods', 'options'),
    ('access-control-expose-headers', 'content-length'),
    ('access-control-request-headers', 'content-type'),
    ('access-control-request-method', 'get'),
    ('access-control-request-method', 'post'),
    ('alt-svc', 'clear'),
    ('authorization', ''),
    ('content-security-policy', "script-src 'none'; object-src 'none'; base-uri 'none'"),
    ('early-data', '1'),
    ('expect-ct', ''),
    ('forwarded', ''),
    ('if-range', ''),
    ('origin', ''),
    ('purpose', 'prefetch'),
    ('server', ''),
    ('timing-allow-origin', '*'),
    ('upgrade-insecure-requests', '1'),
    ('user-agent', ''),
    ('x-forwarded-for', ''),
    ('x-frame-options', 'deny'),
    ('x-frame-options', 'sameorigin'),
]

class TestStaticTable:
    def test_every_entry_matches_the_rfc(self):
        assert len(STATIC) == len(RFC_STATIC) == 99

        for index, (expected, found) in enumerate(zip(RFC_STATIC, STATIC)):
            assert tuple(found) == expected, f"static table index {index} does not match RFC 9204"

    def test_no_two_entries_collide_in_the_encoder_index(self):
        # A truncated value can make two distinct entries equal, and the later one then wins
        # the reverse lookup, so a sender emits an index that means something else entirely.
        assert len(STATIC_INDEX) == len(STATIC)

    def test_the_wrapped_values_are_whole(self):
        # The ten entries RFC 9204 draws across two rows, listed explicitly so a regression
        # names the entry rather than only the index.
        assert STATIC[30] == ("accept", "application/dns-message")
        assert STATIC[41] == ("cache-control", "public, max-age=31536000")
        assert STATIC[44] == ("content-type", "application/dns-message")
        assert STATIC[45] == ("content-type", "application/javascript")
        assert STATIC[47] == ("content-type", "application/x-www-form-urlencoded")
        assert STATIC[52] == ("content-type", "text/html; charset=utf-8")
        assert STATIC[54] == ("content-type", "text/plain;charset=utf-8")
        assert STATIC[57] == ("strict-transport-security", "max-age=31536000; includesubdomains")
        assert STATIC[58] == ("strict-transport-security", "max-age=31536000; includesubdomains; preload")
        assert STATIC[85] == ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'")

    def test_the_most_common_html_entry_decodes_whole(self):
        # 0xF4 is index 52, which a compliant server sends as a single byte on nearly every
        # HTML response. A truncated value there strips the charset from all of them.
        assert QPACKDecoder().decode(b"\x00\x00\xd9\xf4") == [(":status", "200"), ("content-type", "text/html; charset=utf-8")]

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
