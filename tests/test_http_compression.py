"""Content coding, where the header and the body have to keep agreeing with each other."""

import gzip
import zlib

import brotlicffi
import pytest
import zstandard

from kaede.http.models import HTTPMessage, HTTPHeaders, HTTPLimits
from kaede.http.errors import HTTPError
from kaede.http.headers import AcceptEncoding
from kaede.http.helpers.compression import compress, compress_with, decompress

def encoded(body: bytes, coding: str) -> HTTPMessage:
    message = HTTPMessage(headers=HTTPHeaders([("Content-Encoding", coding)]), body=body)
    message.compressed = True

    return message

class TestDecoding:
    """RFC 9110 §8.4: Content-Encoding lists the codings applied, in the order applied."""

    @pytest.mark.parametrize("coding,pack", [
        ("gzip", gzip.compress),
        ("deflate", zlib.compress),
        ("br", brotlicffi.compress),
        ("zstd", lambda data: zstandard.ZstdCompressor().compress(data)),
    ])
    def test_a_known_coding_is_decoded_and_dropped(self, coding, pack):
        message = encoded(pack(b"HELLO"), coding)
        decompress(message, limits=HTTPLimits())

        assert message.body == b"HELLO"
        assert "Content-Encoding" not in message.headers
        assert not message.compressed

    def test_a_coding_name_folds_case(self):
        # §8.4.1 makes content codings case insensitive, so GZIP names the same coding.
        message = encoded(gzip.compress(b"HELLO"), "GZIP")
        decompress(message, limits=HTTPLimits())

        assert message.body == b"HELLO"
        assert "Content-Encoding" not in message.headers

    def test_an_unknown_coding_leaves_the_body_and_the_header_alone(self):
        """A body that was not decoded must not be labelled as if it had been.

        Removing Content-Encoding regardless hands the application an encoded body that
        every content inspection then reads as identity.
        """
        message = encoded(b"RAW", "compress")
        decompress(message, limits=HTTPLimits())

        assert message.body == b"RAW"
        assert message.headers.get("Content-Encoding") == "compress"
        assert message.compressed

    def test_an_unknown_coding_under_a_known_one_stops_the_decoding(self):
        # The codings are removed from the end, so the whole list survives an early stop.
        message = encoded(b"RAW", "gzip, compress")
        decompress(message, limits=HTTPLimits())

        assert message.body == b"RAW"
        assert message.headers.get("Content-Encoding") == "gzip, compress"

    def test_stacked_codings_are_decoded_in_reverse(self):
        message = encoded(gzip.compress(zlib.compress(b"HELLO")), "deflate, gzip")
        decompress(message, limits=HTTPLimits())

        assert message.body == b"HELLO"
        assert "Content-Encoding" not in message.headers

class TestDecodingLimits:
    def test_an_expanding_body_is_refused_at_the_limit(self):
        """A small body that expands by three orders of magnitude has to be stopped as it
        is produced. Decoding it first and measuring afterwards is the failure, not the check."""
        bomb = gzip.compress(b"\0" * 52428800)
        assert len(bomb) < 65536

        message = encoded(bomb, "gzip")

        with pytest.raises(HTTPError) as caught:
            decompress(message, limits=HTTPLimits(max_message_body_size=1048576))

        assert caught.value.code == 413

    def test_a_body_inside_the_limit_still_decodes(self):
        message = encoded(gzip.compress(b"\0" * 200000), "gzip")
        decompress(message, limits=HTTPLimits(max_message_body_size=1048576))

        assert len(message.body) == 200000

    @pytest.mark.parametrize("coding,pack", [
        ("br", brotlicffi.compress),
        ("zstd", lambda data: zstandard.ZstdCompressor().compress(data)),
        ("deflate", zlib.compress),
    ])
    def test_every_coding_honours_the_limit(self, coding, pack):
        message = encoded(pack(b"\0" * 4000000), coding)

        with pytest.raises(HTTPError):
            decompress(message, limits=HTTPLimits(max_message_body_size=65536))

class TestNegotiation:
    """RFC 9110 §12.5.3 ranks the codings by the weight the client gave them."""

    def build(self, accept_encoding: str) -> HTTPMessage:
        message = HTTPMessage(headers=HTTPHeaders(), body=b"x" * 4096)
        compress(message, accept_encoding, limits=HTTPLimits())

        return message

    def test_the_highest_qvalue_wins_over_the_server_order(self):
        # br sits ahead of gzip in the server preference, and the client says otherwise.
        assert self.build("gzip;q=1.0, br;q=0.1").headers.get("Content-Encoding") == "gzip"

    def test_the_server_order_only_breaks_a_tie(self):
        assert self.build("gzip, br").headers.get("Content-Encoding") == "br"

    def test_a_coding_at_q_zero_is_never_chosen(self):
        assert self.build("gzip;q=0, br").headers.get("Content-Encoding") == "br"

    def test_a_refused_identity_forces_a_coding(self):
        # §12.5.3: identity;q=0 says an unencoded body is unacceptable, so sending one is
        # answering with the single thing the client named as unacceptable.
        assert self.build("identity;q=0").headers.get("Content-Encoding") is not None

    def test_nothing_acceptable_leaves_the_body_alone(self):
        assert self.build("compress").headers.get("Content-Encoding") is None

    def test_a_compressed_response_varies_on_accept_encoding(self):
        # §12.5.5: the selected representation depends on a request header field.
        assert self.build("gzip").headers.get("Vary") == "Accept-Encoding"

    def test_vary_is_not_duplicated(self):
        message = HTTPMessage(headers=HTTPHeaders([("Vary", "Accept-Encoding")]), body=b"x" * 4096)
        compress(message, "gzip", limits=HTTPLimits())

        assert message.headers.values("Vary") == ["Accept-Encoding"]

class TestQualityValues:
    """RFC 9110 §12.4.2 writes a qvalue as 0 or 1 with at most three decimal digits."""

    @pytest.mark.parametrize("text,weight", [("0", 0.0), ("1", 1.0), ("0.5", 0.5), ("0.001", 0.001), ("1.000", 1.0)])
    def test_a_valid_qvalue_is_read(self, text, weight):
        assert AcceptEncoding.weight(text) == pytest.approx(weight)

    @pytest.mark.parametrize("text", ["2", "1.001", "0.0001", "-1", "abc", "0.5x", ""])
    def test_an_invalid_qvalue_is_refused(self, text):
        assert AcceptEncoding.weight(text) is None

    def test_an_entry_with_a_broken_qvalue_is_dropped_rather_than_refused(self):
        """Reading a malformed qvalue as 0 invents an explicit refusal, which is the
        strongest meaning the grammar has, from a value that in fact says nothing."""
        parsed = AcceptEncoding.parse("gzip;q=abc, br")

        assert parsed.quality("gzip") is None
        assert parsed.quality("br") == 1.0
