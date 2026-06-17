import gzip
import zlib
import pytest
import zstandard
import brotlicffi

from kaede.models import Request, Response
from kaede.process import parse_accept_encoding, parse_range, is_compressible, compress_response, minimize_response, compress_request, decode_content_encoding, decompress_once, StreamDecompressor

class TestParseAcceptEncoding:
    def test_empty(self):
        assert parse_accept_encoding("") == {}

    def test_single(self):
        result = parse_accept_encoding("gzip")
        assert result == {"gzip": 1.0}

    def test_multiple(self):
        result = parse_accept_encoding("gzip, br, zstd")
        assert result["gzip"] == 1.0
        assert result["br"] == 1.0
        assert result["zstd"] == 1.0

    def test_q_value(self):
        result = parse_accept_encoding("gzip;q=0.8, br;q=1.0, zstd;q=0.5")
        assert result["gzip"] == pytest.approx(0.8)
        assert result["br"] == pytest.approx(1.0)
        assert result["zstd"] == pytest.approx(0.5)

    def test_wildcard(self):
        result = parse_accept_encoding("*")
        assert result["*"] == 1.0

    def test_q_zero(self):
        result = parse_accept_encoding("gzip;q=0")
        assert result["gzip"] == 0.0

    def test_invalid_q_defaults_to_zero(self):
        result = parse_accept_encoding("gzip;q=bad")
        assert result["gzip"] == 0.0

    def test_whitespace(self):
        result = parse_accept_encoding("  gzip  ,  br  ")
        assert "gzip" in result
        assert "br" in result

class TestParseRange:
    def test_basic_range(self):
        assert parse_range("bytes=0-99", 1000) == (0, 99)

    def test_open_ended(self):
        assert parse_range("bytes=500-", 1000) == (500, 999)

    def test_suffix(self):
        assert parse_range("bytes=-200", 1000) == (800, 999)

    def test_clamp_end(self):
        assert parse_range("bytes=0-9999", 100) == (0, 99)

    def test_start_beyond_total(self):
        assert parse_range("bytes=200-300", 100) is None

    def test_start_greater_than_end(self):
        assert parse_range("bytes=50-20", 100) is None

    def test_not_bytes(self):
        assert parse_range("tokens=0-100", 1000) is None

    def test_invalid_spec(self):
        assert parse_range("bytes=abc-def", 1000) is None

    def test_suffix_zero(self):
        assert parse_range("bytes=-0", 100) is None

    def test_multiple_ranges_uses_first(self):
        result = parse_range("bytes=0-10, 20-30", 1000)
        assert result == (0, 10)

class TestIsCompressible:
    def test_text_html(self):
        assert is_compressible("text/html") is True

    def test_application_json(self):
        assert is_compressible("application/json") is True

    def test_svg(self):
        assert is_compressible("image/svg+xml") is True

    def test_jpeg_not_compressible(self):
        assert is_compressible("image/jpeg") is False

    def test_png_not_compressible(self):
        assert is_compressible("image/png") is False

    def test_zip_not_compressible(self):
        assert is_compressible("application/zip") is False

    def test_woff2_not_compressible(self):
        assert is_compressible("font/woff2") is False

    def test_none_content_type(self):
        assert is_compressible(None) is True

    def test_with_charset(self):
        assert is_compressible("text/html; charset=utf-8") is True

    def test_video(self):
        assert is_compressible("video/mp4") is False

class TestCompressResponse:
    @pytest.mark.asyncio
    async def test_gzip_compression(self):
        body = b"hello world" * 100
        resp = Response(body=body, content_type="text/plain")
        encodings = {"gzip": 1.0}
        compressed = await compress_response(resp, encodings)
        assert compressed is not None
        assert gzip.decompress(compressed) == body

    @pytest.mark.asyncio
    async def test_zstd_preferred_over_gzip(self):
        body = b"test data" * 100
        resp = Response(body=body, content_type="text/plain")
        encodings = {"gzip": 0.8, "zstd": 1.0}
        await compress_response(resp, encodings)
        assert resp.headers.get("Content-Encoding") == "zstd"

    @pytest.mark.asyncio
    async def test_no_compression_if_disabled(self):
        resp = Response(body=b"hello", compression=False)
        result = await compress_response(resp, {"gzip": 1.0})
        assert result is None

    @pytest.mark.asyncio
    async def test_no_compression_if_no_encodings(self):
        resp = Response(body=b"hello")
        result = await compress_response(resp, {})
        assert result is None

    @pytest.mark.asyncio
    async def test_no_compression_if_already_encoded(self):
        resp = Response(body=b"hello")
        resp.headers.set("Content-Encoding", "gzip")
        result = await compress_response(resp, {"gzip": 1.0})
        assert result is None

    @pytest.mark.asyncio
    async def test_no_compression_for_image(self):
        resp = Response(body=b"\xff\xd8\xff", content_type="image/jpeg")
        result = await compress_response(resp, {"gzip": 1.0})
        assert result is None

    @pytest.mark.asyncio
    async def test_vary_header_added(self):
        body = b"data" * 100
        resp = Response(body=body, content_type="text/plain")
        await compress_response(resp, {"gzip": 1.0})
        assert "Accept-Encoding" in resp.headers.get("Vary", "")

    @pytest.mark.asyncio
    async def test_q_zero_encoding_skipped(self):
        body = b"data" * 100
        resp = Response(body=body, content_type="text/plain")
        result = await compress_response(resp, {"gzip": 0.0})
        assert result is None

class TestMinimizeResponse:
    @pytest.mark.asyncio
    async def test_minimizes_html(self):
        html = b"<html>  <body>  <p>Hello</p>  </body>  </html>"
        resp = Response(body=html, content_type="text/html", minification=True)
        result = await minimize_response(resp)
        assert result is not None
        assert len(result) <= len(html)

    @pytest.mark.asyncio
    async def test_no_minification_if_disabled(self):
        html = b"<html><body><p>Hello</p></body></html>"
        resp = Response(body=html, content_type="text/html", minification=False)
        result = await minimize_response(resp)
        assert result is None

    @pytest.mark.asyncio
    async def test_no_minification_for_non_body(self):
        resp = Response(body=None, content_type="text/html", minification=True)
        result = await minimize_response(resp)
        assert result is None

    @pytest.mark.asyncio
    async def test_minimizes_css(self):
        css = b"body   {   color:   red;   margin:  0;  }"
        resp = Response(body=css, content_type="text/css", minification=True)
        result = await minimize_response(resp)
        assert result is not None

    @pytest.mark.asyncio
    async def test_minimizes_js(self):
        js = b"function foo()   {   return   1;   }"
        resp = Response(body=js, content_type="text/javascript", minification=True)
        result = await minimize_response(resp)
        assert result is not None

class TestCompressRequest:
    @pytest.mark.asyncio
    async def test_gzip_compress(self):
        from kaede.api.client import Config as ClientConfig
        config = ClientConfig()
        body = b"hello world" * 100
        req = Request(method="POST", target="/", body=body)
        req.headers.set("Content-Encoding", "gzip")
        result = await compress_request(req, config)
        assert result is not None
        assert gzip.decompress(result) == body

    @pytest.mark.asyncio
    async def test_no_body_returns_none(self):
        from kaede.api.client import Config as ClientConfig
        config = ClientConfig()
        req = Request(method="GET", target="/")
        result = await compress_request(req, config)
        assert result is None

    @pytest.mark.asyncio
    async def test_no_encoding_header_returns_none(self):
        from kaede.api.client import Config as ClientConfig
        config = ClientConfig()
        req = Request(method="POST", target="/", body=b"hello")
        result = await compress_request(req, config)
        assert result is None

class TestDecompressOnce:
    def test_identity(self):
        assert decompress_once(b"hello", "identity", None) == b"hello"

    def test_gzip(self):
        compressed = gzip.compress(b"hello world")
        assert decompress_once(compressed, "gzip", None) == b"hello world"

    def test_deflate(self):
        compressed = zlib.compress(b"hello world")
        assert decompress_once(compressed, "deflate", None) == b"hello world"

    def test_brotli(self):
        compressed = brotlicffi.compress(b"hello world")
        assert decompress_once(compressed, "br", None) == b"hello world"

    def test_zstd(self):
        compressed = zstandard.ZstdCompressor().compress(b"hello world")
        assert decompress_once(compressed, "zstd", None) == b"hello world"

    def test_unsupported_encoding(self):
        with pytest.raises(ValueError, match="unsupported Content-Encoding"):
            decompress_once(b"data", "xz", None)

    def test_max_size_exceeded_gzip(self):
        compressed = gzip.compress(b"x" * 1000)
        with pytest.raises(ValueError, match="max_body_size"):
            decompress_once(compressed, "gzip", 500)

    def test_max_size_exceeded_brotli(self):
        compressed = brotlicffi.compress(b"x" * 1000)
        with pytest.raises(ValueError, match="max_body_size"):
            decompress_once(compressed, "br", 500)

    def test_max_size_exceeded_zstd(self):
        compressed = zstandard.ZstdCompressor().compress(b"x" * 1000)
        with pytest.raises(ValueError, match="max_body_size"):
            decompress_once(compressed, "zstd", 500)

class TestStreamDecompressor:
    def test_gzip_stream(self):
        raw = b"hello world" * 10
        compressed = gzip.compress(raw)
        decompressor = StreamDecompressor("gzip")
        result = decompressor.feed(compressed) + decompressor.flush()
        assert result == raw

    def test_identity_passthrough(self):
        decompressor = StreamDecompressor("identity")
        result = decompressor.feed(b"hello")
        assert result == b"hello"

    def test_zstd_stream(self):
        raw = b"test data" * 50
        compressed = zstandard.ZstdCompressor().compress(raw)
        decompressor = StreamDecompressor("zstd")
        result = decompressor.feed(compressed)
        assert result == raw

    def test_empty_feed(self):
        decompressor = StreamDecompressor("gzip")
        assert decompressor.feed(b"") == b""

class TestDecodeContentEncoding:
    def test_single_gzip(self):
        compressed = gzip.compress(b"hello")
        assert decode_content_encoding(compressed, ["gzip"], None) == b"hello"

    def test_chained_encodings(self):
        data = b"hello world"
        gz = gzip.compress(data)
        br = brotlicffi.compress(gz)
        result = decode_content_encoding(br, ["gzip", "br"], None)
        assert result == data
