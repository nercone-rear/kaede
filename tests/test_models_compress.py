import gzip
import zlib
import pytest
import zstandard
import brotlicffi

from kaede.models import Request, Response, Headers


def _make_request(body=None, compression=True, **kwargs):
    r = Request(method="GET", target="/", body=body, compression=compression)
    for k, v in kwargs.items():
        r.headers.set(k.replace("_", "-"), v)
    return r


def _make_response(body=None, compression=True, content_type=None, **kwargs):
    r = Response(body=body, compression=compression, content_type=content_type)
    for k, v in kwargs.items():
        r.headers.set(k.replace("_", "-"), v)
    return r


class TestRequestCompress:
    async def test_zstd_compress(self):
        r = _make_request(body=b"hello world " * 100)
        await r.compress("zstd")
        assert r.headers.get("Content-Encoding") == "zstd"
        assert zstandard.ZstdDecompressor().decompress(r.body) == b"hello world " * 100

    async def test_br_compress(self):
        r = _make_request(body=b"hello world " * 100)
        await r.compress("br")
        assert r.headers.get("Content-Encoding") == "br"
        assert brotlicffi.decompress(r.body) == b"hello world " * 100

    async def test_gzip_compress(self):
        r = _make_request(body=b"hello world " * 100)
        await r.compress("gzip")
        assert r.headers.get("Content-Encoding") == "gzip"
        assert gzip.decompress(r.body) == b"hello world " * 100

    async def test_deflate_compress(self):
        r = _make_request(body=b"hello world " * 100)
        await r.compress("deflate")
        assert r.headers.get("Content-Encoding") == "deflate"
        assert zlib.decompress(r.body) == b"hello world " * 100

    async def test_no_body_skips(self):
        r = _make_request(body=None)
        await r.compress("zstd")
        assert "Content-Encoding" not in r.headers

    async def test_compression_false_skips(self):
        r = _make_request(body=b"data", compression=False)
        await r.compress("zstd")
        assert "Content-Encoding" not in r.headers

    async def test_already_content_encoded_skips(self):
        r = _make_request(body=b"data")
        r.headers.set("Content-Encoding", "gzip")
        original_body = r.body
        await r.compress("zstd")
        assert r.headers.get("Content-Encoding") == "gzip"
        assert r.body is original_body

    async def test_image_content_type_skips(self):
        r = _make_request(body=b"fake image bytes")
        r.headers.set("Content-Type", "image/jpeg")
        await r.compress("gzip")
        assert "Content-Encoding" not in r.headers

    async def test_svg_not_skipped(self):
        r = _make_request(body=b"<svg></svg>")
        r.headers.set("Content-Type", "image/svg+xml")
        await r.compress("gzip")
        assert r.headers.get("Content-Encoding") == "gzip"

    async def test_video_content_type_skips(self):
        r = _make_request(body=b"fake video")
        r.headers.set("Content-Type", "video/mp4")
        await r.compress("gzip")
        assert "Content-Encoding" not in r.headers

    async def test_audio_content_type_skips(self):
        r = _make_request(body=b"fake audio")
        r.headers.set("Content-Type", "audio/mpeg")
        await r.compress("gzip")
        assert "Content-Encoding" not in r.headers

    async def test_already_compressed_type_skips(self):
        r = _make_request(body=b"data")
        r.headers.set("Content-Type", "application/gzip")
        await r.compress("zstd")
        assert "Content-Encoding" not in r.headers

    async def test_pdf_skips(self):
        r = _make_request(body=b"%PDF-1.4")
        r.headers.set("Content-Type", "application/pdf")
        await r.compress("gzip")
        assert "Content-Encoding" not in r.headers

    async def test_content_encoding_header_set(self):
        r = _make_request(body=b"x" * 1000)
        await r.compress("zstd")
        assert r.headers.get("Content-Encoding") == "zstd"

    async def test_body_modified_in_place(self):
        original = b"x" * 1000
        r = _make_request(body=original)
        await r.compress("zstd")
        assert r.body != original


class TestRequestDecompress:
    def test_zstd_decompress(self):
        original = b"hello world"
        compressed = zstandard.ZstdCompressor().compress(original)
        r = _make_request()
        r.body = None
        r.compressed = compressed
        r.decompress("zstd")
        assert r.body == original

    def test_br_decompress(self):
        original = b"hello world"
        compressed = brotlicffi.compress(original)
        r = _make_request()
        r.body = None
        r.compressed = compressed
        r.decompress("br")
        assert r.body == original

    def test_gzip_decompress(self):
        original = b"hello world"
        compressed = gzip.compress(original)
        r = _make_request()
        r.body = None
        r.compressed = compressed
        r.decompress("gzip")
        assert r.body == original

    def test_deflate_decompress(self):
        original = b"hello world"
        compressed = zlib.compress(original)
        r = _make_request()
        r.body = None
        r.compressed = compressed
        r.decompress("deflate")
        assert r.body == original

    def test_deflate_raw_fallback(self):
        original = b"hello world"
        compressed = zlib.compress(original, wbits=-zlib.MAX_WBITS)
        r = _make_request()
        r.body = None
        r.compressed = compressed
        r.decompress("deflate")
        assert r.body == original

    def test_compression_false_skips(self):
        original = b"data"
        r = _make_request()
        r.compression = False
        r.body = None
        r.compressed = original
        r.decompress("gzip")
        assert r.body is None

    def test_body_not_none_skips(self):
        r = _make_request(body=b"existing")
        r.compressed = b"compressed"
        r.decompress("gzip")
        assert r.body == b"existing"

    def test_compressed_none_skips(self):
        r = _make_request()
        r.body = None
        r.compressed = None
        r.decompress("gzip")
        assert r.body is None

    def test_uses_header_encoding_if_no_arg(self):
        original = b"hello"
        compressed = gzip.compress(original)
        r = _make_request()
        r.body = None
        r.compressed = compressed
        r.headers.set("Content-Encoding", "gzip")
        r.decompress()
        assert r.body == original


class TestResponseCompress:
    async def test_zstd_wins_when_all_equal_q(self):
        r = _make_response(body=b"data " * 500)
        await r.compress({"zstd": 1.0, "br": 1.0, "gzip": 1.0})
        assert r.headers.get("Content-Encoding") == "zstd"

    async def test_br_over_gzip_when_equal_q(self):
        r = _make_response(body=b"data " * 500)
        await r.compress({"br": 1.0, "gzip": 1.0})
        assert r.headers.get("Content-Encoding") == "br"

    async def test_q_value_selects_encoding(self):
        r = _make_response(body=b"data " * 500)
        await r.compress({"gzip": 0.9, "br": 0.5})
        assert r.headers.get("Content-Encoding") == "gzip"

    async def test_q_zero_rejected(self):
        r = _make_response(body=b"data " * 500)
        await r.compress({"gzip": 0.0})
        assert "Content-Encoding" not in r.headers

    async def test_wildcard_accepted(self):
        r = _make_response(body=b"data " * 500)
        await r.compress({"*": 1.0})
        assert r.headers.get("Content-Encoding") is not None

    async def test_vary_set(self):
        r = _make_response(body=b"data " * 500)
        await r.compress({"gzip": 1.0})
        vary = r.headers.get("Vary") or ""
        assert "Accept-Encoding" in vary

    async def test_no_body_skips(self):
        r = _make_response(body=None)
        await r.compress({"gzip": 1.0})
        assert "Content-Encoding" not in r.headers

    async def test_compression_false_skips(self):
        r = _make_response(body=b"data", compression=False)
        await r.compress({"gzip": 1.0})
        assert "Content-Encoding" not in r.headers

    async def test_empty_encodings_skips(self):
        r = _make_response(body=b"data " * 500)
        await r.compress({})
        assert "Content-Encoding" not in r.headers

    async def test_already_content_encoded_skips(self):
        r = _make_response(body=b"data")
        r.headers.set("Content-Encoding", "gzip")
        await r.compress({"zstd": 1.0})
        assert r.headers.get("Content-Encoding") == "gzip"

    async def test_image_content_type_skips(self):
        r = _make_response(body=b"fake jpg", content_type=None)
        r.headers.set("Content-Type", "image/png")
        await r.compress({"gzip": 1.0})
        assert "Content-Encoding" not in r.headers

    async def test_svg_is_compressed(self):
        r = _make_response(body=b"<svg></svg>")
        r.headers.set("Content-Type", "image/svg+xml")
        await r.compress({"gzip": 1.0})
        assert r.headers.get("Content-Encoding") == "gzip"

    async def test_zstd_compress_decompress_roundtrip(self):
        original = b"hello world " * 1000
        r = _make_response(body=original)
        await r.compress({"zstd": 1.0})
        assert r.headers.get("Content-Encoding") == "zstd"
        decompressed = zstandard.ZstdDecompressor().decompress(r.body)
        assert decompressed == original

    async def test_streaming_body_gets_encoding_header(self):
        async def gen():
            yield b"chunk " * 100

        r = _make_response(body=gen())
        await r.compress({"gzip": 1.0})
        # streaming body with gzip
        assert r.headers.get("Content-Encoding") == "gzip"
        assert r.is_streaming

    async def test_streaming_body_no_accepted_skips(self):
        async def gen():
            yield b"chunk"

        r = _make_response(body=gen())
        await r.compress({})
        assert "Content-Encoding" not in r.headers


class TestResponseDecompress:
    def test_zstd_bytes_decompress(self):
        original = b"hello world"
        compressed = zstandard.ZstdCompressor().compress(original)
        r = _make_response()
        r.body = None
        r.compressed = compressed
        r.compression = True
        r.decompress("zstd")
        assert r.body == original

    def test_br_bytes_decompress(self):
        original = b"hello"
        compressed = brotlicffi.compress(original)
        r = _make_response()
        r.body = None
        r.compressed = compressed
        r.compression = True
        r.decompress("br")
        assert r.body == original

    def test_gzip_bytes_decompress(self):
        original = b"hello"
        compressed = gzip.compress(original)
        r = _make_response()
        r.body = None
        r.compressed = compressed
        r.compression = True
        r.decompress("gzip")
        assert r.body == original

    def test_x_gzip_alias(self):
        original = b"hello"
        compressed = gzip.compress(original)
        r = _make_response()
        r.body = None
        r.compressed = compressed
        r.compression = True
        r.decompress("x-gzip")
        assert r.body == original

    def test_deflate_bytes_decompress(self):
        original = b"hello"
        compressed = zlib.compress(original)
        r = _make_response()
        r.body = None
        r.compressed = compressed
        r.compression = True
        r.decompress("deflate")
        assert r.body == original

    def test_compression_false_skips(self):
        r = _make_response()
        r.compression = False
        r.body = None
        r.compressed = b"data"
        r.decompress("gzip")
        assert r.body is None

    def test_body_not_none_skips(self):
        r = _make_response(body=b"existing")
        r.compressed = b"compressed"
        r.compression = True
        r.decompress("gzip")
        assert r.body == b"existing"

    def test_uses_header_encoding_if_no_arg(self):
        original = b"hello"
        compressed = gzip.compress(original)
        r = _make_response()
        r.body = None
        r.compressed = compressed
        r.compression = True
        r.headers.set("Content-Encoding", "gzip")
        r.decompress()
        assert r.body == original

    async def test_streaming_zstd_decompress(self):
        original = b"hello world " * 100
        compressed = zstandard.ZstdCompressor().compress(original)

        async def gen():
            yield compressed[:len(compressed) // 2]
            yield compressed[len(compressed) // 2:]

        r = _make_response()
        r.body = None
        r.compressed = gen()
        r.compression = True
        r.decompress("zstd")
        assert r.body is not None
        # Consume the streaming body
        result = b""
        async for chunk in r.body:
            result += chunk
        assert result == original

    async def test_streaming_gzip_decompress(self):
        original = b"hello world " * 100
        compressed = gzip.compress(original)

        async def gen():
            yield compressed

        r = _make_response()
        r.body = None
        r.compressed = gen()
        r.compression = True
        r.decompress("gzip")
        assert r.body is not None
        result = b""
        async for chunk in r.body:
            result += chunk
        assert result == original


class TestResponseMinify:
    async def test_minify_html(self):
        r = Response(body=b"<html>  <body>  hello  </body>  </html>", minification=True, content_type="text/html")
        r.headers.set("Content-Type", "text/html")
        await r.minify(html=True)
        assert len(r.body) < len(b"<html>  <body>  hello  </body>  </html>")

    async def test_minify_css(self):
        css = b"body   {   color:   red;   margin:  0;  }"
        r = Response(body=css, minification=True)
        r.headers.set("Content-Type", "text/css")
        await r.minify(css=True)
        assert len(r.body) < len(css)

    async def test_minify_js(self):
        js = b"function   foo()   {   return   1;   }"
        r = Response(body=js, minification=True)
        r.headers.set("Content-Type", "text/javascript")
        await r.minify(js=True)
        assert len(r.body) < len(js)

    async def test_minification_false_skips(self):
        original = b"<html>  <body>hello</body>  </html>"
        r = Response(body=original, minification=False)
        r.headers.set("Content-Type", "text/html")
        await r.minify(html=True)
        assert r.body == original

    async def test_no_body_skips(self):
        r = Response(body=None, minification=True)
        await r.minify(html=True)
        assert r.body is None

    async def test_streaming_body_skips(self):
        async def gen():
            yield b"<html></html>"

        r = Response(body=gen(), minification=True)
        r.headers.set("Content-Type", "text/html")
        await r.minify(html=True)
        assert r.is_streaming

    async def test_minify_wrong_flag_skips(self):
        # html=True but content type is text/css → no minification
        original = b"body   {   margin: 0;   }"
        r = Response(body=original, minification=True)
        r.headers.set("Content-Type", "text/css")
        await r.minify(html=True)
        assert r.body == original

    async def test_exception_during_minify_is_swallowed(self):
        # Invalid HTML-like data; minify_html may fail; exception should be caught
        r = Response(body=b"\xff\xfe invalid utf-8", minification=True)
        r.headers.set("Content-Type", "text/html")
        await r.minify(html=True)
        # Should not raise; body may or may not be modified
