"""
Request / Response model conformance tests.

RFC 6455 §4.2.1 — WebSocket upgrade validation
RFC 9110 §8.4   — Content-Encoding (compression / decompression)
"""
from __future__ import annotations

import asyncio
import base64
import gzip
import os
import pathlib
import zlib
import ipaddress

import brotlicffi
import pytest
import zstandard

from kaede.models import Headers, Request, Response

CLIENT = (ipaddress.IPv4Address("127.0.0.1"), 12345)

# RFC 6455 §4.2.1: Server-side WebSocket upgrade validation

def ws_key() -> str:
    """Generate a valid 16-byte random Sec-WebSocket-Key."""
    return base64.b64encode(os.urandom(16)).decode()

def ws_request(**overrides) -> Request:
    """Build a minimal valid WebSocket upgrade Request."""
    key = ws_key()
    headers = Headers({
        "Host": "example.com",
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Key": key,
        "Sec-WebSocket-Version": "13",
    })
    kwargs: dict = {"method": "GET", "target": "/ws", "headers": headers}
    kwargs.update(overrides)
    return Request(**kwargs)

class TestRequestIsWebSocketUpgrade:
    """RFC 6455 §4.2.1: A valid WebSocket upgrade request must satisfy all conditions."""

    def test_valid_upgrade_is_true(self):
        assert ws_request().is_websocket_upgrade is True

    def test_method_must_be_get(self):
        """RFC 6455 §4.2.1: The method MUST be GET."""
        assert ws_request(method="POST").is_websocket_upgrade is False

    def test_upgrade_header_must_be_websocket(self):
        """RFC 6455 §4.2.1: Upgrade field must equal 'websocket'."""
        req = Request(
            method="GET",
            target="/ws",
            headers=Headers({
                "Host": "example.com",
                "Upgrade": "http/2",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": ws_key(),
                "Sec-WebSocket-Version": "13",
            }),
        )
        assert req.is_websocket_upgrade is False

    def test_upgrade_case_insensitive(self):
        """RFC 6455 §4.2.1: 'websocket' comparison is case-insensitive."""
        req = Request(
            method="GET",
            target="/ws",
            headers=Headers({
                "Host": "example.com",
                "Upgrade": "WebSocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": ws_key(),
                "Sec-WebSocket-Version": "13",
            }),
        )
        assert req.is_websocket_upgrade is True

    def test_connection_must_include_upgrade_token(self):
        """RFC 6455 §4.2.1: Connection header must contain the 'Upgrade' token."""
        req = Request(
            method="GET",
            target="/ws",
            headers=Headers({
                "Host": "example.com",
                "Upgrade": "websocket",
                "Connection": "keep-alive",
                "Sec-WebSocket-Key": ws_key(),
                "Sec-WebSocket-Version": "13",
            }),
        )
        assert req.is_websocket_upgrade is False

    def test_connection_with_multiple_tokens_accepted(self):
        """Connection header may contain multiple tokens; 'upgrade' among them is valid."""
        req = Request(
            method="GET",
            target="/ws",
            headers=Headers({
                "Host": "example.com",
                "Upgrade": "websocket",
                "Connection": "keep-alive, Upgrade",
                "Sec-WebSocket-Key": ws_key(),
                "Sec-WebSocket-Version": "13",
            }),
        )
        assert req.is_websocket_upgrade is True

    def test_missing_websocket_key_rejected(self):
        """RFC 6455 §4.2.1: Sec-WebSocket-Key is mandatory."""
        req = Request(
            method="GET",
            target="/ws",
            headers=Headers({
                "Host": "example.com",
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Version": "13",
            }),
        )
        assert req.is_websocket_upgrade is False

    def test_key_must_decode_to_exactly_16_bytes(self):
        """RFC 6455 §4.2.1: Sec-WebSocket-Key must be base64 of exactly 16 bytes."""
        short_key = base64.b64encode(b"tooshort").decode()  # only 8 bytes
        req = Request(
            method="GET",
            target="/ws",
            headers=Headers({
                "Host": "example.com",
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": short_key,
                "Sec-WebSocket-Version": "13",
            }),
        )
        assert req.is_websocket_upgrade is False

    def test_invalid_base64_key_rejected(self):
        """RFC 6455 §4.2.1: Key must be valid base64."""
        req = Request(
            method="GET",
            target="/ws",
            headers=Headers({
                "Host": "example.com",
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": "not!!valid!!base64",
                "Sec-WebSocket-Version": "13",
            }),
        )
        assert req.is_websocket_upgrade is False

    def test_websocket_version_must_be_13(self):
        """RFC 6455 §4.2.1: Sec-WebSocket-Version must be '13'."""
        req = Request(
            method="GET",
            target="/ws",
            headers=Headers({
                "Host": "example.com",
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": ws_key(),
                "Sec-WebSocket-Version": "8",
            }),
        )
        assert req.is_websocket_upgrade is False

    def test_missing_version_header_rejected(self):
        req = Request(
            method="GET",
            target="/ws",
            headers=Headers({
                "Host": "example.com",
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": ws_key(),
            }),
        )
        assert req.is_websocket_upgrade is False

# RFC 9110 §6.3 / §6.4: Response body presence

class TestResponseProperties:
    def test_has_real_body_with_bytes(self):
        assert Response(body=b"hello").has_real_body is True

    def test_has_real_body_with_none(self):
        assert Response(body=None).has_real_body is False

    def test_has_real_body_with_path(self):
        """A PathLike body is a file reference, not raw bytes."""
        assert Response(body=pathlib.Path("/tmp/x")).has_real_body is False

    def test_is_streaming_with_async_generator(self):
        async def gen():
            yield b"chunk"

        assert Response(body=gen()).is_streaming is True

    def test_is_streaming_with_bytes(self):
        assert Response(body=b"data").is_streaming is False

    def test_is_streaming_with_none(self):
        assert Response(body=None).is_streaming is False

# RFC 9110 §8.4 / RFC 7231 §5.3.4: Response compression

def run(coro):
    return asyncio.run(coro)

class TestResponseCompressBytes:
    """Response.compress() selects the best encoding from the Accept-Encoding map."""

    def test_zstd_applied(self):
        async def go():
            r = Response(body=b"hello world" * 100, content_type="text/plain")
            await r.compress({"zstd": 1.0})
            assert r.headers.get("Content-Encoding") == "zstd"
            assert zstandard.ZstdDecompressor().decompress(r.body) == b"hello world" * 100

        run(go())

    def test_br_applied(self):
        async def go():
            r = Response(body=b"brotli" * 100, content_type="text/plain")
            await r.compress({"br": 1.0})
            assert r.headers.get("Content-Encoding") == "br"
            assert brotlicffi.decompress(r.body) == b"brotli" * 100

        run(go())

    def test_gzip_applied(self):
        async def go():
            r = Response(body=b"gzip data" * 100, content_type="text/html")
            await r.compress({"gzip": 1.0})
            assert r.headers.get("Content-Encoding") == "gzip"
            assert gzip.decompress(r.body) == b"gzip data" * 100

        run(go())

    def test_deflate_applied(self):
        async def go():
            r = Response(body=b"deflate" * 100, content_type="text/plain")
            await r.compress({"deflate": 1.0})
            assert r.headers.get("Content-Encoding") == "deflate"
            assert zlib.decompress(r.body) == b"deflate" * 100

        run(go())

    def test_vary_accept_encoding_added(self):
        """RFC 7231 §7.1.4: Vary must include Accept-Encoding after compression."""

        async def go():
            r = Response(body=b"x" * 100, content_type="text/plain")
            await r.compress({"gzip": 1.0})
            assert "Accept-Encoding" in (r.headers.get("Vary") or "")

        run(go())

    def test_existing_content_encoding_skipped(self):
        """If Content-Encoding is already set, compression must not be applied again."""

        async def go():
            r = Response(
                body=b"x" * 100,
                content_type="text/plain",
                headers=Headers({"Content-Encoding": "br"}),
            )
            original = r.body
            await r.compress({"gzip": 1.0})
            assert r.body is original
            assert r.headers.get("Content-Encoding") == "br"

        run(go())

    def test_compression_false_skips(self):
        async def go():
            r = Response(body=b"x" * 100, content_type="text/plain", compression=False)
            await r.compress({"gzip": 1.0})
            assert "Content-Encoding" not in r.headers

        run(go())

    def test_empty_accepted_encodings_skips(self):
        async def go():
            r = Response(body=b"x" * 100, content_type="text/plain")
            await r.compress({})
            assert "Content-Encoding" not in r.headers

        run(go())

    def test_q_zero_means_not_acceptable(self):
        """RFC 7231 §5.3.1: q=0 means the encoding is explicitly not acceptable."""

        async def go():
            r = Response(body=b"x" * 100, content_type="text/plain")
            await r.compress({"gzip": 0.0})
            assert "Content-Encoding" not in r.headers

        run(go())

    def test_wildcard_star_matches_any_encoding(self):
        """RFC 7231 §5.3.4: '*' in Accept-Encoding matches any supported encoding."""

        async def go():
            r = Response(body=b"x" * 100, content_type="text/plain")
            await r.compress({"*": 1.0})
            assert "Content-Encoding" in r.headers

        run(go())

    def test_image_jpeg_not_compressed(self):
        """Binary media types must not be re-compressed."""

        async def go():
            r = Response(body=b"\xff\xd8\xff" + b"x" * 100, content_type="image/jpeg")
            await r.compress({"gzip": 1.0})
            assert "Content-Encoding" not in r.headers

        run(go())

    def test_image_svg_xml_is_compressed(self):
        """image/svg+xml is text-based and should be compressed."""

        async def go():
            r = Response(body=b"<svg>" * 100, content_type="image/svg+xml")
            await r.compress({"gzip": 1.0})
            assert "Content-Encoding" in r.headers

        run(go())

    def test_application_zip_not_compressed(self):
        """Already-compressed container formats must not be re-compressed."""

        async def go():
            r = Response(body=b"PK\x03\x04" + b"x" * 100, content_type="application/zip")
            await r.compress({"gzip": 1.0})
            assert "Content-Encoding" not in r.headers

        run(go())

    def test_zstd_preferred_over_br_at_equal_q(self):
        """When zstd and br have equal quality, zstd has higher built-in priority."""

        async def go():
            r = Response(body=b"x" * 100, content_type="text/plain")
            await r.compress({"zstd": 1.0, "br": 1.0})
            assert r.headers.get("Content-Encoding") == "zstd"

        run(go())

    def test_br_preferred_over_gzip_at_equal_q(self):
        async def go():
            r = Response(body=b"x" * 100, content_type="text/plain")
            await r.compress({"br": 1.0, "gzip": 1.0})
            assert r.headers.get("Content-Encoding") == "br"

        run(go())

    def test_higher_q_wins_over_default_priority(self):
        """A higher q-value must take precedence over the built-in encoding priority."""

        async def go():
            r = Response(body=b"x" * 100, content_type="text/plain")
            await r.compress({"gzip": 1.0, "zstd": 0.5})
            assert r.headers.get("Content-Encoding") == "gzip"

        run(go())

    def test_body_none_skips_compression(self):
        async def go():
            r = Response(body=None, content_type="text/plain")
            await r.compress({"gzip": 1.0})
            assert "Content-Encoding" not in r.headers

        run(go())

# RFC 9110 §8.4: Response decompression

class TestResponseDecompressBytes:
    def _make(self, data: bytes, encoding: str) -> Response:
        return Response(
            compressed=data,
            headers=Headers({"Content-Encoding": encoding}),
        )

    def test_zstd_roundtrip(self):
        data = b"hello world" * 100
        r = self._make(zstandard.ZstdCompressor().compress(data), "zstd")
        r.decompress()
        assert r.body == data

    def test_br_roundtrip(self):
        data = b"brotli data" * 50
        r = self._make(brotlicffi.compress(data), "br")
        r.decompress()
        assert r.body == data

    def test_gzip_roundtrip(self):
        data = b"gzip data" * 50
        r = self._make(gzip.compress(data), "gzip")
        r.decompress()
        assert r.body == data

    def test_x_gzip_alias_for_gzip(self):
        """x-gzip is a deprecated alias for gzip and must be supported."""
        data = b"x-gzip data" * 50
        r = self._make(gzip.compress(data), "x-gzip")
        r.decompress()
        assert r.body == data

    def test_deflate_with_zlib_header(self):
        """RFC 7230: 'deflate' may be zlib-wrapped (RFC 1950) deflate."""
        data = b"deflate data" * 50
        r = self._make(zlib.compress(data), "deflate")
        r.decompress()
        assert r.body == data

    def test_deflate_raw_without_zlib_header(self):
        """Some implementations send raw deflate (RFC 1951) without the zlib wrapper."""
        data = b"raw deflate" * 50
        co = zlib.compressobj(wbits=-zlib.MAX_WBITS)
        compressed = co.compress(data) + co.flush()
        r = self._make(compressed, "deflate")
        r.decompress()
        assert r.body == data

    def test_zstd_max_size_enforced(self):
        data = b"x" * 1000
        r = self._make(zstandard.ZstdCompressor().compress(data), "zstd")
        with pytest.raises(ValueError):
            r.decompress(max_size=100)

    def test_br_max_size_enforced(self):
        data = b"x" * 1000
        r = self._make(brotlicffi.compress(data), "br")
        with pytest.raises(ValueError):
            r.decompress(max_size=100)

    def test_gzip_max_size_enforced(self):
        data = b"x" * 1000
        r = self._make(gzip.compress(data), "gzip")
        with pytest.raises(ValueError):
            r.decompress(max_size=100)

    def test_deflate_max_size_enforced(self):
        data = b"x" * 1000
        r = self._make(zlib.compress(data), "deflate")
        with pytest.raises(ValueError):
            r.decompress(max_size=100)

    def test_max_size_exactly_at_limit_succeeds(self):
        data = b"x" * 100
        r = self._make(gzip.compress(data), "gzip")
        r.decompress(max_size=100)
        assert r.body == data

    def test_compression_false_skips_decompression(self):
        r = Response(
            compressed=gzip.compress(b"hello"),
            compression=False,
            headers=Headers({"Content-Encoding": "gzip"}),
        )
        r.decompress()
        assert r.body is None

    def test_body_already_set_skips_decompression(self):
        existing = b"pre-existing"
        r = Response(
            body=existing,
            compressed=gzip.compress(b"other"),
            headers=Headers({"Content-Encoding": "gzip"}),
        )
        r.decompress()
        assert r.body is existing

    def test_no_compressed_data_is_no_op(self):
        r = Response(compressed=None, headers=Headers({"Content-Encoding": "gzip"}))
        r.decompress()
        assert r.body is None

    def test_explicit_encoding_overrides_header(self):
        """An explicit encoding parameter takes precedence over Content-Encoding."""
        data = b"data" * 50
        r = Response(
            compressed=gzip.compress(data),
            headers=Headers({"Content-Encoding": "br"}),
        )
        r.decompress(encoding="gzip")
        assert r.body == data

# RFC 9110 §8.4: Request body compression (outgoing)

class TestRequestCompressAsync:
    """Request.compress() for outgoing client-side request bodies."""

    def test_zstd_applied(self):
        async def go():
            r = Request(
                method="POST",
                target="/",
                headers=Headers({"Host": "example.com"}),
                body=b"hello" * 100,
                content_type="text/plain",
            )
            await r.compress("zstd")
            assert r.headers.get("Content-Encoding") == "zstd"
            assert zstandard.ZstdDecompressor().decompress(r.body) == b"hello" * 100

        run(go())

    def test_br_applied(self):
        async def go():
            r = Request(
                method="POST",
                target="/",
                headers=Headers({"Host": "example.com"}),
                body=b"hello" * 100,
                content_type="text/plain",
            )
            await r.compress("br")
            assert r.headers.get("Content-Encoding") == "br"
            assert brotlicffi.decompress(r.body) == b"hello" * 100

        run(go())

    def test_gzip_applied(self):
        async def go():
            r = Request(
                method="POST",
                target="/",
                headers=Headers({"Host": "example.com"}),
                body=b"hello" * 100,
                content_type="text/plain",
            )
            await r.compress("gzip")
            assert r.headers.get("Content-Encoding") == "gzip"
            assert gzip.decompress(r.body) == b"hello" * 100

        run(go())

    def test_deflate_applied(self):
        async def go():
            r = Request(
                method="POST",
                target="/",
                headers=Headers({"Host": "example.com"}),
                body=b"hello" * 100,
                content_type="text/plain",
            )
            await r.compress("deflate")
            assert r.headers.get("Content-Encoding") == "deflate"
            assert zlib.decompress(r.body) == b"hello" * 100

        run(go())

    def test_existing_content_encoding_skipped(self):
        async def go():
            r = Request(
                method="POST",
                target="/",
                headers=Headers({"Host": "example.com", "Content-Encoding": "br"}),
                body=b"data" * 100,
                content_type="text/plain",
            )
            original = r.body
            await r.compress("gzip")
            assert r.body is original

        run(go())

    def test_compression_false_skips(self):
        async def go():
            r = Request(
                method="POST",
                target="/",
                headers=Headers({"Host": "example.com"}),
                body=b"data" * 100,
                content_type="text/plain",
                compression=False,
            )
            await r.compress("gzip")
            assert "Content-Encoding" not in r.headers

        run(go())

    def test_image_jpeg_not_compressed(self):
        async def go():
            r = Request(
                method="POST",
                target="/",
                headers=Headers({"Host": "example.com"}),
                body=b"\xff\xd8" + b"x" * 100,
                content_type="image/jpeg",
            )
            await r.compress("gzip")
            assert "Content-Encoding" not in r.headers

        run(go())

    def test_application_zip_not_compressed(self):
        async def go():
            r = Request(
                method="POST",
                target="/upload",
                headers=Headers({"Host": "example.com"}),
                body=b"PK\x03\x04" + b"x" * 100,
                content_type="application/zip",
            )
            await r.compress("gzip")
            assert "Content-Encoding" not in r.headers

        run(go())

    def test_body_none_skips(self):
        async def go():
            r = Request(
                method="GET",
                target="/",
                headers=Headers({"Host": "example.com"}),
            )
            await r.compress("gzip")
            assert "Content-Encoding" not in r.headers

        run(go())

# Request decompression

class TestRequestDecompressBytes:
    def _make(self, data: bytes, encoding: str) -> Request:
        return Request(
            method="POST",
            target="/",
            headers=Headers({"Host": "example.com", "Content-Encoding": encoding}),
            compressed=data,
        )

    def test_zstd_roundtrip(self):
        data = b"zstd request" * 100
        r = self._make(zstandard.ZstdCompressor().compress(data), "zstd")
        r.decompress()
        assert r.body == data

    def test_gzip_roundtrip(self):
        data = b"gzip request" * 100
        r = self._make(gzip.compress(data), "gzip")
        r.decompress()
        assert r.body == data

    def test_br_roundtrip(self):
        data = b"brotli request" * 50
        r = self._make(brotlicffi.compress(data), "br")
        r.decompress()
        assert r.body == data

    def test_deflate_roundtrip(self):
        data = b"deflate request" * 50
        r = self._make(zlib.compress(data), "deflate")
        r.decompress()
        assert r.body == data

    def test_body_already_set_skips(self):
        existing = b"existing"
        r = Request(
            method="POST",
            target="/",
            headers=Headers({"Host": "example.com", "Content-Encoding": "gzip"}),
            body=existing,
            compressed=gzip.compress(b"other"),
        )
        r.decompress()
        assert r.body is existing

    def test_compression_false_skips(self):
        data = b"hello" * 100
        r = Request(
            method="POST",
            target="/",
            headers=Headers({"Host": "example.com", "Content-Encoding": "gzip"}),
            compressed=gzip.compress(data),
            compression=False,
        )
        r.decompress()
        assert r.body is None

    def test_zstd_max_size_enforced(self):
        data = b"x" * 1000
        r = self._make(zstandard.ZstdCompressor().compress(data), "zstd")
        with pytest.raises(ValueError):
            r.decompress(max_size=100)

    def test_gzip_max_size_enforced(self):
        data = b"x" * 1000
        r = self._make(gzip.compress(data), "gzip")
        with pytest.raises(ValueError):
            r.decompress(max_size=100)

    def test_br_max_size_enforced(self):
        data = b"x" * 1000
        r = self._make(brotlicffi.compress(data), "br")
        with pytest.raises(ValueError):
            r.decompress(max_size=100)

    def test_no_compressed_data_is_no_op(self):
        r = Request(
            method="POST",
            target="/",
            headers=Headers({"Host": "example.com", "Content-Encoding": "gzip"}),
            compressed=None,
        )
        r.decompress()
        assert r.body is None

# Response minification

class TestResponseMinify:
    """Response.minify() must minify content according to its Content-Type."""

    def test_html_minified_when_enabled(self):
        async def go():
            html = b"<html>  <head>  </head>  <body>  <p>  hello  </p>  </body>  </html>"
            r = Response(body=html, content_type="text/html", minification=True)
            await r.minify(html=True)
            assert len(r.body) < len(html)

        run(go())

    def test_css_minified_when_enabled(self):
        async def go():
            css = b"body   {   color:   red;   margin:   0;   }"
            r = Response(body=css, content_type="text/css", minification=True)
            await r.minify(css=True)
            assert len(r.body) <= len(css)

        run(go())

    def test_js_minified_when_enabled(self):
        async def go():
            js = b"function   hello()   {   return   'world';   }"
            r = Response(body=js, content_type="text/javascript", minification=True)
            await r.minify(js=True)
            assert len(r.body) <= len(js)

        run(go())

    def test_wrong_content_type_not_minified(self):
        """Non-minifiable content types must be returned unchanged."""

        async def go():
            data = b'{"key":  "value",  "key2":  "value2"}'
            r = Response(body=data, content_type="application/json", minification=True)
            original = r.body
            await r.minify(html=True, css=True, js=True)
            assert r.body == original

        run(go())

    def test_minification_false_skips(self):
        async def go():
            html = b"<html>   <body>   </body>   </html>"
            r = Response(body=html, content_type="text/html", minification=False)
            await r.minify(html=True)
            assert r.body == html

        run(go())

    def test_body_none_skips_silently(self):
        """Minification on a response without a real body must not raise."""

        async def go():
            r = Response(body=None, content_type="text/html", minification=True)
            await r.minify(html=True)
            assert r.body is None

        run(go())

    def test_html_flag_false_skips_html(self):
        """html=False must not minify text/html content."""

        async def go():
            html = b"<html>   <body>   </body>   </html>"
            r = Response(body=html, content_type="text/html", minification=True)
            await r.minify(html=False)
            assert r.body == html

        run(go())
