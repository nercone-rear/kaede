import gzip
import zlib
import pytest
import zstandard
import brotlicffi

from kaede.models import Request, Response, Callback, Headers
from kaede.process import process_request, process_response
from kaede.api.server import Config as ServerConfig
from kaede.api.client import Config as ClientConfig


def _server_config(**kwargs):
    return ServerConfig(**kwargs)


def _make_request(method="GET", target="/", protocol="HTTP/1.1", **header_kv):
    r = Request(method=method, target=target, protocol=protocol)
    for k, v in header_kv.items():
        r.headers.set(k.replace("_", "-"), v)
    return r


class _CB(Callback):
    def __init__(self, response_factory):
        super().__init__()
        self._factory = response_factory

    async def on_request(self, request):
        return self._factory(request)


class TestProcessRequest:
    async def test_date_header_set(self):
        config = _server_config()
        req = _make_request()
        cb = _CB(lambda r: Response(b"hi", compression=False))
        resp = await process_request(req, cb, config)
        assert resp.headers.get("Date") is not None

    async def test_server_header_set(self):
        config = _server_config(server_name="TestServer")
        req = _make_request()
        cb = _CB(lambda r: Response(b"hi", compression=False))
        resp = await process_request(req, cb, config)
        assert resp.headers.get("Server") == "TestServer"

    async def test_content_length_set_for_bytes_body(self):
        config = _server_config()
        req = _make_request()
        body = b"hello world"
        cb = _CB(lambda r: Response(body, compression=False))
        resp = await process_request(req, cb, config)
        assert resp.headers.get("Content-Length") == str(len(body))

    async def test_callback_exception_returns_500(self):
        config = _server_config()
        req = _make_request()

        class ErrCB(Callback):
            async def on_request(self, request):
                raise RuntimeError("boom")

        resp = await process_request(req, ErrCB(), config)
        assert resp.status_code == 500
        assert resp.body == b"Internal Server Error"

    async def test_head_request_strips_body(self):
        config = _server_config()
        req = _make_request(method="HEAD")
        cb = _CB(lambda r: Response(b"hello", compression=False))
        resp = await process_request(req, cb, config)
        assert resp.body is None

    async def test_range_request_returns_206(self):
        config = _server_config()
        req = _make_request()
        req.headers.set("Range", "bytes=0-4")
        cb = _CB(lambda r: Response(b"hello world", compression=False))
        resp = await process_request(req, cb, config)
        assert resp.status_code == 206
        assert resp.body == b"hello"
        assert resp.headers.get("Content-Range") == "bytes 0-4/11"

    async def test_invalid_range_returns_416(self):
        config = _server_config()
        req = _make_request()
        req.headers.set("Range", "bytes=100-200")
        cb = _CB(lambda r: Response(b"hi", compression=False))
        resp = await process_request(req, cb, config)
        assert resp.status_code == 416

    async def test_range_not_applied_for_post(self):
        config = _server_config()
        req = _make_request(method="POST")
        req.headers.set("Range", "bytes=0-4")
        cb = _CB(lambda r: Response(b"hello world", compression=False))
        resp = await process_request(req, cb, config)
        assert resp.status_code == 200
        assert resp.body == b"hello world"

    async def test_range_not_applied_for_non_200(self):
        config = _server_config()
        req = _make_request()
        req.headers.set("Range", "bytes=0-4")
        cb = _CB(lambda r: Response(b"hello world", status_code=201, compression=False))
        resp = await process_request(req, cb, config)
        assert resp.status_code == 201

    async def test_content_encoding_request_decompressed(self):
        config = _server_config()
        original = b"hello world"
        compressed = zstandard.ZstdCompressor().compress(original)
        req = _make_request(method="POST")
        req.body = compressed
        req.headers.set("Content-Encoding", "zstd")

        received = []

        class RecordCB(Callback):
            async def on_request(self, request):
                received.append(request.body)
                return Response(b"ok", compression=False)

        await process_request(req, RecordCB(), config)
        assert received[0] == original

    async def test_content_encoding_gzip_decompressed(self):
        config = _server_config()
        original = b"hello world"
        compressed = gzip.compress(original)
        req = _make_request(method="POST")
        req.body = compressed
        req.headers.set("Content-Encoding", "gzip")

        received = []

        class RecordCB(Callback):
            async def on_request(self, request):
                received.append(request.body)
                return Response(b"ok", compression=False)

        await process_request(req, RecordCB(), config)
        assert received[0] == original

    async def test_text_content_type_gets_charset(self):
        config = _server_config()
        req = _make_request()
        cb = _CB(lambda r: Response(b"hello", content_type="text/plain", compression=False))
        resp = await process_request(req, cb, config)
        ct = resp.headers.get("Content-Type") or ""
        assert "charset=utf-8" in ct

    async def test_text_content_type_already_has_charset_unchanged(self):
        config = _server_config()
        req = _make_request()
        cb = _CB(lambda r: Response(b"hi", compression=False))
        resp = await process_request(req, cb, config)
        # No content type → application/octet-stream → no charset appended
        ct = resp.headers.get("Content-Type") or ""
        assert "charset" not in ct

    async def test_pre_passed_response_skips_callback(self):
        config = _server_config()
        req = _make_request()
        pre_resp = Response(b"prebuilt", status_code=201, compression=False)

        class ShouldNotBeCalled(Callback):
            async def on_request(self, request):
                raise AssertionError("callback should not be called")

        resp = await process_request(req, ShouldNotBeCalled(), config, response=pre_resp)
        assert resp.status_code == 201
        assert resp.body == b"prebuilt"

    async def test_streaming_response_h11_gets_transfer_encoding(self):
        config = _server_config()
        req = _make_request(protocol="HTTP/1.1")

        async def gen():
            yield b"chunk"

        cb = _CB(lambda r: Response(body=gen(), compression=False))
        resp = await process_request(req, cb, config)
        assert resp.is_streaming
        assert resp.headers.get("Transfer-Encoding") == "chunked"
        assert "Content-Length" not in resp.headers

    async def test_streaming_response_h2_no_transfer_encoding(self):
        config = _server_config()
        req = _make_request(protocol="HTTP/2.0")

        async def gen():
            yield b"chunk"

        cb = _CB(lambda r: Response(body=gen(), compression=False))
        resp = await process_request(req, cb, config)
        assert resp.is_streaming
        assert "Transfer-Encoding" not in resp.headers

    async def test_response_compressed_by_accept_encoding(self):
        config = _server_config()
        req = _make_request()
        req.headers.set("Accept-Encoding", "gzip")
        cb = _CB(lambda r: Response(b"data " * 500))
        resp = await process_request(req, cb, config)
        assert resp.headers.get("Content-Encoding") is not None

    async def test_accept_ranges_set_for_bytes_body(self):
        config = _server_config()
        req = _make_request()
        req.headers.set("Range", "bytes=0-2")
        cb = _CB(lambda r: Response(b"hello", compression=False))
        resp = await process_request(req, cb, config)
        assert resp.headers.get("Accept-Ranges") == "bytes"

    async def test_head_streaming_removes_transfer_encoding(self):
        config = _server_config()
        req = _make_request(method="HEAD", protocol="HTTP/1.1")

        async def gen():
            yield b"chunk"

        cb = _CB(lambda r: Response(body=gen(), compression=False))
        resp = await process_request(req, cb, config)
        assert resp.body is None
        assert "Transfer-Encoding" not in resp.headers

    async def test_empty_body_response(self):
        config = _server_config()
        req = _make_request()
        cb = _CB(lambda r: Response(b"", status_code=204, compression=False))
        resp = await process_request(req, cb, config)
        assert resp.status_code == 204


class TestProcessResponse:
    async def test_no_decompress_config_returns_unchanged(self):
        config = ClientConfig(decompress=False)
        resp = Response(b"compressed", status_code=200)
        resp.headers.set("Content-Encoding", "gzip")
        result = await process_response(resp, config)
        assert result.body == b"compressed"
        assert result.headers.get("Content-Encoding") == "gzip"

    async def test_no_content_encoding_returns_unchanged(self):
        config = ClientConfig(decompress=True)
        resp = Response(b"plain body", status_code=200)
        result = await process_response(resp, config)
        assert result.body == b"plain body"

    async def test_zstd_bytes_decompressed(self):
        config = ClientConfig(decompress=True)
        original = b"hello world"
        compressed = zstandard.ZstdCompressor().compress(original)
        resp = Response(compressed, status_code=200)
        resp.headers.set("Content-Encoding", "zstd")
        result = await process_response(resp, config)
        assert result.body == original

    async def test_gzip_bytes_decompressed(self):
        config = ClientConfig(decompress=True)
        original = b"hello world"
        compressed = gzip.compress(original)
        resp = Response(compressed, status_code=200)
        resp.headers.set("Content-Encoding", "gzip")
        result = await process_response(resp, config)
        assert result.body == original

    async def test_br_bytes_decompressed(self):
        config = ClientConfig(decompress=True)
        original = b"hello"
        compressed = brotlicffi.compress(original)
        resp = Response(compressed, status_code=200)
        resp.headers.set("Content-Encoding", "br")
        result = await process_response(resp, config)
        assert result.body == original

    async def test_content_length_updated_after_decompress(self):
        config = ClientConfig(decompress=True)
        original = b"hello world"
        compressed = zstandard.ZstdCompressor().compress(original)
        resp = Response(compressed, status_code=200)
        resp.headers.set("Content-Encoding", "zstd")
        result = await process_response(resp, config)
        assert result.headers.get("Content-Length") == str(len(original))

    async def test_streaming_body_gets_decompressor_wrapper(self):
        config = ClientConfig(decompress=True)
        original = b"hello world " * 100
        compressed = gzip.compress(original)

        async def gen():
            yield compressed

        resp = Response(body=gen(), status_code=200)
        resp.headers.set("Content-Encoding", "gzip")
        result = await process_response(resp, config)
        assert result.is_streaming
        # Consume and verify
        out = b""
        async for chunk in result.body:
            out += chunk
        assert out == original

    async def test_failed_decompress_falls_back_to_compressed(self):
        config = ClientConfig(decompress=True)
        # Provide invalid compressed data for an unsupported encoding
        resp = Response(b"some body", status_code=200)
        resp.headers.set("Content-Encoding", "unknown-encoding")
        result = await process_response(resp, config)
        # Unknown encoding → decompress does nothing → body stays compressed
        assert result.body == b"some body"
