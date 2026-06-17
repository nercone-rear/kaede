from __future__ import annotations

import os
import gzip
import zlib
import asyncio
import inspect
import mimetypes
import zstandard
import brotlicffi
import email.utils

from typing import TYPE_CHECKING, Awaitable
from async_lru import alru_cache
from collections.abc import AsyncIterator

import minify_html as rhtmin
import rjsmin
import rcssmin
from scour import scour

from .models import Request, Response, Callback

if TYPE_CHECKING:
    from .api.server import Config as ServerConfig
    from .api.client import Config as ClientConfig

def size_limited_cache(maxsize: int, max_cacheable_body_size: int = 1024 * 1024):
    def decorator(fn):
        cached = alru_cache(maxsize=maxsize)(fn)

        async def wrapper(body: bytes) -> bytes:
            if len(body) > max_cacheable_body_size:
                return await fn(body)
            return await cached(body)

        return wrapper

    return decorator

@size_limited_cache(maxsize=128)
async def minimize_html(body: bytes) -> bytes:
    return rhtmin.minify(body.decode("utf-8", errors="replace"), minify_js=True, minify_css=True, keep_comments=True, keep_html_and_head_opening_tags=True).encode("utf-8")

@size_limited_cache(maxsize=128)
async def minimize_css(body: bytes) -> bytes:
    return rcssmin.cssmin(body.decode("utf-8", errors="replace")).encode("utf-8") # type: ignore

@size_limited_cache(maxsize=128)
async def minimize_js(body: bytes) -> bytes:
    return rjsmin.jsmin(body.decode("utf-8", errors="replace")).encode("utf-8") # type: ignore

@size_limited_cache(maxsize=64)
async def minimize_svg(body: bytes) -> bytes:
    scour_options = scour.generateDefaultOptions()
    scour_options.newlines = False
    scour_options.shorten_ids = True
    scour_options.strip_comments = True
    return scour.scourString(body.decode("utf-8", errors="replace"), scour_options).encode("utf-8")

@size_limited_cache(maxsize=128)
async def compress_zstd(body: bytes) -> bytes:
    return zstandard.ZstdCompressor(level=3).compress(body)

@size_limited_cache(maxsize=128)
async def compress_brotli(body: bytes) -> bytes:
    return brotlicffi.compress(body, quality=4)

@size_limited_cache(maxsize=128)
async def compress_gzip(body: bytes) -> bytes:
    return gzip.compress(body, compresslevel=6)

@size_limited_cache(maxsize=128)
async def compress_deflate(body: bytes) -> bytes:
    return zlib.compress(body, level=6)

async def compress_stream_zstd(body: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    compressor = zstandard.ZstdCompressor(level=3).compressobj()
    async for chunk in body:
        out = compressor.compress(chunk)
        if out:
            yield out
    out = compressor.flush(zstandard.COMPRESSOBJ_FLUSH_FINISH)
    if out:
        yield out

async def compress_stream_brotli(body: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    compressor = brotlicffi.Compressor(quality=4)
    async for chunk in body:
        out = compressor.process(chunk)
        if out:
            yield out
    out = compressor.finish()
    if out:
        yield out

async def compress_stream_gzip(body: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    compressor = zlib.compressobj(level=6, wbits=31)
    async for chunk in body:
        out = compressor.compress(chunk)
        if out:
            yield out
    out = compressor.flush(zlib.Z_FINISH)
    if out:
        yield out

async def compress_stream_deflate(body: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    compressor = zlib.compressobj(level=6)
    async for chunk in body:
        out = compressor.compress(chunk)
        if out:
            yield out
    out = compressor.flush(zlib.Z_FINISH)
    if out:
        yield out

async def minimize_response(response: Response) -> bytes | None:
    if response.has_real_body and response.minification:
        content_type = response.content_type or response.headers.get("Content-Type", "") or ""
        try:
            if content_type.startswith("text/html"):
                return await minimize_html(response.body)
            elif content_type.startswith("text/css"):
                return await minimize_css(response.body)
            elif content_type.startswith(("text/javascript", "application/javascript")):
                return await minimize_js(response.body)
            elif content_type.startswith("image/svg"):
                return await minimize_svg(response.body)
        except Exception:
            return None
    return None

def is_compressible(content_type: str | None) -> bool:
    if not content_type:
        return True

    ct = content_type.split(";", 1)[0].strip().lower()

    if ct.startswith(("image/", "video/", "audio/")):
        return ct == "image/svg+xml"

    elif ct in ("application/zip", "application/gzip", "application/x-gzip", "application/zstd", "application/x-zstd", "application/x-bzip2", "application/x-xz", "application/x-7z-compressed", "application/x-rar-compressed", "application/pdf", "application/ogg", "font/woff", "font/woff2"):
        return False

    return True

async def compress_response(response: Response, accepted_encodings: dict[str, float], max_compressible_file_size: int = 16 * 1024 * 1024) -> bytes | AsyncIterator[bytes] | None:
    if not (response.body is not None and response.compression and accepted_encodings):
        return None

    if "Content-Encoding" in response.headers:
        return None

    if not is_compressible(response.content_type or response.headers.get("Content-Type")):
        return None

    candidates: list[tuple[str, object, object, int]] = [
        ("zstd",    compress_zstd,    compress_stream_zstd,    0),
        ("br",      compress_brotli,  compress_stream_brotli,  1),
        ("gzip",    compress_gzip,    compress_stream_gzip,    2),
        ("deflate", compress_deflate, compress_stream_deflate, 3),
    ]

    star_q = accepted_encodings.get("*", None)

    scored: list[tuple[float, int, str, object, object]] = []
    for encoding, fn, stream_fn, priority in candidates:
        q = accepted_encodings.get(encoding)
        if q is None:
            q = star_q
        if q is None or q <= 0:
            continue
        scored.append((-q, priority, encoding, fn, stream_fn))

    scored.sort()

    for _, _, encoding, fn, stream_fn in scored:
        if response.is_streaming:
            response.headers.set("Content-Encoding", encoding)
            response.headers.append_vary("Accept-Encoding")
            return stream_fn(response.body)

        if response.has_real_body:
            try:
                compressed = await fn(response.body)
            except Exception:
                continue
            response.headers.set("Content-Encoding", encoding)
            response.headers.append_vary("Accept-Encoding")
            return compressed

        loop = asyncio.get_running_loop()
        try:
            path_str = os.fspath(response.body)

            if await loop.run_in_executor(None, os.path.getsize, path_str) > max_compressible_file_size:
                return None

            def read_file() -> bytes:
                with open(path_str, "rb") as f:
                    return f.read()

            data = await loop.run_in_executor(None, read_file)
            compressed = await fn(data)

        except Exception:
            continue

        response.headers.set("Content-Encoding", encoding)
        response.headers.append_vary("Accept-Encoding")

        return compressed

    return None

def parse_accept_encoding(value: str) -> dict[str, float]:
    result: dict[str, float] = {}
    if not value:
        return result

    for item in value.split(","):
        token, _, params = item.strip().partition(";")
        token = token.strip().lower()
        if not token:
            continue

        q = 1.0
        for param in params.split(";"):
            param = param.strip()
            if param.startswith("q="):
                try:
                    q = float(param[2:])
                except ValueError:
                    q = 0.0
                break

        result[token] = q

    return result

def parse_range(value: str, total: int) -> tuple[int, int] | None:
    if not value.startswith("bytes="):
        return None
    spec = value[6:].split(",")[0].strip()

    if spec.startswith("-"):
        try:
            suffix = int(spec[1:])
        except ValueError:
            return None
        if suffix <= 0 or total == 0:
            return None
        return (max(0, total - suffix), total - 1)

    dash = spec.find("-")
    if dash == -1:
        return None

    start_s, end_s = spec[:dash].strip(), spec[dash + 1:].strip()
    try:
        start = int(start_s)
    except ValueError:
        return None

    try:
        end = int(end_s) if end_s else total - 1
    except ValueError:
        return None

    if end >= total:
        end = total - 1

    if start > end or start >= total:
        return None

    return (start, end)

def error_response(request: Request, config: ServerConfig) -> Response:
    response = Response(b"Internal Server Error", status_code=500, compression=False, minification=False)

    response.headers.set("Date", email.utils.formatdate(usegmt=True), override=False)
    response.headers.set("Server", config.server_name, override=False)
    response.headers.set("Content-Type", "text/plain; charset=utf-8")
    response.headers.set("Content-Length", str(len(response.body)))

    if request.method == "HEAD":
        response.body = None

    return response

def decompress_once(data: bytes, encoding: str, max_size: int | None) -> bytes:
    enc = encoding.strip().lower()

    if enc in ("", "identity"):
        return data

    if enc in ("gzip", "x-gzip"):
        return zlib_decompress(data, 16 + zlib.MAX_WBITS, max_size)

    if enc == "deflate":
        try:
            return zlib_decompress(data, zlib.MAX_WBITS, max_size)
        except zlib.error:
            return zlib_decompress(data, -zlib.MAX_WBITS, max_size)

    if enc == "br":
        d = brotlicffi.Decompressor()
        out = bytearray()
        chunk = 65536

        for i in range(0, len(data), chunk):
            out.extend(d.process(data[i:i + chunk]))
            if max_size is not None and len(out) > max_size:
                raise ValueError("decompressed body exceeds max_body_size")

        return bytes(out)

    if enc == "zstd":
        out = zstandard.ZstdDecompressor().decompress(data)
        if max_size is not None and len(out) > max_size:
            raise ValueError("decompressed body exceeds max_body_size")
        return out

    raise ValueError(f"unsupported Content-Encoding: {enc!r}")

def zlib_decompress(data: bytes, wbits: int, max_size: int | None) -> bytes:
    decompressor = zlib.decompressobj(wbits)

    if max_size is None:
        return decompressor.decompress(data) + decompressor.flush()

    out = decompressor.decompress(data, max_size + 1)
    if decompressor.unconsumed_tail or len(out) > max_size:
        raise ValueError("decompressed body exceeds max_body_size")

    return out

def decode_content_encoding(body: bytes, encodings: list[str], max_size: int | None) -> bytes:
    for encoding in reversed(encodings):
        body = decompress_once(body, encoding, max_size)
    return body

KNOWN_ENCODINGS = ("gzip", "x-gzip", "deflate", "br", "zstd", "identity")

class StreamDecompressor:
    def __init__(self, encoding: str):
        self.kind = encoding.lower()
        self.zobj = None
        self.bobj = None
        self.zstd = None
        self._deflate_tried = False

        if self.kind in ("gzip", "x-gzip"):
            self.zobj = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif self.kind == "deflate":
            self.zobj = zlib.decompressobj(zlib.MAX_WBITS)
        elif self.kind == "br":
            self.bobj = brotlicffi.Decompressor()
        elif self.kind == "zstd":
            self.zstd = zstandard.ZstdDecompressor().decompressobj()

    def feed(self, data: bytes) -> bytes:
        if self.bobj is not None:
            return self.bobj.process(data) if data else b""

        if self.zstd is not None:
            return self.zstd.decompress(data) if data else b""

        if self.zobj is not None:
            if not data:
                return b""
            try:
                return self.zobj.decompress(data)
            except zlib.error:
                if self.kind == "deflate" and not self._deflate_tried:
                    self._deflate_tried = True
                    self.zobj = zlib.decompressobj(-zlib.MAX_WBITS)
                    return self.zobj.decompress(data)
                raise

        return data

    def flush(self) -> bytes:
        if self.zobj is not None:
            return self.zobj.flush()
        return b""

async def decompress_stream(source: AsyncIterator[bytes], encodings: list[str], max_size: int | None) -> AsyncIterator[bytes]:
    chain = [StreamDecompressor(encoding) for encoding in reversed(encodings) if encoding != "identity"]
    total = 0

    async for chunk in source:
        out = chunk
        for decompressor in chain:
            out = decompressor.feed(out)
        if out:
            total += len(out)
            if max_size is not None and total > max_size:
                raise ValueError("decompressed stream exceeds max_body_size")
            yield out

    pending = b""
    for decompressor in chain:
        pending = decompressor.feed(pending) + decompressor.flush()

    if pending:
        if max_size is not None and total + len(pending) > max_size:
            raise ValueError("decompressed stream exceeds max_body_size")
        yield pending

def wrap_streaming_response(response: Response, config: ClientConfig) -> Response:
    if not getattr(config, "decompress", True):
        return response

    raw = response.headers.get("Content-Encoding")
    if not raw or isinstance(raw, list):
        return response

    encodings = [e.strip().lower() for e in raw.split(",") if e.strip() and e.strip().lower() != "identity"]
    if not encodings or any(e not in KNOWN_ENCODINGS for e in encodings):
        return response

    response.body = decompress_stream(response.body, encodings, config.max_body_size)
    response.headers.remove("Content-Encoding")
    response.headers.remove("Content-Length")

    return response

async def process_response(response: Response, request: Request, config: ClientConfig) -> Response:
    if not getattr(config, "decompress", True):
        return response

    if not response.has_real_body:
        return response

    raw = response.headers.get("Content-Encoding")
    if not raw or isinstance(raw, list):
        return response

    encodings = [e.strip().lower() for e in raw.split(",") if e.strip() and e.strip().lower() != "identity"]
    if not encodings:
        return response

    loop = asyncio.get_running_loop()
    try:
        body = await loop.run_in_executor(None, decode_content_encoding, response.body, encodings, config.max_body_size)
    except Exception:
        return response

    response.body = body
    response.headers.remove("Content-Encoding")
    response.headers.set("Content-Length", str(len(body)))

    return response

async def compress_request(request: Request, config: ClientConfig) -> bytes | None:
    if not (request.body and isinstance(request.body, bytes)):
        return None

    raw = request.headers.get("Content-Encoding")
    if not raw or isinstance(raw, list):
        return None

    encoder = {
        "zstd":    compress_zstd,
        "br":      compress_brotli,
        "gzip":    compress_gzip,
        "deflate": compress_deflate,
    }.get(raw.split(",")[-1].strip().lower())

    if encoder is None:
        return None

    try:
        return await encoder(request.body)
    except Exception:
        return None

async def process_request(request: Request, callback: Callback, config: ServerConfig, response: Response | None = None) -> Response:
    if not response:
        try:
            response: Response | Awaitable[Response] = callback.on_request(request)
            if inspect.isawaitable(response):
                response = await response

        except Exception:
            response = Response(b"Internal Server Error", status_code=500, compression=False, minification=False)

    response.headers.set("Date", email.utils.formatdate(usegmt=True), override=False)
    response.headers.set("Server", config.server_name, override=False)
    response.headers.set("Content-Length", "0")

    try:
        if response.has_real_body:
            minimized = await minimize_response(response)
            if minimized is not None:
                response.body = minimized

            range_header = request.headers.get("Range", "")
            if (range_header and request.method in ("GET", "HEAD") and response.status_code == 200):
                total = len(response.body)
                parsed = parse_range(range_header, total)

                response.headers.set("Accept-Ranges", "bytes")

                if parsed is None:
                    response.status_code = 416
                    response.headers.set("Content-Range", f"bytes */{total}")
                    response.body = b""
                    response.headers.set("Content-Length", "0")
                    return response

                start, end = parsed
                response.body = response.body[start:end + 1]
                response.status_code = 206
                response.headers.set("Content-Range", f"bytes {start}-{end}/{total}")

            if response.status_code != 206:
                compressed = await compress_response(response, parse_accept_encoding(request.headers.get("Accept-Encoding", "")))
                if compressed is not None:
                    response.body = compressed

            response.headers.set("Content-Type", response.content_type or response.headers.get("Content-Type") or "application/octet-stream")
            response.headers.set("Content-Length", str(len(response.body)))

        elif response.is_streaming:
            compressed = await compress_response(response, parse_accept_encoding(request.headers.get("Accept-Encoding", "")))
            if compressed is not None:
                response.body = compressed

            response.headers.set("Content-Type", response.content_type or response.headers.get("Content-Type") or "application/octet-stream")
            response.headers.remove("Content-Length")

            if request.protocol == "HTTP/1.1":
                response.headers.set("Transfer-Encoding", "chunked")

        elif response.body is not None:
            loop = asyncio.get_running_loop()
            path = os.fspath(response.body)

            try:
                mime, _ = mimetypes.guess_type(path)
            except OSError:
                mime = None

            total = await loop.run_in_executor(None, os.path.getsize, path)

            response.headers.set("Accept-Ranges", "bytes")
            response.headers.set("Content-Type", response.content_type or response.headers.get("Content-Type") or mime or "application/octet-stream")

            range_header = request.headers.get("Range", "")
            if (range_header and request.method in ("GET", "HEAD") and response.status_code == 200):
                parsed = parse_range(range_header, total)
                if parsed is None:
                    response.status_code = 416
                    response.headers.set("Content-Range", f"bytes */{total}")
                    response.body = None
                    response.headers.set("Content-Length", "0")
                    return response

                start, end = parsed
                response.file_range = (start, end)
                response.status_code = 206
                response.headers.set("Content-Range", f"bytes {start}-{end}/{total}")
                response.headers.set("Content-Length", str(end - start + 1))

            else:
                compressed = await compress_response(response, parse_accept_encoding(request.headers.get("Accept-Encoding", "")))
                if compressed is not None:
                    response.body = compressed
                    response.headers.remove("Accept-Ranges")
                    response.headers.set("Content-Length", str(len(compressed)))
                else:
                    response.headers.set("Content-Length", str(total))

        if response.headers.get("Content-Type", "").startswith("text/") and "charset=" not in response.headers.get("Content-Type", ""):
            response.headers.set("Content-Type", response.headers.get("Content-Type", "") + "; charset=utf-8")

    except Exception:
        return error_response(request, config)

    if request.method == "HEAD":
        if response.is_streaming:
            response.headers.remove("Transfer-Encoding")
        response.body = None

    return response
