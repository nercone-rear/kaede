import io
import os
import gzip
import zlib
import zstandard
import brotlicffi
from typing import Optional, Callable, List

from ..models import HTTPMessage, HTTPLimits
from ..errors import HTTPError
from ..headers import CommaHeader, AcceptEncoding

class Compression:
    CHUNK = 65536

    ENCODERS = {
        "zstd":    lambda data: zstandard.ZstdCompressor(level=3).compress(data),
        "br":      lambda data: brotlicffi.compress(data, quality=4),
        "gzip":    lambda data: gzip.compress(data, compresslevel=6),
        "deflate": lambda data: zlib.compress(data, level=6),
    }

    DECODERS = frozenset(ENCODERS) | {"identity"}

    @staticmethod
    def expand(encoding: str, data: bytes, ceiling: int) -> bytes:
        if encoding == "identity":
            return data

        if encoding == "zstd":
            return Compression.pull(zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data)).read, ceiling)

        if encoding == "br":
            return Compression.pull(Compression.brotli(data), ceiling)

        if encoding == "gzip":
            return Compression.pull(Compression.inflate(data, 16 + zlib.MAX_WBITS), ceiling)

        try:
            return Compression.pull(Compression.inflate(data, zlib.MAX_WBITS), ceiling)

        except zlib.error:
            return Compression.pull(Compression.inflate(data, -zlib.MAX_WBITS), ceiling)

    @staticmethod
    def pull(step: Callable[[int], bytes], ceiling: int) -> bytes:
        out = bytearray()

        while True:
            chunk = step(min(Compression.CHUNK, ceiling + 1 - len(out)))

            if not chunk:
                return bytes(out)

            out += chunk

            if len(out) > ceiling:
                raise HTTPError(413, "The decoded message body is larger than allowed.")

    @staticmethod
    def brotli(data: bytes) -> Callable[[int], bytes]:
        engine = brotlicffi.Decompressor()
        pending = data

        def step(room: int) -> bytes:
            nonlocal pending

            if engine.is_finished():
                return b""

            chunk = engine.decompress(pending, output_buffer_limit=room)
            pending = b""

            return chunk

        return step

    @staticmethod
    def inflate(data: bytes, wbits: int) -> Callable[[int], bytes]:
        engine = zlib.decompressobj(wbits)
        pending = data

        def step(room: int) -> bytes:
            nonlocal pending

            chunk = engine.decompress(pending, room)
            pending = engine.unconsumed_tail

            return chunk

        return step

def compress(message: HTTPMessage, accept_encoding: str, *, preference: List[str] = ["zstd", "br", "gzip", "deflate"], limits: HTTPLimits):
    if not (message.compression and not message.compressed and accept_encoding and isinstance(message.body, (bytes, str, os.PathLike))):
        return

    accept = AcceptEncoding.parse(accept_encoding)
    ranked = [(accept.quality(coding), -index, coding) for index, coding in enumerate(preference)]
    best = max((entry for entry in ranked if entry[0]), default=None)

    if best is None:
        if accept.quality("identity") != 0:
            return

        best = max(((0.0 if quality is None else quality, order, coding) for quality, order, coding in ranked if quality != 0), default=None)

        if best is None:
            return

    compress_with(message, [best[2]], limits=limits)

    if message.compressed:
        vary = CommaHeader(message.headers.get("Vary", ""))

        if not any(token.lower() == "accept-encoding" for token in vary.raw):
            vary.append("Accept-Encoding")
            message.headers.set("Vary", str(vary))

def compress_with(message: HTTPMessage, encodings: Optional[List[str]] = None, *, limits: HTTPLimits):
    if not (message.compression and not message.compressed and message.body is not None):
        return

    content_encoding = CommaHeader(message.headers.get("Content-Encoding", ""))

    if isinstance(message.body, str):
        message.offload(limits)

    if isinstance(message.body, bytes):
        for encoding in encodings:
            shrink = Compression.ENCODERS.get(encoding)

            if shrink is None:
                continue

            message.body = shrink(message.body)
            content_encoding.append(encoding)
            message.compressed = True

        message.headers.set("Content-Encoding", str(content_encoding))

def decompress(message: HTTPMessage, *, limits: HTTPLimits):
    if not (message.compression and message.compressed and message.body is not None):
        return

    content_encoding = CommaHeader(message.headers.get("Content-Encoding", ""))

    if isinstance(message.body, str):
        message.offload(limits)

    if not isinstance(message.body, bytes):
        return

    while content_encoding.raw:
        encoding = content_encoding.raw[-1].lower()

        if encoding not in Compression.DECODERS:
            break

        message.body = Compression.expand(encoding, message.body, limits.max_message_body_size)
        content_encoding.raw.pop()

    if content_encoding.raw:
        message.headers.set("Content-Encoding", str(content_encoding))
    else:
        message.headers.remove("Content-Encoding")
        message.compressed = False
