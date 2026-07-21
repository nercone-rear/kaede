import io
import os
import gzip
import zlib
import zstandard
import brotlicffi
from typing import Optional, List

from ..models import HTTPMessage
from ..api.common import HTTPLimits
from ..errors import HTTPError
from ..headers import CommaHeader, AcceptEncoding

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
            if encoding == "zstd":
                message.body = zstandard.ZstdCompressor(level=3).compress(message.body)

            elif encoding == "br":
                message.body = brotlicffi.compress(message.body, quality=4)

            elif encoding == "gzip":
                message.body = gzip.compress(message.body, compresslevel=6)

            elif encoding == "deflate":
                message.body = zlib.compress(message.body, level=6)

            else:
                continue

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

        if encoding == "identity":
            content_encoding.raw.pop()
            continue

        if encoding not in ("zstd", "br", "gzip", "deflate"):
            break

        decoded = bytearray()

        if encoding == "zstd":
            reader = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(message.body))

            while True:
                chunk = reader.read(min(limits.decompress_chunk_size, limits.max_message_body_size + 1 - len(decoded)))

                if not chunk:
                    break

                decoded += chunk

                if len(decoded) > limits.max_message_body_size:
                    raise HTTPError(413, "The decoded message body is larger than allowed.")

        elif encoding == "br":
            engine = brotlicffi.Decompressor()
            pending = message.body

            while not engine.is_finished():
                chunk = engine.decompress(pending, output_buffer_limit=min(limits.decompress_chunk_size, limits.max_message_body_size + 1 - len(decoded)))
                pending = b""

                if not chunk:
                    break

                decoded += chunk

                if len(decoded) > limits.max_message_body_size:
                    raise HTTPError(413, "The decoded message body is larger than allowed.")

        elif encoding == "gzip":
            engine = zlib.decompressobj(16 + zlib.MAX_WBITS)
            pending = message.body

            while True:
                chunk = engine.decompress(pending, min(limits.decompress_chunk_size, limits.max_message_body_size + 1 - len(decoded)))
                pending = engine.unconsumed_tail

                if not chunk:
                    break

                decoded += chunk

                if len(decoded) > limits.max_message_body_size:
                    raise HTTPError(413, "The decoded message body is larger than allowed.")

        else:
            try:
                engine = zlib.decompressobj(zlib.MAX_WBITS)
                pending = message.body

                while True:
                    chunk = engine.decompress(pending, min(limits.decompress_chunk_size, limits.max_message_body_size + 1 - len(decoded)))
                    pending = engine.unconsumed_tail

                    if not chunk:
                        break

                    decoded += chunk

                    if len(decoded) > limits.max_message_body_size:
                        raise HTTPError(413, "The decoded message body is larger than allowed.")

            except zlib.error:
                decoded = bytearray()
                engine = zlib.decompressobj(-zlib.MAX_WBITS)
                pending = message.body

                while True:
                    chunk = engine.decompress(pending, min(limits.decompress_chunk_size, limits.max_message_body_size + 1 - len(decoded)))
                    pending = engine.unconsumed_tail

                    if not chunk:
                        break

                    decoded += chunk

                    if len(decoded) > limits.max_message_body_size:
                        raise HTTPError(413, "The decoded message body is larger than allowed.")

        message.body = bytes(decoded)
        content_encoding.raw.pop()

    if content_encoding.raw:
        message.headers.set("Content-Encoding", str(content_encoding))
    else:
        message.headers.remove("Content-Encoding")
        message.compressed = False
