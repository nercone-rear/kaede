import os
import gzip
import zlib
import zstandard
import brotlicffi
from typing import Optional, List

from ..models import HTTPMessage, HTTPLimits
from ..headers import CommaHeader, AcceptEncoding

def compress(message: HTTPMessage, accept_encoding: str, *, preference: List[str] = ["zstd", "br", "gzip", "deflate"], limits: HTTPLimits):
    if not (message.compression and not message.compressed and accept_encoding and isinstance(message.body, (bytes, str, os.PathLike))):
        return

    accept      = AcceptEncoding.parse(accept_encoding)
    acceptable  = {c for c, q in accept.raw if q > 0}
    wildcard_ok = any(c == "*" and q > 0 for c, q in accept.raw)

    best = next((c for c in preference if c in acceptable or (wildcard_ok and c not in {c2 for c2, q in accept.raw if q == 0})), None)

    if best is not None:
        compress_with(message, [best], limit=limits)

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

    if isinstance(message.body, bytes):
        for encoding in reversed(content_encoding.raw):
            if encoding == "zstd":
                message.body = zstandard.ZstdDecompressor().decompress(message.body)
            elif encoding == "br":
                message.body = brotlicffi.decompress(message.body)
            elif encoding == "gzip":
                message.body = gzip.decompress(message.body)
            elif encoding == "deflate":
                try:
                    message.body = zlib.decompress(message.body)
                except zlib.error:
                    message.body = zlib.decompress(message.body, -zlib.MAX_WBITS)
            else:
                break

        message.headers.remove("Content-Encoding")
        message.compressed = False
