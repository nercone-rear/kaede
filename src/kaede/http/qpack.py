from __future__ import annotations

from ..huffman import huffman_decode

STATIC_TABLE: list[tuple[bytes, bytes]] = [
    (b":authority", b""),
    (b":path", b"/"),
    (b"age", b"0"),
    (b"content-disposition", b""),
    (b"content-length", b"0"),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"referer", b""),
    (b"set-cookie", b""),
    (b":method", b"CONNECT"),
    (b":method", b"DELETE"),
    (b":method", b"GET"),
    (b":method", b"HEAD"),
    (b":method", b"OPTIONS"),
    (b":method", b"POST"),
    (b":method", b"PUT"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"103"),
    (b":status", b"200"),
    (b":status", b"304"),
    (b":status", b"404"),
    (b":status", b"503"),
    (b"accept", b"*/*"),
    (b"accept", b"application/dns-message"),
    (b"accept-encoding", b"gzip, deflate, br"),
    (b"accept-ranges", b"bytes"),
    (b"access-control-allow-headers", b"cache-control"),
    (b"access-control-allow-headers", b"content-type"),
    (b"access-control-allow-origin", b"*"),
    (b"cache-control", b"max-age=0"),
    (b"cache-control", b"max-age=2592000"),
    (b"cache-control", b"max-age=604800"),
    (b"cache-control", b"no-cache"),
    (b"cache-control", b"no-store"),
    (b"cache-control", b"public, max-age=31536000"),
    (b"content-encoding", b"br"),
    (b"content-encoding", b"gzip"),
    (b"content-type", b"application/dns-message"),
    (b"content-type", b"application/javascript"),
    (b"content-type", b"application/json"),
    (b"content-type", b"application/x-www-form-urlencoded"),
    (b"content-type", b"image/gif"),
    (b"content-type", b"image/jpeg"),
    (b"content-type", b"image/png"),
    (b"content-type", b"text/css"),
    (b"content-type", b"text/html; charset=utf-8"),
    (b"content-type", b"text/plain"),
    (b"content-type", b"text/plain;charset=utf-8"),
    (b"range", b"bytes=0-"),
    (b"strict-transport-security", b"max-age=31536000"),
    (b"strict-transport-security", b"max-age=31536000; includesubdomains"),
    (b"strict-transport-security", b"max-age=31536000; includesubdomains; preload"),
    (b"vary", b"accept-encoding"),
    (b"vary", b"origin"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-xss-protection", b"1; mode=block"),
    (b":status", b"100"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"302"),
    (b":status", b"400"),
    (b":status", b"403"),
    (b":status", b"421"),
    (b":status", b"425"),
    (b":status", b"500"),
    (b"accept-language", b""),
    (b"access-control-allow-credentials", b"FALSE"),
    (b"access-control-allow-credentials", b"TRUE"),
    (b"access-control-allow-headers", b"*"),
    (b"access-control-allow-methods", b"get"),
    (b"access-control-allow-methods", b"get, post, options"),
    (b"access-control-allow-methods", b"options"),
    (b"access-control-expose-headers", b"content-length"),
    (b"access-control-request-headers", b"content-type"),
    (b"access-control-request-method", b"get"),
    (b"access-control-request-method", b"post"),
    (b"alt-svc", b"clear"),
    (b"authorization", b""),
    (b"content-security-policy", b"script-src 'none'; object-src 'none'; base-uri 'none'"),
    (b"early-data", b"1"),
    (b"expect-ct", b""),
    (b"forwarded", b""),
    (b"if-range", b""),
    (b"origin", b""),
    (b"purpose", b"prefetch"),
    (b"server", b""),
    (b"timing-allow-origin", b"*"),
    (b"upgrade-insecure-requests", b"1"),
    (b"user-agent", b""),
    (b"x-forwarded-for", b""),
    (b"x-frame-options", b"deny"),
    (b"x-frame-options", b"sameorigin")
]

STATIC_INDEX_BY_HEADER: dict[tuple[bytes, bytes], int] = {}
STATIC_INDEX_BY_NAME: dict[bytes, int] = {}

for _i, (_n, _v) in enumerate(STATIC_TABLE):
    STATIC_INDEX_BY_HEADER.setdefault((_n, _v), _i)
    STATIC_INDEX_BY_NAME.setdefault(_n, _i)

class QpackError(Exception):
    pass

def encode_integer(value: int, prefix_bits: int, flags: int = 0) -> bytes:
    mask = (1 << prefix_bits) - 1
    out = bytearray()

    if value < mask:
        out.append(flags | value)
        return bytes(out)

    out.append(flags | mask)

    value -= mask

    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7

    out.append(value)
    return bytes(out)

def decode_integer(data: bytes, offset: int, prefix_bits: int) -> tuple[int, int]:
    mask = (1 << prefix_bits) - 1
    value = data[offset] & mask

    offset += 1

    if value < mask:
        return value, offset

    shift = 0

    for _ in range(10):
        if offset >= len(data):
            raise QpackError("integer encoding truncated")
        b = data[offset]
        offset += 1
        value += (b & 0x7F) << shift
        shift += 7

        if not (b & 0x80):
            break
    else:
        raise QpackError("integer encoding too long")

    return value, offset

def encode_string(value: bytes, prefix_bits: int, flag_bit: int) -> bytes:
    out = bytearray()
    out += encode_integer(len(value), prefix_bits, flag_bit)
    out += value
    return bytes(out)

def decode_string(data: bytes, offset: int, prefix_bits: int) -> tuple[bytes, int]:
    huffman = bool(data[offset] & (1 << prefix_bits))
    length, offset = decode_integer(data, offset, prefix_bits)
    raw = data[offset:offset + length]
    offset += length

    if huffman:
        raw = huffman_decode(raw)

    return raw, offset

def encode_headers(headers: list[tuple[bytes, bytes]]) -> bytes:
    out = bytearray()
    out += encode_integer(0, 8)
    out += encode_integer(0, 7)

    for name, value in headers:
        name = name.lower()
        full = STATIC_INDEX_BY_HEADER.get((name, value))

        if full is not None:
            out += encode_integer(full, 6, 0xC0)
            continue

        name_idx = STATIC_INDEX_BY_NAME.get(name)
        if name_idx is not None:
            out += encode_integer(name_idx, 4, 0x50)
            out += encode_string(value, 7, 0)
        else:
            out += encode_string(name, 3, 0x20)
            out += encode_string(value, 7, 0)

    return bytes(out)

def decode_headers(data: bytes) -> list[tuple[bytes, bytes]]:
    offset = 0
    required_insert_count, offset = decode_integer(data, offset, 8)
    delta_base, offset = decode_integer(data, offset, 7)

    if required_insert_count != 0:
        raise QpackError("dynamic table references are not supported (QPACK capacity is 0)")

    headers: list[tuple[bytes, bytes]] = []
    n = len(data)

    while offset < n:
        first = data[offset]
        if first & 0x80:
            is_static = bool(first & 0x40)
            index, offset = decode_integer(data, offset, 6)

            if not is_static:
                raise QpackError("dynamic table reference not supported")

            if index >= len(STATIC_TABLE):
                raise QpackError(f"static table index out of range: {index}")
            headers.append(STATIC_TABLE[index])

        elif first & 0x40:
            is_static = bool(first & 0x10)
            index, offset = decode_integer(data, offset, 4)

            if not is_static:
                raise QpackError("dynamic table reference not supported")

            if index >= len(STATIC_TABLE):
                raise QpackError(f"static table index out of range: {index}")
            name = STATIC_TABLE[index][0]
            value, offset = decode_string(data, offset, 7)
            headers.append((name, value))

        elif first & 0x20:
            name, offset = decode_string(data, offset, 3)
            value, offset = decode_string(data, offset, 7)
            headers.append((name.lower(), value))

        else:
            raise QpackError(f"unsupported QPACK representation 0x{first:02x}")

    return headers
