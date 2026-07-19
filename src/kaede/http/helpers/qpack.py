from typing import List, Dict, Tuple

from .hpack import Huffman, Coding, HPACKError, HPACKField, HPACKTable, SENSITIVE

class QPACKError(Exception):
    """A malformed QPACK block, which HTTP/3 treats as a QPACK_DECOMPRESSION_FAILED error."""

STATIC: List[Tuple[str, str]] = [
    (':authority', ''),
    (':path', '/'),
    ('age', '0'),
    ('content-disposition', ''),
    ('content-length', '0'),
    ('cookie', ''),
    ('date', ''),
    ('etag', ''),
    ('if-modified-since', ''),
    ('if-none-match', ''),
    ('last-modified', ''),
    ('link', ''),
    ('location', ''),
    ('referer', ''),
    ('set-cookie', ''),
    (':method', 'CONNECT'),
    (':method', 'DELETE'),
    (':method', 'GET'),
    (':method', 'HEAD'),
    (':method', 'OPTIONS'),
    (':method', 'POST'),
    (':method', 'PUT'),
    (':scheme', 'http'),
    (':scheme', 'https'),
    (':status', '103'),
    (':status', '200'),
    (':status', '304'),
    (':status', '404'),
    (':status', '503'),
    ('accept', '*/*'),
    ('accept', 'application/dns-message'),
    ('accept-encoding', 'gzip, deflate, br'),
    ('accept-ranges', 'bytes'),
    ('access-control-allow-headers', 'cache-control'),
    ('access-control-allow-headers', 'content-type'),
    ('access-control-allow-origin', '*'),
    ('cache-control', 'max-age=0'),
    ('cache-control', 'max-age=2592000'),
    ('cache-control', 'max-age=604800'),
    ('cache-control', 'no-cache'),
    ('cache-control', 'no-store'),
    ('cache-control', 'public, max-age=31536000'),
    ('content-encoding', 'br'),
    ('content-encoding', 'gzip'),
    ('content-type', 'application/dns-message'),
    ('content-type', 'application/javascript'),
    ('content-type', 'application/json'),
    ('content-type', 'application/x-www-form-urlencoded'),
    ('content-type', 'image/gif'),
    ('content-type', 'image/jpeg'),
    ('content-type', 'image/png'),
    ('content-type', 'text/css'),
    ('content-type', 'text/html; charset=utf-8'),
    ('content-type', 'text/plain'),
    ('content-type', 'text/plain;charset=utf-8'),
    ('range', 'bytes=0-'),
    ('strict-transport-security', 'max-age=31536000'),
    ('strict-transport-security', 'max-age=31536000; includesubdomains'),
    ('strict-transport-security', 'max-age=31536000; includesubdomains; preload'),
    ('vary', 'accept-encoding'),
    ('vary', 'origin'),
    ('x-content-type-options', 'nosniff'),
    ('x-xss-protection', '1; mode=block'),
    (':status', '100'),
    (':status', '204'),
    (':status', '206'),
    (':status', '302'),
    (':status', '400'),
    (':status', '403'),
    (':status', '421'),
    (':status', '425'),
    (':status', '500'),
    ('accept-language', ''),
    ('access-control-allow-credentials', 'FALSE'),
    ('access-control-allow-credentials', 'TRUE'),
    ('access-control-allow-headers', '*'),
    ('access-control-allow-methods', 'get'),
    ('access-control-allow-methods', 'get, post, options'),
    ('access-control-allow-methods', 'options'),
    ('access-control-expose-headers', 'content-length'),
    ('access-control-request-headers', 'content-type'),
    ('access-control-request-method', 'get'),
    ('access-control-request-method', 'post'),
    ('alt-svc', 'clear'),
    ('authorization', ''),
    ('content-security-policy', "script-src 'none'; object-src 'none'; base-uri 'none'"),
    ('early-data', '1'),
    ('expect-ct', ''),
    ('forwarded', ''),
    ('if-range', ''),
    ('origin', ''),
    ('purpose', 'prefetch'),
    ('server', ''),
    ('timing-allow-origin', '*'),
    ('upgrade-insecure-requests', '1'),
    ('user-agent', ''),
    ('x-forwarded-for', ''),
    ('x-frame-options', 'deny'),
    ('x-frame-options', 'sameorigin'),
]

STATIC_INDEX: Dict[Tuple[str, str], int] = {pair: number for number, pair in enumerate(STATIC)}
STATIC_NAMES: Dict[str, int] = {}
for number, (name, value) in enumerate(STATIC):
    STATIC_NAMES.setdefault(name, number)

class QPACKEncoder:
    def encode(self, headers: List[Tuple[str, str]]) -> bytes:
        out = bytearray(b"\x00\x00")

        for field in headers:
            name, value = field
            name = name.lower()

            never = getattr(field, "never", None)
            never = name in SENSITIVE if never is None else never

            exact = STATIC_INDEX.get((name, value))

            if exact is not None and not never:
                out += Coding.integer(exact, 6, 0xC0)
                continue

            named = STATIC_NAMES.get(name)

            if named is not None:
                out += Coding.integer(named, 4, 0x50 | (0x20 if never else 0))
            else:
                out += self.name(name, never)

            out += Coding.string(value)

        return bytes(out)

    def name(self, name: str, never: bool) -> bytes:
        flags = 0x20 | (0x10 if never else 0)
        raw = name.encode("latin-1")
        packed = Huffman.encode(raw)

        if len(packed) < len(raw):
            return Coding.integer(len(packed), 3, flags | 0x08) + packed

        return Coding.integer(len(raw), 3, flags) + raw

class QPACKDecoder:
    def __init__(self, max_header_list: int = 262144):
        self.max_header_list = max_header_list

    def decode(self, data: bytes) -> List[Tuple[str, str]]:
        try:
            return self.parse(data)

        except HPACKError as e:
            raise QPACKError(str(e))

    def parse(self, data: bytes) -> List[Tuple[str, str]]:
        offset = 0

        ric, offset = Coding.read_integer(data, offset, 8)

        if offset >= len(data):
            raise QPACKError("The field section prefix is truncated.")

        negative = bool(data[offset] & 0x80)
        delta, offset = Coding.read_integer(data, offset, 7)

        if ric != 0:
            raise QPACKError("The Required Insert Count is not zero, but no dynamic table was offered.")

        if negative or delta != 0:
            raise QPACKError("The Base does not match a Required Insert Count of zero.")

        fields: List[Tuple[str, str]] = []
        total = 0

        while offset < len(data):
            name, value, never, offset = self.line(data, offset)

            total += HPACKTable.cost(name, value)

            if total > self.max_header_list:
                raise QPACKError("The decoded header list is larger than allowed.")

            fields.append(HPACKField(name, value, never))

        return fields

    def line(self, data: bytes, offset: int) -> Tuple[str, str, bool, int]:
        byte = data[offset]

        if byte & 0x80: # indexed field line, §4.5.2
            static = bool(byte & 0x40)
            index, offset = Coding.read_integer(data, offset, 6)

            if not static:
                raise QPACKError("An indexed field line references the dynamic table.")

            name, value = self.entry(index)
            return (name, value, False, offset)

        if byte & 0x40: # literal field line with name reference, §4.5.4
            never = bool(byte & 0x20)
            static = bool(byte & 0x10)
            index, offset = Coding.read_integer(data, offset, 4)

            if not static:
                raise QPACKError("A literal field line references a dynamic name.")

            name, _ = self.entry(index)
            value, offset = self.string(data, offset)
            return (name, value, never, offset)

        if byte & 0x20: # literal field line with literal name, §4.5.6
            never = bool(byte & 0x10)
            huffman = bool(byte & 0x08)
            length, offset = Coding.read_integer(data, offset, 3)

            if offset + length > len(data):
                raise QPACKError("A literal name runs past the end of the block.")

            raw = data[offset:offset + length]
            offset += length

            try:
                name = (Huffman.decode(raw) if huffman else raw).decode("latin-1")

            except HPACKError as e:
                raise QPACKError(str(e))

            value, offset = self.string(data, offset)
            return (name, value, never, offset)

        raise QPACKError("The field line references the dynamic table, which is not offered.")

    def entry(self, index: int) -> Tuple[str, str]:
        if not 0 <= index < len(STATIC):
            raise QPACKError(f"The static table index {index} is out of range.")

        return STATIC[index]

    def string(self, data: bytes, offset: int) -> Tuple[str, int]:
        try:
            return Coding.read_string(data, offset)

        except HPACKError as e:
            raise QPACKError(str(e))
