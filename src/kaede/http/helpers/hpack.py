from typing import List, Dict, Tuple
from collections import deque

class HPACKError(Exception):
    """A malformed HPACK block, which HTTP/2 treats as a COMPRESSION_ERROR."""

class HPACKField(tuple):
    def __new__(cls, name: str, value: str, never: bool = False):
        field = super().__new__(cls, (name, value))
        field.never = never

        return field

    @property
    def name(self) -> str:
        return self[0]

    @property
    def value(self) -> str:
        return self[1]

class Huffman:
    CODES = [
        (0x1ff8, 13),
        (0x7fffd8, 23),
        (0xfffffe2, 28),
        (0xfffffe3, 28),
        (0xfffffe4, 28),
        (0xfffffe5, 28),
        (0xfffffe6, 28),
        (0xfffffe7, 28),
        (0xfffffe8, 28),
        (0xffffea, 24),
        (0x3ffffffc, 30),
        (0xfffffe9, 28),
        (0xfffffea, 28),
        (0x3ffffffd, 30),
        (0xfffffeb, 28),
        (0xfffffec, 28),
        (0xfffffed, 28),
        (0xfffffee, 28),
        (0xfffffef, 28),
        (0xffffff0, 28),
        (0xffffff1, 28),
        (0xffffff2, 28),
        (0x3ffffffe, 30),
        (0xffffff3, 28),
        (0xffffff4, 28),
        (0xffffff5, 28),
        (0xffffff6, 28),
        (0xffffff7, 28),
        (0xffffff8, 28),
        (0xffffff9, 28),
        (0xffffffa, 28),
        (0xffffffb, 28),
        (0x14, 6),
        (0x3f8, 10),
        (0x3f9, 10),
        (0xffa, 12),
        (0x1ff9, 13),
        (0x15, 6),
        (0xf8, 8),
        (0x7fa, 11),
        (0x3fa, 10),
        (0x3fb, 10),
        (0xf9, 8),
        (0x7fb, 11),
        (0xfa, 8),
        (0x16, 6),
        (0x17, 6),
        (0x18, 6),
        (0x0, 5),
        (0x1, 5),
        (0x2, 5),
        (0x19, 6),
        (0x1a, 6),
        (0x1b, 6),
        (0x1c, 6),
        (0x1d, 6),
        (0x1e, 6),
        (0x1f, 6),
        (0x5c, 7),
        (0xfb, 8),
        (0x7ffc, 15),
        (0x20, 6),
        (0xffb, 12),
        (0x3fc, 10),
        (0x1ffa, 13),
        (0x21, 6),
        (0x5d, 7),
        (0x5e, 7),
        (0x5f, 7),
        (0x60, 7),
        (0x61, 7),
        (0x62, 7),
        (0x63, 7),
        (0x64, 7),
        (0x65, 7),
        (0x66, 7),
        (0x67, 7),
        (0x68, 7),
        (0x69, 7),
        (0x6a, 7),
        (0x6b, 7),
        (0x6c, 7),
        (0x6d, 7),
        (0x6e, 7),
        (0x6f, 7),
        (0x70, 7),
        (0x71, 7),
        (0x72, 7),
        (0xfc, 8),
        (0x73, 7),
        (0xfd, 8),
        (0x1ffb, 13),
        (0x7fff0, 19),
        (0x1ffc, 13),
        (0x3ffc, 14),
        (0x22, 6),
        (0x7ffd, 15),
        (0x3, 5),
        (0x23, 6),
        (0x4, 5),
        (0x24, 6),
        (0x5, 5),
        (0x25, 6),
        (0x26, 6),
        (0x27, 6),
        (0x6, 5),
        (0x74, 7),
        (0x75, 7),
        (0x28, 6),
        (0x29, 6),
        (0x2a, 6),
        (0x7, 5),
        (0x2b, 6),
        (0x76, 7),
        (0x2c, 6),
        (0x8, 5),
        (0x9, 5),
        (0x2d, 6),
        (0x77, 7),
        (0x78, 7),
        (0x79, 7),
        (0x7a, 7),
        (0x7b, 7),
        (0x7ffe, 15),
        (0x7fc, 11),
        (0x3ffd, 14),
        (0x1ffd, 13),
        (0xffffffc, 28),
        (0xfffe6, 20),
        (0x3fffd2, 22),
        (0xfffe7, 20),
        (0xfffe8, 20),
        (0x3fffd3, 22),
        (0x3fffd4, 22),
        (0x3fffd5, 22),
        (0x7fffd9, 23),
        (0x3fffd6, 22),
        (0x7fffda, 23),
        (0x7fffdb, 23),
        (0x7fffdc, 23),
        (0x7fffdd, 23),
        (0x7fffde, 23),
        (0xffffeb, 24),
        (0x7fffdf, 23),
        (0xffffec, 24),
        (0xffffed, 24),
        (0x3fffd7, 22),
        (0x7fffe0, 23),
        (0xffffee, 24),
        (0x7fffe1, 23),
        (0x7fffe2, 23),
        (0x7fffe3, 23),
        (0x7fffe4, 23),
        (0x1fffdc, 21),
        (0x3fffd8, 22),
        (0x7fffe5, 23),
        (0x3fffd9, 22),
        (0x7fffe6, 23),
        (0x7fffe7, 23),
        (0xffffef, 24),
        (0x3fffda, 22),
        (0x1fffdd, 21),
        (0xfffe9, 20),
        (0x3fffdb, 22),
        (0x3fffdc, 22),
        (0x7fffe8, 23),
        (0x7fffe9, 23),
        (0x1fffde, 21),
        (0x7fffea, 23),
        (0x3fffdd, 22),
        (0x3fffde, 22),
        (0xfffff0, 24),
        (0x1fffdf, 21),
        (0x3fffdf, 22),
        (0x7fffeb, 23),
        (0x7fffec, 23),
        (0x1fffe0, 21),
        (0x1fffe1, 21),
        (0x3fffe0, 22),
        (0x1fffe2, 21),
        (0x7fffed, 23),
        (0x3fffe1, 22),
        (0x7fffee, 23),
        (0x7fffef, 23),
        (0xfffea, 20),
        (0x3fffe2, 22),
        (0x3fffe3, 22),
        (0x3fffe4, 22),
        (0x7ffff0, 23),
        (0x3fffe5, 22),
        (0x3fffe6, 22),
        (0x7ffff1, 23),
        (0x3ffffe0, 26),
        (0x3ffffe1, 26),
        (0xfffeb, 20),
        (0x7fff1, 19),
        (0x3fffe7, 22),
        (0x7ffff2, 23),
        (0x3fffe8, 22),
        (0x1ffffec, 25),
        (0x3ffffe2, 26),
        (0x3ffffe3, 26),
        (0x3ffffe4, 26),
        (0x7ffffde, 27),
        (0x7ffffdf, 27),
        (0x3ffffe5, 26),
        (0xfffff1, 24),
        (0x1ffffed, 25),
        (0x7fff2, 19),
        (0x1fffe3, 21),
        (0x3ffffe6, 26),
        (0x7ffffe0, 27),
        (0x7ffffe1, 27),
        (0x3ffffe7, 26),
        (0x7ffffe2, 27),
        (0xfffff2, 24),
        (0x1fffe4, 21),
        (0x1fffe5, 21),
        (0x3ffffe8, 26),
        (0x3ffffe9, 26),
        (0xffffffd, 28),
        (0x7ffffe3, 27),
        (0x7ffffe4, 27),
        (0x7ffffe5, 27),
        (0xfffec, 20),
        (0xfffff3, 24),
        (0xfffed, 20),
        (0x1fffe6, 21),
        (0x3fffe9, 22),
        (0x1fffe7, 21),
        (0x1fffe8, 21),
        (0x7ffff3, 23),
        (0x3fffea, 22),
        (0x3fffeb, 22),
        (0x1ffffee, 25),
        (0x1ffffef, 25),
        (0xfffff4, 24),
        (0xfffff5, 24),
        (0x3ffffea, 26),
        (0x7ffff4, 23),
        (0x3ffffeb, 26),
        (0x7ffffe6, 27),
        (0x3ffffec, 26),
        (0x3ffffed, 26),
        (0x7ffffe7, 27),
        (0x7ffffe8, 27),
        (0x7ffffe9, 27),
        (0x7ffffea, 27),
        (0x7ffffeb, 27),
        (0xffffffe, 28),
        (0x7ffffec, 27),
        (0x7ffffed, 27),
        (0x7ffffee, 27),
        (0x7ffffef, 27),
        (0x7fffff0, 27),
        (0x3ffffee, 26),
        (0x3fffffff, 30),
    ]

    EOS = 256

    tree = None

    @staticmethod
    def build():
        if Huffman.tree is not None:
            return Huffman.tree

        root: Dict = {}

        for symbol, (code, length) in enumerate(Huffman.CODES):
            if symbol == Huffman.EOS:
                continue

            node = root

            for position in range(length - 1, 0, -1):
                node = node.setdefault((code >> position) & 1, {})

            node[code & 1] = symbol

        Huffman.tree = root
        return root

    @staticmethod
    def encode(data: bytes) -> bytes:
        acc = 0
        bits = 0
        out = bytearray()

        for byte in data:
            code, length = Huffman.CODES[byte]
            acc = (acc << length) | code
            bits += length

            while bits >= 8:
                bits -= 8
                out.append((acc >> bits) & 0xFF)

            acc &= (1 << bits) - 1

        if bits:
            out.append(((acc << (8 - bits)) | ((1 << (8 - bits)) - 1)) & 0xFF)

        return bytes(out)

    @staticmethod
    def decode(data: bytes) -> bytes:
        root = Huffman.build()
        node = root
        out = bytearray()

        partial = 0
        ones = True

        for byte in data:
            for shift in range(7, -1, -1):
                bit = (byte >> shift) & 1

                partial += 1
                ones = ones and bit == 1

                node = node.get(bit)

                if node is None:
                    raise HPACKError("The Huffman code does not decode to a symbol.")

                if isinstance(node, int):
                    out.append(node)
                    node = root
                    partial = 0
                    ones = True

        if partial > 7 or not ones:
            raise HPACKError("The Huffman stream has invalid padding.")

        return bytes(out)

STATIC: List[Tuple[str, str]] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
]

STATIC_INDEX: Dict[Tuple[str, str], int] = {pair: number for number, pair in enumerate(STATIC, 1)}
STATIC_NAMES: Dict[str, int] = {}
for number, (name, value) in enumerate(STATIC, 1):
    STATIC_NAMES.setdefault(name, number)

SENSITIVE = frozenset({"authorization", "cookie", "set-cookie", "proxy-authorization"})

class HPACKTable:
    def __init__(self, capacity: int = 4096):
        self.capacity = capacity
        self.size = 0
        self.entries: deque = deque()

    @staticmethod
    def cost(name: str, value: str) -> int:
        return len(name) + len(value) + 32

    def add(self, name: str, value: str):
        cost = HPACKTable.cost(name, value)

        while self.entries and self.size + cost > self.capacity:
            old = self.entries.pop()
            self.size -= HPACKTable.cost(old[0], old[1])

        if cost <= self.capacity:
            self.entries.appendleft((name, value))
            self.size += cost

    def get(self, index: int) -> Tuple[str, str]:
        if not 0 <= index < len(self.entries):
            raise HPACKError(f"The dynamic table index {index} is out of range.")

        return self.entries[index]

    def resize(self, capacity: int):
        self.capacity = capacity

        while self.entries and self.size > self.capacity:
            old = self.entries.pop()
            self.size -= HPACKTable.cost(old[0], old[1])

    def __len__(self) -> int:
        return len(self.entries)

class Coding:
    @staticmethod
    def integer(value: int, prefix: int, flags: int = 0) -> bytes:
        cap = (1 << prefix) - 1

        if value < cap:
            return bytes([flags | value])

        out = bytearray([flags | cap])
        value -= cap

        while value >= 128:
            out.append((value & 0x7F) | 0x80)
            value >>= 7

        out.append(value)
        return bytes(out)

    @staticmethod
    def read_integer(data: bytes, offset: int, prefix: int) -> Tuple[int, int]:
        if offset >= len(data):
            raise HPACKError("An HPACK integer runs past the end of the block.")

        cap = (1 << prefix) - 1
        value = data[offset] & cap
        offset += 1

        if value < cap:
            return (value, offset)

        shift = 0

        while True:
            if offset >= len(data):
                raise HPACKError("An HPACK integer runs past the end of the block.")

            byte = data[offset]
            offset += 1
            value += (byte & 0x7F) << shift
            shift += 7

            if not byte & 0x80:
                break

            if shift > 63:
                raise HPACKError("An HPACK integer is too long.")

        if value > 0x3FFFFFFFFFFFFFFF:
            raise HPACKError("An HPACK integer is larger than 62 bits.")

        return (value, offset)

    @staticmethod
    def string(value: str, huffman: bool = True) -> bytes:
        raw = value.encode("latin-1")
        packed = Huffman.encode(raw)

        if huffman and len(packed) < len(raw):
            return Coding.integer(len(packed), 7, 0x80) + packed

        return Coding.integer(len(raw), 7, 0x00) + raw

    @staticmethod
    def read_string(data: bytes, offset: int) -> Tuple[str, int]:
        if offset >= len(data):
            raise HPACKError("An HPACK string runs past the end of the block.")

        huffman = bool(data[offset] & 0x80)
        length, offset = Coding.read_integer(data, offset, 7)

        if offset + length > len(data):
            raise HPACKError("An HPACK string runs past the end of the block.")

        raw = data[offset:offset + length]
        offset += length

        decoded = Huffman.decode(raw) if huffman else raw

        return (decoded.decode("latin-1"), offset)

class HPACKEncoder:
    def encode(self, headers: List[Tuple[str, str]]) -> bytes:
        out = bytearray()

        for field in headers:
            name, value = field
            name = name.lower()

            never = getattr(field, "never", None)
            never = name in SENSITIVE if never is None else never

            indexed = STATIC_INDEX.get((name, value))

            if indexed is not None and not never:
                out += Coding.integer(indexed, 7, 0x80)
                continue

            named = STATIC_NAMES.get(name)
            out += Coding.integer(named or 0, 4, 0x10 if never else 0x00)

            if not named:
                out += Coding.string(name)

            out += Coding.string(value)

        return bytes(out)

class HPACKDecoder:
    def __init__(self, capacity: int = 4096, max_header_list: int = 262144):
        self.table = HPACKTable(capacity)
        self.limit = capacity
        self.max_header_list = max_header_list

    def entry(self, index: int) -> Tuple[str, str]:
        if index == 0:
            raise HPACKError("The HPACK index 0 is not a valid reference.")

        if index <= len(STATIC):
            return STATIC[index - 1]

        return self.table.get(index - len(STATIC) - 1)

    def decode(self, data: bytes) -> List[Tuple[str, str]]:
        headers: List[Tuple[str, str]] = []
        offset = 0
        total = 0

        while offset < len(data):
            byte = data[offset]
            never = False

            if byte & 0x80: # indexed header field
                index, offset = Coding.read_integer(data, offset, 7)
                name, value = self.entry(index)

            elif byte & 0x40: # literal with incremental indexing
                name, value, offset = self.line(data, offset, 6)
                self.table.add(name, value)

            elif byte & 0x20: # dynamic table size update
                size, offset = Coding.read_integer(data, offset, 5)

                if size > self.limit:
                    raise HPACKError("A dynamic table size update exceeds the negotiated maximum.")

                self.table.resize(size)
                continue

            else: # literal without indexing (0x00) or never indexed (0x10)
                never = bool(byte & 0x10)
                name, value, offset = self.line(data, offset, 4)

            total += HPACKTable.cost(name, value)

            if total > self.max_header_list:
                raise HPACKError("The decoded header list is larger than the negotiated maximum.")

            headers.append(HPACKField(name, value, never))

        return headers

    def line(self, data: bytes, offset: int, prefix: int) -> Tuple[str, str, int]:
        index, offset = Coding.read_integer(data, offset, prefix)

        if index:
            name, _ = self.entry(index)
        else:
            name, offset = Coding.read_string(data, offset)

        value, offset = Coding.read_string(data, offset)

        return (name, value, offset)
