from __future__ import annotations

import os
import struct

from .crypto import LEVEL_INITIAL, LEVEL_EARLY, LEVEL_HANDSHAKE

PACKET_TYPE_INITIAL = 0x00
PACKET_TYPE_0RTT = 0x01
PACKET_TYPE_HANDSHAKE = 0x02
PACKET_TYPE_RETRY = 0x03

PACKET_LONG_HEADER = 0x80
PACKET_FIXED_BIT = 0x40

QUIC_VERSION_1 = 0x00000001

TYPE_TO_LEVEL = {
    PACKET_TYPE_INITIAL: LEVEL_INITIAL,
    PACKET_TYPE_0RTT: LEVEL_EARLY,
    PACKET_TYPE_HANDSHAKE: LEVEL_HANDSHAKE,
}

def level_for_long_type(packet_type: int) -> int:
    return TYPE_TO_LEVEL[packet_type]

class BufferError(ValueError):
    pass

class Buffer:
    def __init__(self, data: bytes = b""):
        self._data = bytearray(data)
        self.pos = 0

    @property
    def data(self) -> bytes:
        return bytes(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def tell(self) -> int:
        return self.pos

    def seek(self, pos: int):
        self.pos = pos

    def remaining(self) -> int:
        return len(self._data) - self.pos

    def eof(self) -> bool:
        return self.pos >= len(self._data)

    def pull_bytes(self, length: int) -> bytes:
        if length < 0 or self.pos + length > len(self._data):
            raise BufferError("read past end of buffer")

        out = bytes(self._data[self.pos:self.pos+length])
        self.pos += length
        return out

    def pull_uint8(self) -> int:
        return self.pull_bytes(1)[0]

    def pull_uint16(self) -> int:
        return struct.unpack("!H", self.pull_bytes(2))[0]

    def pull_uint32(self) -> int:
        return struct.unpack("!I", self.pull_bytes(4))[0]

    def pull_uint64(self) -> int:
        return struct.unpack("!Q", self.pull_bytes(8))[0]

    def pull_uint_var(self) -> int:
        first = self.pull_uint8()
        prefix = first >> 6
        length = 1 << prefix
        value = first & 0x3F

        for _ in range(length - 1):
            value = (value << 8) | self.pull_uint8()

        return value

    def push_bytes(self, data: bytes):
        self._data.extend(data)

    def push_uint8(self, value: int):
        self._data.append(value & 0xFF)

    def push_uint16(self, value: int):
        self._data.extend(struct.pack("!H", value))

    def push_uint32(self, value: int):
        self._data.extend(struct.pack("!I", value))

    def push_uint64(self, value: int):
        self._data.extend(struct.pack("!Q", value))

    def push_uint_var(self, value: int):
        self._data.extend(encode_uint_var(value))

def encode_uint_var(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint cannot be negative")
    if value < 0x40:
        return bytes([value])
    if value < 0x4000:
        return struct.pack("!H", value | 0x4000)
    if value < 0x40000000:
        return struct.pack("!I", value | 0x80000000)
    if value < 0x4000000000000000:
        return struct.pack("!Q", value | 0xC000000000000000)
    raise ValueError("varint out of range")

def size_uint_var(value: int) -> int:
    if value < 0x40:
        return 1
    if value < 0x4000:
        return 2
    if value < 0x40000000:
        return 4
    return 8

def encode_packet_number(full_pn: int, largest_acked: int | None) -> tuple[int, int]:
    if largest_acked is None:
        num_unacked = full_pn + 1
    else:
        num_unacked = full_pn - largest_acked

    min_bits = max(num_unacked.bit_length() + 1, 1)
    num_bytes = (min_bits + 7) // 8
    num_bytes = max(1, min(4, num_bytes))
    mask = (1 << (num_bytes * 8)) - 1
    return full_pn & mask, num_bytes

def decode_packet_number(truncated: int, num_bytes: int, largest_pn: int) -> int:
    pn_bits = num_bytes * 8
    pn_win = 1 << pn_bits
    pn_hwin = pn_win // 2
    pn_mask = pn_win - 1

    expected = largest_pn + 1
    candidate = (expected & ~pn_mask) | truncated

    if candidate <= expected - pn_hwin and candidate < (1 << 62) - pn_win:
        return candidate + pn_win
    if candidate > expected + pn_hwin and candidate >= pn_win:
        return candidate - pn_win
    return candidate

class LongHeader:
    __slots__ = ("packet_type", "version", "destination_cid", "source_cid", "token", "length", "pn_offset")

    def __init__(self, packet_type, version, destination_cid, source_cid, token, length, pn_offset):
        self.packet_type = packet_type
        self.version = version
        self.destination_cid = destination_cid
        self.source_cid = source_cid
        self.token = token
        self.length = length
        self.pn_offset = pn_offset

def is_long_header(first_byte: int) -> bool:
    return bool(first_byte & PACKET_LONG_HEADER)

def parse_long_header(datagram: bytes, offset: int = 0) -> LongHeader:
    buf = Buffer(datagram)
    buf.seek(offset)

    first = buf.pull_uint8()

    if not (first & PACKET_LONG_HEADER) or not (first & PACKET_FIXED_BIT):
        raise BufferError("not a long header")

    version = buf.pull_uint32()
    dcid_len = buf.pull_uint8()
    dcid = buf.pull_bytes(dcid_len)
    scid_len = buf.pull_uint8()
    scid = buf.pull_bytes(scid_len)

    packet_type = (first & 0x30) >> 4

    token = b""
    if packet_type == PACKET_TYPE_INITIAL:
        token_len = buf.pull_uint_var()
        token = buf.pull_bytes(token_len)

    if packet_type == PACKET_TYPE_RETRY:
        remaining = buf.remaining()
        if remaining < 16:
            raise BufferError("Retry packet too short for integrity tag")
        token = buf.pull_bytes(remaining - 16)
        length = 16
        pn_offset = buf.tell()
    else:
        length = buf.pull_uint_var()
        pn_offset = buf.tell()

    return LongHeader(packet_type, version, dcid, scid, token, length, pn_offset)

def serialize_long_header_prefix(packet_type: int, version: int, dcid: bytes, scid: bytes, token: bytes, pn_length: int, payload_length: int) -> tuple[bytes, int]:
    buf = Buffer()

    first = PACKET_LONG_HEADER | PACKET_FIXED_BIT | (packet_type << 4) | (pn_length - 1)

    buf.push_uint8(first)
    buf.push_uint32(version)
    buf.push_uint8(len(dcid))
    buf.push_bytes(dcid)
    buf.push_uint8(len(scid))
    buf.push_bytes(scid)

    if packet_type == PACKET_TYPE_INITIAL:
        buf.push_uint_var(len(token))
        buf.push_bytes(token)

    buf.push_uint_var(pn_length + payload_length)

    return buf.data, first

def build_version_negotiation(client_dcid: bytes, client_scid: bytes) -> bytes:
    buf = Buffer()
    buf.push_uint8(0x80 | (os.urandom(1)[0] & 0x7F))
    buf.push_uint32(0)
    buf.push_uint8(len(client_scid))
    buf.push_bytes(client_scid)
    buf.push_uint8(len(client_dcid))
    buf.push_bytes(client_dcid)
    buf.push_uint32(QUIC_VERSION_1)
    return buf.data

def serialize_short_header_prefix(dcid: bytes, pn_length: int, *, spin: bool = False, key_phase: bool = False) -> tuple[bytes, int]:
    buf = Buffer()
    first = PACKET_FIXED_BIT | (pn_length - 1)

    if spin:
        first |= 0x20

    if key_phase:
        first |= 0x04

    buf.push_uint8(first)
    buf.push_bytes(dcid)

    return buf.data, first
