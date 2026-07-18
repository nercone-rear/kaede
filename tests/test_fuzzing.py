import os
import random
import struct

import pytest

from kaede.dns.models import DNSMessage, DNSName
from kaede.dns.errors import DNSError
from kaede.http.models import HTTPHeaders
from kaede.http.helpers.hpack import HPACKDecoder, HPACKError, Huffman
from kaede.http.helpers.qpack import QPACKDecoder, QPACKError
from kaede.http.protocol.h2 import H2Settings, H2Error
from kaede.http.websocket import WSFrame
from kaede.http.errors import WebSocketError

SEED = 1234567

def corpus_dns() -> bytes:
    message = DNSMessage(id=0x1234, response=True)
    message.questions.append(__import__("kaede.dns", fromlist=["DNSQuestion"]).DNSQuestion("www.example.com"))

    from kaede.dns import DNSRecord, DNSRecordType, EDNS
    from kaede.dns.records import ARecordData
    import ipaddress

    message.answers.append(DNSRecord("www.example.com", DNSRecordType.A, ARecordData(ipaddress.IPv4Address("192.0.2.1")), ttl=300))
    message.edns = EDNS()

    return message.pack()

class TestDNSFuzzing:
    def test_truncations_only_raise_the_error_family(self):
        wire = corpus_dns()

        for cut in range(len(wire) + 1):
            try:
                DNSMessage.unpack(wire[:cut])

            except DNSError:
                pass

    def test_random_mutations_only_raise_the_error_family(self):
        rng = random.Random(SEED)
        wire = corpus_dns()

        for _ in range(4000):
            data = bytearray(wire)

            for _ in range(rng.randint(1, 8)):
                data[rng.randrange(len(data))] = rng.randrange(256)

            try:
                message = DNSMessage.unpack(bytes(data))
                message.pack() # a parsed message must also re-pack without surprising errors

            except DNSError:
                pass

    def test_random_bytes_only_raise_the_error_family(self):
        rng = random.Random(SEED + 1)

        for _ in range(4000):
            data = bytes(rng.randrange(256) for _ in range(rng.randint(0, 64)))

            try:
                DNSMessage.unpack(data)

            except DNSError:
                pass

    def test_name_parsing_never_hangs_or_crashes(self):
        rng = random.Random(SEED + 2)

        for _ in range(4000):
            data = bytes(rng.randrange(256) for _ in range(rng.randint(1, 48)))

            try:
                DNSName.unpack(data, 0)

            except DNSError:
                pass

class TestHTTPFuzzing:
    def test_header_parsing_only_raises_value_error(self):
        rng = random.Random(SEED + 3)
        pieces = [b"Host: x", b"X:y", b" fold", b"A:", b":", b"\r\n", b"\x00", b"Content-Length: 5", b"a b: c"]

        for _ in range(4000):
            block = b"\r\n".join(rng.choice(pieces) for _ in range(rng.randint(0, 6)))

            try:
                HTTPHeaders.parse(block, "HTTP/1.1")

            except ValueError:
                pass

    def test_hpack_decoding_only_raises_its_error(self):
        rng = random.Random(SEED + 4)

        for _ in range(6000):
            data = bytes(rng.randrange(256) for _ in range(rng.randint(0, 32)))

            try:
                HPACKDecoder().decode(data)

            except HPACKError:
                pass

    def test_huffman_decoding_only_raises_its_error(self):
        rng = random.Random(SEED + 5)

        for _ in range(6000):
            data = bytes(rng.randrange(256) for _ in range(rng.randint(0, 16)))

            try:
                Huffman.decode(data)

            except HPACKError:
                pass

    def test_qpack_decoding_only_raises_its_error(self):
        rng = random.Random(SEED + 6)

        for _ in range(6000):
            data = bytes(rng.randrange(256) for _ in range(rng.randint(0, 32)))

            try:
                QPACKDecoder().decode(data)

            except QPACKError:
                pass

    def test_settings_parsing_only_raises_h2_error(self):
        rng = random.Random(SEED + 7)

        for _ in range(4000):
            data = bytes(rng.randrange(256) for _ in range(rng.randint(0, 24)))

            try:
                H2Settings().apply(data)

            except H2Error:
                pass

class Streamed:
    def __init__(self, data: bytes):
        self.data = bytearray(data)

    async def receive_exactly(self, n: int) -> bytes:
        if len(self.data) < n:
            from kaede.tcp.errors import TCPClosedError
            raise TCPClosedError("out of data")

        out = bytes(self.data[:n])
        del self.data[:n]
        return out

class TestWebSocketFuzzing:
    async def test_frame_reading_only_raises_expected_errors(self):
        from kaede.tcp.errors import TCPError

        rng = random.Random(SEED + 8)

        for _ in range(6000):
            data = bytes(rng.randrange(256) for _ in range(rng.randint(0, 32)))

            try:
                await WSFrame.read(Streamed(data), limit=1 << 20)

            except (WebSocketError, TCPError):
                pass
