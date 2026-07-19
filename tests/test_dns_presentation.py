import base64
import ipaddress

from kaede.dns import DNSRecordType
from kaede.dns.records import (
    RawRecordData, RRSIGRecordData, NSECRecordData, NSEC3RecordData,
    NSEC3PARAMRecordData, SVCBRecordData, HTTPSRecordData
)

# The expected presentation strings below are written from the RFCs that define each
# record's presentation format, not from Kaede's output. Kaede follows the convention
# already used by its A/MX/DS/TLSA renderers: names carry no trailing root dot and
# hexadecimal/Base32hex fields are upper-cased (both are case-insensitive per the RFCs).

def base32hex(text: str) -> bytes:
    # Base32hex (RFC 4648 section 7) decode, independent of base64.b32hexdecode which is 3.10+.
    swap = str.maketrans("0123456789ABCDEFGHIJKLMNOPQRSTUV", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

    return base64.b32decode(text.upper().translate(swap) + "=" * (-len(text) % 8))

class TestRRSIG:
    # RFC 5702 section 6.1 prints this A-covering RSA/SHA-256 signature.
    SIGNATURE = "kRCOH6u7l0QGy9qpC9l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEacFYK/lPtPiVYP4bwg=="

    def data(self) -> RRSIGRecordData:
        return RRSIGRecordData(
            type_covered=DNSRecordType.A, algorithm=8, labels=3, original_ttl=3600,
            expiration=RRSIGRecordData.moment("20300101000000"),
            inception=RRSIGRecordData.moment("20000101000000"),
            key_tag=9033, signer="example.net", signature=base64.b64decode(self.SIGNATURE)
        )

    def test_text_matches_rfc_4034_presentation(self):
        # RFC 4034 section 3.2: type-covered algorithm labels original-TTL
        # sig-expiration sig-inception key-tag signer's-name signature.
        assert self.data().text == f"A 8 3 3600 20300101000000 20000101000000 9033 example.net {self.SIGNATURE}"

    def test_from_text_round_trips_wire(self):
        data = self.data()
        parsed = RRSIGRecordData.from_text(data.text.split())

        assert parsed == data
        assert parsed.pack() == data.pack()

class TestNSEC:
    def data(self) -> NSECRecordData:
        # RFC 4034 section 6.1 example, whose bitmap includes the unknown TYPE1234.
        return NSECRecordData("host.example.com", (
            DNSRecordType.A, DNSRecordType.MX, DNSRecordType.RRSIG, DNSRecordType.NSEC, 1234
        ))

    def test_text_matches_rfc_4034_presentation(self):
        # RFC 4034 section 4.1.2: next-domain-name followed by the type mnemonics.
        assert self.data().text == "host.example.com A MX RRSIG NSEC TYPE1234"

    def test_from_text_round_trips_wire(self):
        data = self.data()
        parsed = NSECRecordData.from_text(data.text.split())

        assert parsed == data
        assert parsed.pack() == data.pack()

class TestNSEC3:
    def data(self) -> NSEC3RecordData:
        # RFC 5155 section 7.3 / Appendix B example.
        return NSEC3RecordData(
            algorithm=1, flags=1, iterations=12, salt=bytes.fromhex("aabbccdd"),
            next_hashed=base32hex("2T7B4G4VSA5SMI47K61MV5BV1A22BOJR"),
            types=(DNSRecordType.MX, DNSRecordType.DNSKEY, DNSRecordType.NS,
                   DNSRecordType.SOA, DNSRecordType.NSEC3PARAM, DNSRecordType.RRSIG)
        )

    def test_text_matches_rfc_5155_presentation(self):
        # RFC 5155 section 3.3: hash-alg flags iterations salt next-hashed types.
        assert self.data().text == (
            "1 1 12 AABBCCDD 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR MX DNSKEY NS SOA NSEC3PARAM RRSIG"
        )

    def test_from_text_round_trips_wire(self):
        data = self.data()
        parsed = NSEC3RecordData.from_text(data.text.split())

        assert parsed == data
        assert parsed.pack() == data.pack()

class TestNSEC3PARAM:
    def test_text_matches_rfc_5155_presentation(self):
        # RFC 5155 section 4.3: hash-alg flags iterations salt.
        data = NSEC3PARAMRecordData(algorithm=1, flags=0, iterations=12, salt=bytes.fromhex("aabbccdd"))

        assert data.text == "1 0 12 AABBCCDD"

        parsed = NSEC3PARAMRecordData.from_text(data.text.split())

        assert parsed == data
        assert parsed.pack() == data.pack()

    def test_an_empty_salt_is_a_dash(self):
        # RFC 5155 section 4.3: a zero-length salt is written as "-".
        data = NSEC3PARAMRecordData(algorithm=1, flags=0, iterations=0, salt=b"")

        assert data.text == "1 0 0 -"

        parsed = NSEC3PARAMRecordData.from_text(data.text.split())

        assert parsed == data
        assert parsed.pack() == data.pack()

class TestSVCB:
    def test_text_matches_rfc_9460_presentation(self):
        # RFC 9460 section 2.2: SvcPriority TargetName then key=value SvcParams.
        data = HTTPSRecordData(1, "foo.example.com", params=(
            (SVCBRecordData.ALPN, b"\x02h2\x02h3"),
            (SVCBRecordData.PORT, (8443).to_bytes(2, "big")),
            (SVCBRecordData.IPV4HINT, ipaddress.IPv4Address("192.0.2.1").packed),
            (SVCBRecordData.ECH, b"\xde\xad\xbe\xef"),
            (SVCBRecordData.IPV6HINT, ipaddress.IPv6Address("2001:db8::1").packed),
        ))

        assert data.text == "1 foo.example.com alpn=h2,h3 port=8443 ipv4hint=192.0.2.1 ech=3q2+7w== ipv6hint=2001:db8::1"

        parsed = HTTPSRecordData.from_text(data.text.split())

        assert parsed == data
        assert parsed.pack() == data.pack()

    def test_mandatory_lists_key_mnemonics(self):
        # RFC 9460 sections 2.2 and 8: mandatory names the required keys.
        data = SVCBRecordData(16, "foo.example.org", params=(
            (SVCBRecordData.MANDATORY, b"\x00\x01\x00\x04"),
            (SVCBRecordData.ALPN, b"\x02h2\x05h3-19"),
            (SVCBRecordData.IPV4HINT, ipaddress.IPv4Address("192.0.2.1").packed),
        ))

        assert data.text == "16 foo.example.org mandatory=alpn,ipv4hint alpn=h2,h3-19 ipv4hint=192.0.2.1"

        parsed = SVCBRecordData.from_text(data.text.split())

        assert parsed == data
        assert parsed.pack() == data.pack()

    def test_a_valueless_key_renders_bare(self):
        # RFC 9460 section 7.1: no-default-alpn carries no value; "." is the root target.
        data = HTTPSRecordData(1, ".", params=(
            (SVCBRecordData.ALPN, b"\x02h2"),
            (SVCBRecordData.NO_DEFAULT_ALPN, b""),
        ))

        assert data.text == "1 . alpn=h2 no-default-alpn"

        parsed = HTTPSRecordData.from_text(data.text.split())

        assert parsed == data
        assert parsed.pack() == data.pack()

class TestRaw:
    def test_text_matches_rfc_3597_generic_format(self):
        # RFC 3597 section 5: \# <length> <hexdata>.
        data = RawRecordData(b"\x01\x02\x03", 999)

        assert data.text == "\\# 3 010203"

        parsed = RawRecordData.from_text(data.text.split())

        assert parsed.pack() == data.pack()

    def test_empty_data_is_length_zero(self):
        # RFC 3597 section 5: empty RDATA is "\# 0".
        data = RawRecordData(b"")

        assert data.text == "\\# 0"

        parsed = RawRecordData.from_text(data.text.split())

        assert parsed.pack() == data.pack()
