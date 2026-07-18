import ipaddress

import pytest

from kaede.dns import (
    DNSOpcode, DNSResponseCode, DNSRecordType, DNSRecordClass, DNSName,
    DNSQuestion, DNSRecord, DNSRecords, EDNS, DNSMessage
)
from kaede.dns.errors import DNSError, DNSFormatError, DNSNameError
from kaede.dns.records import (
    RawRecordData, ARecordData, AAAARecordData, NSRecordData, CNAMERecordData,
    PTRRecordData, SOARecordData, MXRecordData, TXTRecordData, SRVRecordData,
    CAARecordData, DSRecordData, DNSKEYRecordData, RRSIGRecordData,
    NSECRecordData, NSEC3RecordData, NSEC3PARAMRecordData, TLSARecordData,
    SVCBRecordData, HTTPSRecordData
)

def header(*, id=0, flags=0, qd=0, an=0, ns=0, ar=0) -> bytes:
    parts = bytearray()

    for value in (id, flags, qd, an, ns, ar):
        parts += value.to_bytes(2, "big")

    return bytes(parts)

class TestHeader:
    def test_the_flag_bits_sit_where_rfc_1035_says(self):
        # RFC 1035 section 4.1.1: QR(15) opcode(11-14) AA(10) TC(9) RD(8) RA(7) Z AD(5) CD(4) rcode(0-3)
        raw = header(id=0x1234, flags=0x8000 | (2 << 11) | 0x0400 | 0x0200 | 0x0100 | 0x0080 | 0x0020 | 0x0010 | 3)
        message = DNSMessage.unpack(raw)

        assert message.id == 0x1234
        assert message.response
        assert message.opcode == DNSOpcode.STATUS
        assert message.authoritative
        assert message.truncated
        assert message.recursion_desired
        assert message.recursion_available
        assert message.authentic
        assert message.check_disabled
        assert message.rcode == DNSResponseCode.NXDOMAIN

    def test_packing_reverses_the_bits(self):
        message = DNSMessage(id=0x1234, response=True, opcode=DNSOpcode.STATUS, authoritative=True, truncated=True,
                             recursion_desired=True, recursion_available=True, authentic=True, check_disabled=True,
                             rcode=DNSResponseCode.NXDOMAIN)

        assert message.pack() == header(id=0x1234, flags=0x8000 | (2 << 11) | 0x0400 | 0x0200 | 0x0100 | 0x0080 | 0x0020 | 0x0010 | 3)

    def test_an_unknown_rcode_is_kept_as_a_number(self):
        message = DNSMessage.unpack(header(flags=13))

        assert message.rcode == 13

    def test_a_short_header_is_rejected(self):
        with pytest.raises(DNSFormatError):
            DNSMessage.unpack(header()[:11])

class TestNames:
    def test_round_trips(self):
        message = bytearray()
        DNSName.pack("www.Example.COM", message, None)

        assert bytes(message) == b"\x03www\x07Example\x03COM\x00"
        assert DNSName.unpack(bytes(message), 0) == ("www.Example.COM", len(message))

    def test_the_root_is_a_single_zero(self):
        assert DNSName.wire("") == b"\x00"
        assert DNSName.wire(".") == b"\x00"
        assert DNSName.unpack(b"\x00", 0) == ("", 1)

    def test_compression_pointers_resolve(self):
        # RFC 1035 section 4.1.4: a pointer replaces an entire suffix.
        raw = b"\x07example\x03com\x00" + b"\x03www\xc0\x00"

        assert DNSName.unpack(raw, 13) == ("www.example.com", len(raw))

    def test_a_pointer_must_point_backward(self):
        with pytest.raises(DNSFormatError):
            DNSName.unpack(b"\xc0\x00", 0) # points at itself

        with pytest.raises(DNSFormatError):
            DNSName.unpack(b"\xc0\x04\x00\x00\x03www\x00", 0) # points forward

    def test_a_pointer_loop_is_rejected(self):
        # Two pointers referring to each other survive the backward rule alone.
        raw = b"\x01a\xc0\x04\x01b\xc0\x00"

        with pytest.raises(DNSError):
            DNSName.unpack(raw, 4)

    def test_the_reserved_length_bits_are_rejected(self):
        # RFC 1035 section 4.1.4: 0x40 and 0x80 are reserved.
        with pytest.raises(DNSFormatError):
            DNSName.unpack(b"\x41a\x00", 0)

    def test_a_label_longer_than_63_bytes_is_rejected(self):
        with pytest.raises(DNSNameError):
            DNSName.wire("a" * 64 + ".example")

    def test_a_name_longer_than_255_bytes_is_rejected(self):
        with pytest.raises(DNSNameError):
            DNSName.wire(".".join(["a" * 63] * 4) + ".example")

    def test_an_empty_label_is_rejected(self):
        with pytest.raises(DNSNameError):
            DNSName.wire("a..b")

    def test_escapes_round_trip(self):
        # RFC 1035 section 5.1: \. keeps a dot inside a label, \DDD is a raw byte.
        message = bytearray()
        DNSName.pack(r"a\.b.\032c", message, None)

        assert bytes(message) == b"\x03a.b\x02 c\x00"
        assert DNSName.unpack(bytes(message), 0) == (r"a\.b.\032c", len(message))

    def test_non_ascii_names_travel_as_idna(self):
        wire = DNSName.wire("日本語.jp")

        assert wire == b"\x0exn--wgv71a119e\x02jp\x00"

    def test_packing_compresses_repeated_suffixes(self):
        message = bytearray()
        pointers = {}

        DNSName.pack("example.com", message, pointers)
        before = len(message)
        DNSName.pack("www.example.com", message, pointers)

        assert len(message) - before == 4 + 2 # "www" plus one pointer
        assert DNSName.unpack(bytes(message), before) == ("www.example.com", len(message))

class TestMessages:
    def test_a_query_round_trips(self):
        message = DNSMessage(id=0x1234, questions=[DNSQuestion("example.com", DNSRecordType.A)])
        back = DNSMessage.unpack(message.pack())

        assert back.id == 0x1234
        assert not back.response
        assert back.recursion_desired
        assert back.questions == [DNSQuestion("example.com", DNSRecordType.A, DNSRecordClass.IN)]

    def test_a_response_with_every_section_round_trips(self):
        message = DNSMessage(id=1, response=True, questions=[DNSQuestion("example.com", DNSRecordType.A)])
        message.answers.append(DNSRecord("example.com", DNSRecordType.A, ARecordData(ipaddress.IPv4Address("192.0.2.1")), ttl=300))
        message.authorities.append(DNSRecord("example.com", DNSRecordType.NS, NSRecordData("ns1.example.com"), ttl=86400))
        message.additionals.append(DNSRecord("ns1.example.com", DNSRecordType.A, ARecordData(ipaddress.IPv4Address("192.0.2.53")), ttl=86400))

        back = DNSMessage.unpack(message.pack())

        assert back.answers[0].data.address == ipaddress.IPv4Address("192.0.2.1")
        assert back.authorities[0].data.target == "ns1.example.com"
        assert back.additionals[0].name == "ns1.example.com"
        assert back.answers[0].ttl == 300

    def test_a_hand_built_wire_message_parses(self):
        raw = header(id=1, flags=0x8180, qd=1, an=1)
        raw += b"\x03www\x07example\x03com\x00" + b"\x00\x01\x00\x01"
        raw += b"\xc0\x0c" + b"\x00\x01\x00\x01" + (300).to_bytes(4, "big") + b"\x00\x04" + bytes([192, 0, 2, 1])

        message = DNSMessage.unpack(raw)

        assert message.answers[0].name == "www.example.com"
        assert message.answers[0].data.address == ipaddress.IPv4Address("192.0.2.1")

    def test_trailing_bytes_are_rejected(self):
        with pytest.raises(DNSFormatError):
            DNSMessage.unpack(header() + b"\x00")

    def test_every_truncation_is_rejected(self):
        message = DNSMessage(id=1, response=True, questions=[DNSQuestion("example.com", DNSRecordType.A)], edns=EDNS())
        message.answers.append(DNSRecord("example.com", DNSRecordType.MX, MXRecordData(10, "mail.example.com"), ttl=300))
        wire = message.pack()

        for cut in range(len(wire)):
            with pytest.raises(DNSError):
                DNSMessage.unpack(wire[:cut])

    def test_an_unknown_record_type_is_kept_raw(self):
        raw = header(qd=0, an=1)
        raw += b"\x00" + (999).to_bytes(2, "big") + b"\x00\x01" + (0).to_bytes(4, "big") + b"\x00\x03abc"

        message = DNSMessage.unpack(raw)
        record = message.answers[0]

        assert record.type == 999
        assert isinstance(record.data, RawRecordData)
        assert record.data.raw == b"abc"
        assert record.data.rtype_unknown == 999
        assert DNSMessage.unpack(message.pack()).answers[0].data.raw == b"abc"

    def test_reply_echoes_the_question(self):
        query = DNSMessage(id=7, questions=[DNSQuestion("example.com", DNSRecordType.A)], edns=EDNS())
        reply = query.reply(rcode=DNSResponseCode.NXDOMAIN)

        assert reply.id == 7
        assert reply.response
        assert reply.questions == query.questions
        assert reply.rcode == DNSResponseCode.NXDOMAIN
        assert reply.edns is not None

class TestEDNS:
    def test_the_opt_record_is_synthesized_and_extracted(self):
        message = DNSMessage(id=1, questions=[DNSQuestion("example.com", DNSRecordType.A)], edns=EDNS(payload_size=4096, do=True, options=[(10, b"\x01\x02")]))
        wire = message.pack()
        back = DNSMessage.unpack(wire)

        assert back.edns is not None
        assert back.edns.payload_size == 4096
        assert back.edns.do
        assert back.edns.version == 0
        assert back.edns.options == [(10, b"\x01\x02")]
        assert len(back.additionals) == 0 # the OPT record must not leak into the section

    def test_the_extended_rcode_is_split_across_opt_and_header(self):
        # RFC 6891 section 6.1.3: the upper 8 bits live in the OPT TTL.
        message = DNSMessage(id=1, response=True, rcode=DNSResponseCode.BADVERS, edns=EDNS())
        wire = message.pack()
        back = DNSMessage.unpack(wire)

        assert back.rcode == DNSResponseCode.BADVERS
        assert wire[3] & 0xF == 0 # BADVERS is 16, so the header keeps only the low nibble

    def test_an_extended_rcode_without_edns_cannot_be_packed(self):
        with pytest.raises(DNSFormatError):
            DNSMessage(rcode=DNSResponseCode.BADVERS).pack()

    def test_two_opt_records_are_rejected(self):
        # RFC 6891 section 6.1.1: more than one OPT is FORMERR.
        opt = b"\x00" + (41).to_bytes(2, "big") + (1232).to_bytes(2, "big") + (0).to_bytes(4, "big") + b"\x00\x00"
        raw = header(ar=2) + opt + opt

        with pytest.raises(DNSFormatError):
            DNSMessage.unpack(raw)

    def test_an_opt_record_not_owned_by_the_root_is_rejected(self):
        raw = header(ar=1) + b"\x01a\x00" + (41).to_bytes(2, "big") + (1232).to_bytes(2, "big") + (0).to_bytes(4, "big") + b"\x00\x00"

        with pytest.raises(DNSFormatError):
            DNSMessage.unpack(raw)

class TestRecordData:
    def round_trip(self, rtype, data):
        message = DNSMessage(id=1, response=True)
        message.answers.append(DNSRecord("test.example", rtype, data, ttl=60))

        back = DNSMessage.unpack(message.pack())

        assert back.answers[0].data == data
        return back.answers[0].data

    def test_a(self):
        self.round_trip(DNSRecordType.A, ARecordData(ipaddress.IPv4Address("192.0.2.1")))

    def test_aaaa(self):
        self.round_trip(DNSRecordType.AAAA, AAAARecordData(ipaddress.IPv6Address("2001:db8::1")))

    def test_ns_cname_ptr(self):
        self.round_trip(DNSRecordType.NS, NSRecordData("ns.example.com"))
        self.round_trip(DNSRecordType.CNAME, CNAMERecordData("target.example.com"))
        self.round_trip(DNSRecordType.PTR, PTRRecordData("host.example.com"))

    def test_soa(self):
        self.round_trip(DNSRecordType.SOA, SOARecordData("ns.example.com", "hostmaster.example.com", 2024010101, 7200, 3600, 1209600, 3600))

    def test_mx(self):
        self.round_trip(DNSRecordType.MX, MXRecordData(10, "mail.example.com"))

    def test_txt(self):
        self.round_trip(DNSRecordType.TXT, TXTRecordData((b"v=spf1 -all", b"second")))

    def test_a_txt_string_cannot_exceed_255_bytes(self):
        with pytest.raises(DNSFormatError):
            TXTRecordData((b"a" * 256,)).pack()

    def test_srv(self):
        self.round_trip(DNSRecordType.SRV, SRVRecordData(0, 5, 5060, "sip.example.com"))

    def test_caa(self):
        self.round_trip(DNSRecordType.CAA, CAARecordData(0, "issue", b"letsencrypt.org"))

    def test_ds(self):
        self.round_trip(DNSRecordType.DS, DSRecordData(20326, 8, 2, bytes.fromhex("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D")))

    def test_dnskey(self):
        self.round_trip(DNSRecordType.DNSKEY, DNSKEYRecordData(257, 3, 8, b"\x03\x01\x00\x01" + b"k" * 64))

    def test_rrsig(self):
        data = RRSIGRecordData(
            type_covered=DNSRecordType.A, algorithm=8, labels=2, original_ttl=3600,
            expiration=1893456000, inception=1577836800, key_tag=12345,
            signer="example.com", signature=b"s" * 128
        )
        back = self.round_trip(DNSRecordType.RRSIG, data)

        assert back.signer == "example.com"
        assert back.signature == b"s" * 128

    def test_nsec(self):
        self.round_trip(DNSRecordType.NSEC, NSECRecordData("next.example.com", (DNSRecordType.A, DNSRecordType.MX, DNSRecordType.RRSIG, DNSRecordType.NSEC, DNSRecordType.CAA)))

    def test_nsec3(self):
        self.round_trip(DNSRecordType.NSEC3, NSEC3RecordData(1, 0, 10, b"\xab\xcd", b"\x01" * 20, (DNSRecordType.A, DNSRecordType.SOA)))

    def test_nsec3param(self):
        self.round_trip(DNSRecordType.NSEC3PARAM, NSEC3PARAMRecordData(1, 0, 10, b"\xab\xcd"))

    def test_tlsa(self):
        self.round_trip(DNSRecordType.TLSA, TLSARecordData(3, 1, 1, b"\x99" * 32))

    def test_svcb_and_https(self):
        data = HTTPSRecordData(1, "", params=(
            (SVCBRecordData.ALPN, b"\x02h2\x02h3"),
            (SVCBRecordData.PORT, (8443).to_bytes(2, "big")),
            (SVCBRecordData.IPV4HINT, ipaddress.IPv4Address("192.0.2.1").packed),
            (SVCBRecordData.IPV6HINT, ipaddress.IPv6Address("2001:db8::1").packed),
        ))
        back = self.round_trip(DNSRecordType.HTTPS, data)

        assert back.alpn == ["h2", "h3"]
        assert back.port == 8443
        assert back.ipv4hints == [ipaddress.IPv4Address("192.0.2.1")]
        assert back.ipv6hints == [ipaddress.IPv6Address("2001:db8::1")]
        assert back.ech is None

    def test_svcb_params_must_be_strictly_increasing(self):
        # RFC 9460 section 2.2.
        rdata = (1).to_bytes(2, "big") + b"\x00"
        rdata += (3).to_bytes(2, "big") + (2).to_bytes(2, "big") + (443).to_bytes(2, "big")
        rdata += (1).to_bytes(2, "big") + (3).to_bytes(2, "big") + b"\x02h2"

        raw = header(an=1) + b"\x00" + (64).to_bytes(2, "big") + b"\x00\x01" + (0).to_bytes(4, "big") + len(rdata).to_bytes(2, "big") + rdata

        with pytest.raises(DNSFormatError):
            DNSMessage.unpack(raw)

    def test_names_inside_rdata_may_arrive_compressed(self):
        # RFC 1035 allows pointers in the RDATA of the well-known types.
        raw = header(qd=1, an=1)
        raw += b"\x07example\x03com\x00" + b"\x00\x0f\x00\x01"
        rdata = (10).to_bytes(2, "big") + b"\x04mail\xc0\x0c"
        raw += b"\xc0\x0c" + b"\x00\x0f\x00\x01" + (300).to_bytes(4, "big") + len(rdata).to_bytes(2, "big") + rdata

        message = DNSMessage.unpack(raw)

        assert message.answers[0].data == MXRecordData(10, "mail.example.com")

class TestRecords:
    def test_bytes_are_rejected_with_direction(self):
        with pytest.raises(DNSFormatError):
            DNSRecords(b"\x00\x01")

    def test_find_is_case_insensitive(self):
        records = DNSRecords([DNSRecord("WWW.Example.COM", DNSRecordType.A, ARecordData(ipaddress.IPv4Address("192.0.2.1")))])

        assert len(records.find(name="www.example.com.")) == 1
        assert records.first(DNSRecordType.A) is not None
        assert records.first(DNSRecordType.MX) is None

    def test_presentation_lines_parse(self):
        records = DNSRecords(
            "example.com 300 IN MX 10 mail.example.com ; the primary\n"
            "\n"
            'example.com 300 IN TXT "v=spf1 include:_spf.example.com -all"\n'
            "IN-ttl-order.example IN 60 A 192.0.2.7\n"
        )

        assert records[0].data == MXRecordData(10, "mail.example.com")
        assert records[0].ttl == 300
        assert records[1].data.strings == (b"v=spf1 include:_spf.example.com -all",)
        assert records[2].ttl == 60
        assert records[2].rclass == DNSRecordClass.IN

    def test_an_unknown_presentation_type_is_rejected(self):
        with pytest.raises(DNSFormatError):
            DNSRecords("example.com 300 IN WKS 192.0.2.1")

    def test_an_unterminated_quote_is_rejected(self):
        with pytest.raises(DNSFormatError):
            DNSRecords('example.com 300 IN TXT "unterminated')
