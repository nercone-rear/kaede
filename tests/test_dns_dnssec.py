import base64
import calendar

import pytest

from kaede.dns import DNSRecordType, DNSRecord, DNSRecords
from kaede.dns.records import ARecordData, MXRecordData, DSRecordData, DNSKEYRecordData, RRSIGRecordData
from kaede.dns.helpers import DNSSECValidator

import ipaddress

def moment(text: str) -> int:
    """A YYYYMMDDHHMMSS timestamp as the RRSIG presentation format uses."""

    return calendar.timegm((int(text[0:4]), int(text[4:6]), int(text[6:8]), int(text[8:10]), int(text[10:12]), int(text[12:14]), 0, 0, 0))

@pytest.fixture(scope="module")
def validator():
    return DNSSECValidator()

# RFC 5702 section 6.1: RSA/SHA-256.
RSA256_KEY = DNSRecord("example.net", DNSRecordType.DNSKEY, DNSKEYRecordData(256, 3, 8, base64.b64decode(
    "AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8PkxUdp6p/DlUmObdk="
)), ttl=3600)

RSA256_SET = DNSRecords([DNSRecord("www.example.net", DNSRecordType.A, ARecordData(ipaddress.IPv4Address("192.0.2.91")), ttl=3600)])

RSA256_SIG = DNSRecord("www.example.net", DNSRecordType.RRSIG, RRSIGRecordData(
    type_covered=DNSRecordType.A, algorithm=8, labels=3, original_ttl=3600,
    expiration=moment("20300101000000"), inception=moment("20000101000000"),
    key_tag=9033, signer="example.net",
    signature=base64.b64decode("kRCOH6u7l0QGy9qpC9l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEacFYK/lPtPiVYP4bwg==")
), ttl=3600)

# RFC 5702 section 6.2: RSA/SHA-512.
RSA512_KEY = DNSRecord("example.net", DNSRecordType.DNSKEY, DNSKEYRecordData(256, 3, 10, base64.b64decode(
    "AwEAAdHoNTOW+et86KuJOWRDp1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFDxj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8gpMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL"
)), ttl=3600)

RSA512_SIG = DNSRecord("www.example.net", DNSRecordType.RRSIG, RRSIGRecordData(
    type_covered=DNSRecordType.A, algorithm=10, labels=3, original_ttl=3600,
    expiration=moment("20300101000000"), inception=moment("20000101000000"),
    key_tag=3740, signer="example.net",
    signature=base64.b64decode(
        "tsb4wnjRUDnB1BUi+t6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRaeUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOLDiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw="
    )
), ttl=3600)

# RFC 6605 section 6.1: ECDSA P-256/SHA-256.
P256_KEY = DNSRecord("example.net", DNSRecordType.DNSKEY, DNSKEYRecordData(257, 3, 13, base64.b64decode(
    "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA=="
)), ttl=3600)

P256_SET = DNSRecords([DNSRecord("www.example.net", DNSRecordType.A, ARecordData(ipaddress.IPv4Address("192.0.2.1")), ttl=3600)])

P256_SIG = DNSRecord("www.example.net", DNSRecordType.RRSIG, RRSIGRecordData(
    type_covered=DNSRecordType.A, algorithm=13, labels=3, original_ttl=3600,
    expiration=moment("20100909100439"), inception=moment("20100812100439"),
    key_tag=55648, signer="example.net",
    signature=base64.b64decode("qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXAyGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw==")
), ttl=3600)

P256_DS = DNSRecord("example.net", DNSRecordType.DS, DSRecordData(55648, 13, 2, bytes.fromhex(
    "b4c8c1fe2e7477127b27115656ad6256f424625bf5c1e2770ce6d6e37df61d17"
)))

# RFC 6605 section 6.2: ECDSA P-384/SHA-384.
P384_KEY = DNSRecord("example.net", DNSRecordType.DNSKEY, DNSKEYRecordData(257, 3, 14, base64.b64decode(
    "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40"
)), ttl=3600)

P384_SIG = DNSRecord("www.example.net", DNSRecordType.RRSIG, RRSIGRecordData(
    type_covered=DNSRecordType.A, algorithm=14, labels=3, original_ttl=3600,
    expiration=moment("20100909102025"), inception=moment("20100812102025"),
    key_tag=10771, signer="example.net",
    signature=base64.b64decode(
        "/L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuzWTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm"
    )
), ttl=3600)

P384_DS = DNSRecord("example.net", DNSRecordType.DS, DSRecordData(10771, 14, 4, bytes.fromhex(
    "72d7b62976ce06438e9c0bf319013cf801f09ecc84b8d7e9495f27e305c6a9b0563a9b5f4d288405c3008a946df983d6"
)))

# RFC 8080 section 6.1 as corrected by verified erratum 4935: Ed25519.
ED_KEY = DNSRecord("example.com", DNSRecordType.DNSKEY, DNSKEYRecordData(257, 3, 15, base64.b64decode(
    "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4="
)), ttl=3600)

ED_SET = DNSRecords([DNSRecord("example.com", DNSRecordType.MX, MXRecordData(10, "mail.example.com"), ttl=3600)])

ED_SIG = DNSRecord("example.com", DNSRecordType.RRSIG, RRSIGRecordData(
    type_covered=DNSRecordType.MX, algorithm=15, labels=2, original_ttl=3600,
    expiration=1440021600, inception=1438207200,
    key_tag=3613, signer="example.com",
    signature=base64.b64decode("oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeRAvTdszaPD+QLs3fx8A4M3e23mRZ9VrbpMngwcrqNAg==")
), ttl=3600)

ED_DS = DNSRecord("example.com", DNSRecordType.DS, DSRecordData(3613, 15, 2, bytes.fromhex(
    "3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79a304b"
)))

ED2_KEY = DNSRecord("example.com", DNSRecordType.DNSKEY, DNSKEYRecordData(257, 3, 15, base64.b64decode(
    "zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs="
)), ttl=3600)

ED2_SIG = DNSRecord("example.com", DNSRecordType.RRSIG, RRSIGRecordData(
    type_covered=DNSRecordType.MX, algorithm=15, labels=2, original_ttl=3600,
    expiration=1440021600, inception=1438207200,
    key_tag=35217, signer="example.com",
    signature=base64.b64decode("zXQ0bkYgQTEFyfLyi9QoiY6D8ZdYo4wyUhVioYZXFdT410QPRITQSqJSnzQoSm5poJ7gD7AQR0O7KuI5k2pcBg==")
), ttl=3600)

class TestKeyTags:
    # RFC 4034 Appendix B, checked against the tags the RFCs print.
    def test_rsa(self, validator):
        assert validator.keytag(RSA256_KEY.data) == 9033
        assert validator.keytag(RSA512_KEY.data) == 3740

    def test_ecdsa(self, validator):
        assert validator.keytag(P256_KEY.data) == 55648
        assert validator.keytag(P384_KEY.data) == 10771

    def test_ed25519(self, validator):
        assert validator.keytag(ED_KEY.data) == 3613
        assert validator.keytag(ED2_KEY.data) == 35217

class TestSignatures:
    def test_rsa_sha256(self, validator):
        assert validator.verify_rrset(RSA256_SET, RSA256_SIG, RSA256_KEY, now=1400000000)

    def test_rsa_sha512(self, validator):
        assert validator.verify_rrset(RSA256_SET, RSA512_SIG, RSA512_KEY, now=1400000000)

    def test_ecdsa_p256(self, validator):
        assert validator.verify_rrset(P256_SET, P256_SIG, P256_KEY, now=moment("20100820000000"))

    def test_ecdsa_p384(self, validator):
        assert validator.verify_rrset(P256_SET, P384_SIG, P384_KEY, now=moment("20100820000000"))

    def test_ed25519(self, validator):
        assert validator.verify_rrset(ED_SET, ED_SIG, ED_KEY, now=1439000000)
        assert validator.verify_rrset(ED_SET, ED2_SIG, ED2_KEY, now=1439000000)

    def test_uppercase_owners_still_verify(self, validator):
        # RFC 4034 section 6.2: the canonical form downcases the owner name.
        loud = DNSRecords([DNSRecord("WWW.Example.NET", DNSRecordType.A, ARecordData(ipaddress.IPv4Address("192.0.2.91")), ttl=3600)])

        assert validator.verify_rrset(loud, RSA256_SIG, RSA256_KEY, now=1400000000)

    def test_the_received_ttl_does_not_matter(self, validator):
        # RFC 4034 section 3.1.8.1: the original TTL from the RRSIG is used.
        aged = DNSRecords([DNSRecord("www.example.net", DNSRecordType.A, ARecordData(ipaddress.IPv4Address("192.0.2.91")), ttl=17)])

        assert validator.verify_rrset(aged, RSA256_SIG, RSA256_KEY, now=1400000000)

class TestRejections:
    def test_a_tampered_record_fails(self, validator):
        changed = DNSRecords([DNSRecord("www.example.net", DNSRecordType.A, ARecordData(ipaddress.IPv4Address("192.0.2.92")), ttl=3600)])

        assert not validator.verify_rrset(changed, RSA256_SIG, RSA256_KEY, now=1400000000)

    def test_a_tampered_signature_fails(self, validator):
        from dataclasses import replace

        broken = replace(RSA256_SIG.data, signature=bytes([RSA256_SIG.data.signature[0] ^ 1]) + RSA256_SIG.data.signature[1:])

        assert not validator.verify_rrset(RSA256_SET, DNSRecord("www.example.net", DNSRecordType.RRSIG, broken, ttl=3600), RSA256_KEY, now=1400000000)

    def test_time_outside_the_window_fails(self, validator):
        assert not validator.verify_rrset(P256_SET, P256_SIG, P256_KEY, now=moment("20110101000000"))
        assert not validator.verify_rrset(P256_SET, P256_SIG, P256_KEY, now=moment("20100801000000"))

    def test_the_wrong_key_fails(self, validator):
        assert not validator.verify_rrset(ED_SET, ED_SIG, ED2_KEY, now=1439000000)

    def test_a_revoked_or_non_zone_key_fails(self, validator):
        from dataclasses import replace

        host = DNSRecord("example.com", DNSRecordType.DNSKEY, replace(ED_KEY.data, flags=ED_KEY.data.flags & ~DNSKEYRecordData.ZONE_KEY), ttl=3600)

        assert not validator.verify_rrset(ED_SET, ED_SIG, host, now=1439000000)

    def test_an_unknown_algorithm_fails_closed(self, validator):
        assert not validator.crypto.verify(200, b"\x00" * 32, b"data", b"\x00" * 64)

class TestDelegations:
    def test_ds_digests_match_their_keys(self, validator):
        assert validator.verify_ds(P256_KEY, P256_DS)
        assert validator.verify_ds(P384_KEY, P384_DS)
        assert validator.verify_ds(ED_KEY, ED_DS)

    def test_a_foreign_key_does_not_match(self, validator):
        assert not validator.verify_ds(ED2_KEY, ED_DS)

    def test_a_tampered_digest_does_not_match(self, validator):
        from dataclasses import replace

        broken = DNSRecord("example.com", DNSRecordType.DS, replace(ED_DS.data, digest=bytes(32)))

        assert not validator.verify_ds(ED_KEY, broken)

    def test_a_sha1_ds_is_not_honoured(self, validator):
        # RFC 8624 section 3.3: SHA-1 DS digests are deprecated. Even a correctly
        # computed SHA-1 digest must not prove the delegation, so the zone falls
        # back to insecure rather than secure.
        import hashlib
        from kaede.dns import DNSName

        digest = hashlib.sha1(DNSName.wire("example.net") + P256_KEY.data.pack()).digest()
        sha1_ds = DNSRecord("example.net", DNSRecordType.DS, DSRecordData(55648, 13, 1, digest))

        assert not validator.verify_ds(P256_KEY, sha1_ds)

    def test_the_root_anchors_are_the_iana_set(self, validator):
        tags = {anchor.data.key_tag for anchor in DNSSECValidator.ANCHORS}

        assert tags == {20326, 38696}
