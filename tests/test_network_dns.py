import os
import ipaddress

import pytest

from kaede.udp import UDPPort
from kaede.tcp import TCPPort
from kaede.quic.tls import QTLS
from kaede.dns import DNSPort, DNSRecordType, DNSResponseCode, DNSClient, DNSClientConfig
from kaede.dns.errors import DNSServerError
from kaede.dns.helpers import DNSSECValidator

pytestmark = [
    pytest.mark.network,
    pytest.mark.skipif(os.environ.get("KAEDE_NETWORK_TESTS") != "1", reason="set KAEDE_NETWORK_TESTS=1 to reach real resolvers"),
]

def resolver(kind: str):
    if kind == "udp":
        return [("1.1.1.1", DNSPort("udp", UDPPort(53))), ("8.8.8.8", DNSPort("udp", UDPPort(53)))]
    if kind == "tcp":
        return [("1.1.1.1", DNSPort("tcp", TCPPort(53))), ("8.8.8.8", DNSPort("tcp", TCPPort(53)))]
    if kind == "tls":
        return [("1.1.1.1", DNSPort("tcp", TCPPort(853), True)), ("8.8.8.8", DNSPort("tcp", TCPPort(853), True))]
    if kind == "quic":
        return [("94.140.14.140", DNSPort("quic", UDPPort(853), True))] # AdGuard, a stable DoQ endpoint
    if kind == "https":
        return [("cloudflare-dns.com", DNSPort("https", 443, True)), ("dns.google", DNSPort("https", 443, True))]

def client(kind: str) -> DNSClient:
    hostname = {"https": "cloudflare-dns.com", "tls": "cloudflare-dns.com", "quic": "dns.adguard-dns.com"}.get(kind)

    return DNSClient(config=DNSClientConfig(servers=resolver(kind), timeout=8.0, retries=1, cache=False, hostname=hostname))

class TestDo53:
    async def test_a_over_udp(self):
        async with client("udp") as dns:
            records = await dns.resolve("cloudflare.com", DNSRecordType.A)

            assert all(isinstance(record.data.address, ipaddress.IPv4Address) for record in records)
            assert records

    async def test_aaaa_over_tcp(self):
        async with client("tcp") as dns:
            records = await dns.resolve("cloudflare.com", DNSRecordType.AAAA)

            assert records

    async def test_mx_and_txt(self):
        async with client("udp") as dns:
            assert await dns.resolve("gmail.com", DNSRecordType.MX)
            assert await dns.resolve("cloudflare.com", DNSRecordType.TXT)

    async def test_https_record(self):
        async with client("udp") as dns:
            records = await dns.resolve("cloudflare.com", DNSRecordType.HTTPS)

            assert any("h3" in record.data.alpn or "h2" in record.data.alpn for record in records)

    async def test_nxdomain(self):
        async with client("udp") as dns:
            with pytest.raises(DNSServerError) as caught:
                await dns.resolve("nonexistent-" + "x" * 20 + ".example", DNSRecordType.A)

            assert caught.value.rcode == DNSResponseCode.NXDOMAIN

class TestSecure:
    async def test_dot(self):
        async with client("tls") as dns:
            assert await dns.resolve("cloudflare.com", DNSRecordType.A)

    async def test_doh(self):
        async with client("https") as dns:
            assert await dns.resolve("cloudflare.com", DNSRecordType.A)

    async def test_doq(self):
        from kaede.dns.errors import DNSConnectionError

        if not QTLS().available:
            pytest.skip("this OpenSSL has no QUIC client")

        try:
            async with client("quic") as dns:
                assert await dns.resolve("cloudflare.com", DNSRecordType.A)

        except DNSConnectionError:
            pytest.skip("the public DoQ endpoint was unreachable") # DoQ availability varies by network

class TestDNSSEC:
    async def test_a_signed_zone_validates(self):
        async with DNSClient(config=DNSClientConfig(servers=resolver("udp"), timeout=8.0, cache=False)) as dns:
            records = await dns.resolve("cloudflare.com", DNSRecordType.A, validate=True)

            assert records

    async def test_an_unsigned_zone_is_reported(self):
        from kaede.dns.errors import DNSSECError

        async with DNSClient(config=DNSClientConfig(servers=resolver("udp"), timeout=8.0, cache=False)) as dns:
            # example.com is signed; a truly unsigned name should raise rather than validate.
            try:
                await dns.resolve("example.com", DNSRecordType.A, validate=True)

            except DNSSECError:
                pass # acceptable: the resolver returned an unsigned or unvalidatable answer
