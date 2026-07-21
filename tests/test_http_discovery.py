import socket

import pytest

from kaede.tcp import TCPPort
from kaede.udp import UDPPort
from kaede.dns import DNSPort, DNSRecordType, DNSRecord, DNSRecords, DNSClient, DNSClientConfig, DNSClientLimits, DNSServer, DNSServerConfig, DNSHandler
from kaede.dns.records import SVCBRecordData, HTTPSRecordData
from kaede.http.helpers.dns import HTTPSRecordProbe

LOCAL = "127.0.0.1"

# An HTTPS record advertising h3 for the origin.
RECORD = DNSRecord("origin.test", DNSRecordType.HTTPS, HTTPSRecordData(1, "", params=(
    (SVCBRecordData.ALPN, b"\x02h3\x02h2"),
    (SVCBRecordData.IPV4HINT, b"\xc0\x00\x02\x01"),
)), ttl=300)

async def resolver(connection):
    while True:
        query = await connection.receive(timeout=2)
        answer = query.reply()

        for question in query.questions:
            if question.type == DNSRecordType.HTTPS and question.name.lower() == "origin.test":
                answer.answers.append(RECORD)

        await connection.send(answer)

class Running:
    def __init__(self):
        self.server = DNSServer(config=DNSServerConfig())
        self.handler = DNSHandler(resolver)

    async def __aenter__(self):
        await self.server.listen(self.handler, [(LOCAL, DNSPort("udp", UDPPort(0)))])
        return self.server

    async def __aexit__(self, *_):
        await self.server.close(timeout=0.2)

def client(server) -> DNSClient:
    return DNSClient(config=DNSClientConfig(servers=list(server.ports), limits=DNSClientLimits(timeout_query=2.0, max_retries=0), cache=False))

class TestDiscovery:
    async def test_the_probe_finds_the_https_record(self):
        async with Running() as server:
            async with client(server) as dns:
                record = await HTTPSRecordProbe.discover(dns, "origin.test")

                assert record is not None
                assert record.alpn == ["h3", "h2"]

    async def test_h3_support_is_reported(self):
        async with Running() as server:
            async with client(server) as dns:
                assert await HTTPSRecordProbe.supports_h3(dns, "origin.test")

    async def test_an_origin_without_a_record_reports_nothing(self):
        async with Running() as server:
            async with client(server) as dns:
                assert await HTTPSRecordProbe.discover(dns, "plain.test") is None
                assert not await HTTPSRecordProbe.supports_h3(dns, "plain.test")
