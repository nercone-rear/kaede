import ipaddress
from ssl import CERT_NONE

import pytest

from kaede.tls import TLSConfig
from kaede.tcp import TCPPort
from kaede.udp import UDPPort
from kaede.http.models import HTTPPort
from kaede.http.api.server import HTTPServer, HTTPServerConfig
from kaede.dns import DNSPort, DNSRecordType, DNSRecords, DNSMessage, DNSClient, DNSClientConfig
from kaede.dns.protocol.https import DNSHTTPSHandler, DNSHTTPSTransport
from kaede.dns.errors import DNSFormatError

LOCAL = "127.0.0.1"

ZONE = DNSRecords("example.test 300 IN A 192.0.2.1\n")

def resolve(query: DNSMessage) -> DNSMessage:
    answer = query.reply()

    for question in query.questions:
        for record in ZONE.find(question.type, question.name):
            answer.answers.append(record)

    return answer

class Running:
    def __init__(self, certificate, *, versions=("HTTP/1.1", "HTTP/2.0")):
        certfile, keyfile = certificate

        config = HTTPServerConfig(versions=list(versions))
        config.tls = TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE)

        self.server = HTTPServer(config=config)
        self.handler = DNSHTTPSHandler(resolve)

    async def __aenter__(self):
        await self.server.listen(self.handler, [(LOCAL, HTTPPort("tcp", TCPPort(0), True))])
        return self.server

    async def __aexit__(self, *_):
        await self.server.close(timeout=2)

def transport(server, authority) -> DNSHTTPSTransport:
    host, port = server.ports[0]

    return DNSHTTPSTransport((LOCAL, int(port.value)), tls=TLSConfig(cafile=authority.ca), hostname="localhost", connect_timeout=5)

class TestDoH:
    async def test_a_query_over_doh(self, server_certificate, authority):
        async with Running(server_certificate) as server:
            doh = transport(server, authority)

            try:
                from kaede.dns import DNSQuestion

                query = DNSMessage(questions=[DNSQuestion("example.test", DNSRecordType.A)])
                response = await doh.query(query, timeout=5)

                assert response.id == 0
                assert response.answers.first(DNSRecordType.A).data.address == ipaddress.IPv4Address("192.0.2.1")

            finally:
                await doh.close()

    async def test_doh_over_h2(self, server_certificate, authority):
        async with Running(server_certificate, versions=["HTTP/2.0", "HTTP/1.1"]) as server:
            doh = transport(server, authority)

            try:
                from kaede.dns import DNSQuestion

                response = await doh.query(DNSMessage(questions=[DNSQuestion("example.test", DNSRecordType.A)]), timeout=5)

                assert response.answers.first(DNSRecordType.A).data.address == ipaddress.IPv4Address("192.0.2.1")

            finally:
                await doh.close()

    async def test_the_client_resolves_through_doh(self, server_certificate, authority):
        async with Running(server_certificate) as server:
            host, port = server.ports[0]

            config = DNSClientConfig(
                servers=[(LOCAL, DNSPort("https", int(port.value), True))],
                timeout=5.0, retries=0, cache=False,
                tls=TLSConfig(cafile=authority.ca), hostname="localhost"
            )

            async with DNSClient(config=config) as client:
                records = await client.resolve("example.test", DNSRecordType.A)

                assert [record.data.address for record in records] == [ipaddress.IPv4Address("192.0.2.1")]

    async def test_a_wrong_media_type_is_refused(self, server_certificate, authority):
        from kaede.http.api.client import HTTPClient, HTTPClientConfig

        async with Running(server_certificate) as server:
            host, port = server.ports[0]

            config = HTTPClientConfig(versions=["HTTP/1.1"])
            config.tls = TLSConfig(cafile=authority.ca)

            async with HTTPClient(config=config) as http:
                connection = await http.post(f"https://localhost:{int(port.value)}/dns-query", headers={"content-type": "text/plain"}, body=b"not a dns message")
                response = await connection.receive()

                assert response.status_code == 415
