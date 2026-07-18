import ipaddress
from ssl import CERT_NONE

import pytest

from kaede.tls import TLSConfig
from kaede.tcp import TCPPort
from kaede.udp import UDPPort
from kaede.quic.tls import QTLS
from kaede.dns import (
    DNSPort, DNSRecordType, DNSRecords, DNSClient, DNSClientConfig,
    DNSServer, DNSServerConfig, DNSHandler
)
from kaede.dns.errors import DNSError, DNSConnectionError, DNSFormatError

LOCAL = "127.0.0.1"

ZONE = DNSRecords("example.test 300 IN A 192.0.2.1\n")

async def resolver(connection):
    while True:
        query = await connection.receive(timeout=2)
        answer = query.reply()

        for question in query.questions:
            for record in ZONE.find(question.type, question.name):
                answer.answers.append(record)

        await connection.send(answer)

class Running:
    def __init__(self, certificate, *, kind="tcp", on_connection=resolver):
        certfile, keyfile = certificate

        config = DNSServerConfig(idle_timeout=10)
        config.tls = TLSConfig(certfile=certfile, keyfile=keyfile, verify_mode=CERT_NONE)
        config.handshake_timeout = 10

        self.kind = kind
        self.server = DNSServer(config=config)
        self.handler = DNSHandler(on_connection)

    async def __aenter__(self):
        port = DNSPort("tcp", TCPPort(0), True) if self.kind == "tcp" else DNSPort("quic", UDPPort(0), True)

        await self.server.listen(self.handler, [(LOCAL, port)])
        return self.server

    async def __aexit__(self, *_):
        await self.server.close(timeout=0.5)

def client(server, authority, *, hostname="localhost") -> DNSClient:
    return DNSClient(config=DNSClientConfig(
        servers=list(server.ports), timeout=5.0, retries=0, cache=False,
        tls=TLSConfig(cafile=authority.ca), hostname=hostname
    ))

class TestDoT:
    async def test_a_query_over_tls(self, server_certificate, authority):
        async with Running(server_certificate) as server:
            async with client(server, authority) as stub:
                records = await stub.resolve("example.test", DNSRecordType.A)

                assert [record.data.address for record in records] == [ipaddress.IPv4Address("192.0.2.1")]

    async def test_the_transport_is_kept_between_queries(self, server_certificate, authority):
        async with Running(server_certificate) as server:
            async with client(server, authority) as stub:
                await stub.query("example.test", DNSRecordType.A)
                await stub.query("example.test", DNSRecordType.A)

                assert len(stub.transports) == 1

    async def test_an_untrusted_certificate_is_rejected(self, server_certificate):
        async with Running(server_certificate) as server:
            stub = DNSClient(config=DNSClientConfig(
                servers=list(server.ports), timeout=5.0, retries=0, cache=False,
                tls=TLSConfig(), hostname="localhost" # the system trust store lacks the test CA
            ))

            with pytest.raises(DNSConnectionError):
                await stub.query("example.test", DNSRecordType.A)

    async def test_a_wrong_hostname_is_rejected(self, other_certificate, authority):
        async with Running(other_certificate) as server:
            with pytest.raises(DNSConnectionError):
                await client(server, authority).query("example.test", DNSRecordType.A)

@pytest.fixture(scope="module")
def servable():
    if not QTLS().servable:
        pytest.skip("a QUIC server needs OpenSSL 4.0 or newer")

class TestDoQ:
    async def test_a_query_over_quic(self, servable, server_certificate, authority):
        async with Running(server_certificate, kind="quic") as server:
            async with client(server, authority) as stub:
                records = await stub.resolve("example.test", DNSRecordType.A)

                assert [record.data.address for record in records] == [ipaddress.IPv4Address("192.0.2.1")]

    async def test_queries_share_one_connection(self, servable, server_certificate, authority):
        async with Running(server_certificate, kind="quic") as server:
            async with client(server, authority) as stub:
                await stub.query("example.test", DNSRecordType.A)
                await stub.query("example.test", DNSRecordType.A)

                assert len(stub.transports) == 1

    async def test_the_message_id_travels_as_zero(self, servable, server_certificate, authority):
        # RFC 9250 section 4.2.1.
        seen = []

        async def observing(connection):
            query = await connection.receive(timeout=2)
            seen.append(query.id)
            await connection.send(query.reply())

        async with Running(server_certificate, kind="quic", on_connection=observing) as server:
            async with client(server, authority) as stub:
                response = await stub.query("example.test", DNSRecordType.A)

                assert response.id == 0
                assert seen == [0]

    async def test_a_nonzero_response_id_is_rejected(self, servable, server_certificate, authority):
        async def defiant(connection):
            query = await connection.receive(timeout=2)
            answer = query.reply()
            answer.id = 1
            await connection.send(answer)

        async with Running(server_certificate, kind="quic", on_connection=defiant) as server:
            async with client(server, authority) as stub:
                with pytest.raises(DNSFormatError):
                    await stub.query("example.test", DNSRecordType.A)
