import socket
import ipaddress

import pytest

from kaede.tcp import TCPPort
from kaede.udp import UDPPort, UDPConnection
from kaede.dns import (
    DNSPort, DNSRecordType, DNSResponseCode, DNSRecordName, DNSRecord, DNSRecords,
    DNSMessage, DNSCache, DNSClient, DNSClientConfig, DNSClientLimits, DNSServer, DNSServerConfig, DNSHandler
)
from kaede.dns.errors import DNSError, DNSServerError, DNSTimeoutError
from kaede.dns.records import SOARecordData, TXTRecordData

LOCAL = "127.0.0.1"

ZONE = DNSRecords(
    "example.test 300 IN A 192.0.2.1\n"
    "example.test 300 IN AAAA 2001:db8::1\n"
    "example.test 300 IN MX 10 mail.example.test\n"
    "www.example.test 300 IN CNAME example.test\n"
)

ZONE.append(DNSRecord("big.example.test", DNSRecordType.TXT, TXTRecordData(tuple(bytes([65 + at % 26]) * 200 for at in range(12))), ttl=300))

START = DNSRecord("example.test", DNSRecordType.SOA, SOARecordData("ns.example.test", "hostmaster.example.test", 1, 7200, 3600, 1209600, 60), ttl=60)

async def resolver(connection):
    """A tiny authoritative server over the ZONE records."""

    while True:
        query = await connection.receive(timeout=2)
        answer = query.reply()
        answer.authoritative = True

        for question in query.questions:
            name = question.name
            visited = set()

            while True: # follow CNAMEs the way a real server includes the chain
                found = ZONE.find(None, name)

                for record in found:
                    if record.type in (question.type, DNSRecordType.CNAME):
                        answer.answers.append(record)

                alias = found.first(DNSRecordType.CNAME)

                if alias is None or question.type == DNSRecordType.CNAME or DNSRecordName.key(name) in visited:
                    if not found and DNSRecordName.key(name) not in {DNSRecordName.key(record.name) for record in ZONE}:
                        answer.rcode = DNSResponseCode.NXDOMAIN
                        answer.authorities.append(START)

                    elif not answer.answers:
                        answer.authorities.append(START) # NODATA

                    break

                visited.add(DNSRecordName.key(name))
                name = alias.data.target

        await connection.send(answer)

def port_pair() -> int:
    """A port number currently free for both UDP and TCP on the loopback."""

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind((LOCAL, 0))
        return probe.getsockname()[1]

class Running:
    def __init__(self, on_connection=resolver, *, both: bool = False):
        self.server = DNSServer(config=DNSServerConfig())
        self.handler = DNSHandler(on_connection)
        self.both = both

    async def __aenter__(self):
        if self.both: # the same port number over UDP and TCP, as real resolvers expose it
            for _ in range(5):
                number = port_pair()

                try:
                    await self.server.listen(self.handler, [(LOCAL, DNSPort("udp", UDPPort(number))), (LOCAL, DNSPort("tcp", TCPPort(number)))])
                    return self.server

                except OSError:
                    continue

            raise OSError("Could not find a port number free for both UDP and TCP.")

        await self.server.listen(self.handler, [(LOCAL, DNSPort("udp", UDPPort(0))), (LOCAL, DNSPort("tcp", TCPPort(0)))])
        return self.server

    async def __aexit__(self, *_):
        await self.server.close(timeout=0.2)

def client(server, *, kinds=("udp",), cache=False) -> DNSClient:
    servers = [(host, port) for host, port in server.ports if port.type in kinds]

    return DNSClient(config=DNSClientConfig(servers=servers, limits=DNSClientLimits(timeout_query=2.0, max_retries=0), cache=cache))

class TestQueries:
    async def test_a_query_over_udp(self):
        async with Running() as server:
            async with client(server, kinds=("udp",)) as resolver_client:
                response = await resolver_client.query("example.test", DNSRecordType.A)

                assert response.response
                assert response.answers.first(DNSRecordType.A).data.address == ipaddress.IPv4Address("192.0.2.1")

    async def test_a_query_over_tcp(self):
        async with Running() as server:
            async with client(server, kinds=("tcp",)) as resolver_client:
                response = await resolver_client.query("example.test", DNSRecordType.AAAA)

                assert response.answers.first(DNSRecordType.AAAA).data.address == ipaddress.IPv6Address("2001:db8::1")

    async def test_a_tcp_transport_is_reused(self):
        async with Running() as server:
            async with client(server, kinds=("tcp",)) as resolver_client:
                await resolver_client.query("example.test", DNSRecordType.A)
                await resolver_client.query("example.test", DNSRecordType.MX)

                assert len(resolver_client.transports) == 1

    async def test_resolve_follows_a_cname_chain(self):
        async with Running() as server:
            async with client(server) as resolver_client:
                records = await resolver_client.resolve("www.example.test", DNSRecordType.A)

                assert [record.data.address for record in records] == [ipaddress.IPv4Address("192.0.2.1")]

    async def test_nxdomain_raises(self):
        async with Running() as server:
            async with client(server) as resolver_client:
                with pytest.raises(DNSServerError) as caught:
                    await resolver_client.resolve("missing.test", DNSRecordType.A)

                assert caught.value.rcode == DNSResponseCode.NXDOMAIN

    async def test_addresses_merges_both_families(self):
        async with Running() as server:
            async with client(server) as resolver_client:
                found = await resolver_client.addresses("example.test")

                assert ipaddress.IPv4Address("192.0.2.1") in found
                assert ipaddress.IPv6Address("2001:db8::1") in found

class TestTruncation:
    async def test_an_oversized_answer_falls_back_to_tcp(self):
        # RFC 1035 section 4.2.1: TC=1 over UDP means retry over a stream.
        async with Running(both=True) as server:
            async with client(server, kinds=("udp",)) as resolver_client:
                records = await resolver_client.resolve("big.example.test", DNSRecordType.TXT)

                assert len(records) == 1
                assert len(records[0].data.strings) == 12

    async def test_the_udp_answer_alone_is_truncated(self):
        async with Running() as server:
            async with client(server, kinds=("udp",)) as resolver_client:
                # Reach the transport directly so the TC fallback does not kick in.
                from kaede.dns.protocol.udp import DNSUDPProtocol
                from kaede.dns import DNSQuestion, DNSExtension

                host, port = [entry for entry in server.ports if entry[1].type == "udp"][0]
                query = DNSMessage(questions=[DNSQuestion("big.example.test", DNSRecordType.TXT)], edns=DNSExtension(payload_size=1232))

                response = await DNSUDPProtocol((host, int(port.value)), limits=DNSClientLimits(max_retries=0)).query(query, timeout=2.0)

                assert response.truncated
                assert len(response.answers) == 0

class TestRobustness:
    async def test_a_mismatched_id_is_ignored(self):
        # RFC 5452: a response that does not match the query must not be accepted.
        async def confusing(connection):
            query = await connection.receive(timeout=2)

            wrong = query.reply()
            wrong.answers = DNSRecords("example.test 300 IN A 198.51.100.66")
            wrong.id = query.id ^ 1
            await connection.send(wrong)

            right = query.reply()
            right.answers = DNSRecords("example.test 300 IN A 192.0.2.1")
            await connection.send(right)

        async with Running(confusing) as server:
            async with client(server) as resolver_client:
                response = await resolver_client.query("example.test", DNSRecordType.A)

                assert response.answers.first(DNSRecordType.A).data.address == ipaddress.IPv4Address("192.0.2.1")

    async def test_garbage_receives_formerr_and_the_server_survives(self):
        async with Running() as server:
            host, port = [entry for entry in server.ports if entry[1].type == "udp"][0]

            probe = UDPConnection(("", UDPPort(0)), (host, UDPPort(int(port.value))))
            await probe.connect(2)

            try:
                await probe.send((0xABCD).to_bytes(2, "big") + bytes(10) + b"!")
                answer = DNSMessage.unpack(await probe.receive(timeout=2))

                assert answer.id == 0xABCD
                assert answer.response
                assert answer.rcode == DNSResponseCode.FORMERR

            finally:
                await probe.close()

            # A real query afterwards still works.
            async with client(server) as resolver_client:
                assert await resolver_client.resolve("example.test", DNSRecordType.A)

    async def test_a_silent_server_times_out(self):
        async def silent(connection):
            await connection.receive(timeout=2)

        async with Running(silent) as server:
            resolver_client = DNSClient(config=DNSClientConfig(
                servers=[entry for entry in server.ports if entry[1].type == "udp"],
                limits=DNSClientLimits(timeout_query=0.3, max_retries=1), cache=False
            ))

            with pytest.raises(DNSTimeoutError):
                await resolver_client.query("example.test", DNSRecordType.A)

    async def test_the_default_handler_refuses(self):
        async with Running(None) as server:
            async with client(server) as resolver_client:
                response = await resolver_client.query("example.test", DNSRecordType.A)

                assert response.rcode == DNSResponseCode.REFUSED

class TestCaching:
    async def test_a_second_resolve_is_served_from_the_cache(self):
        seen = []

        async def counting(connection):
            while True:
                query = await connection.receive(timeout=2)
                seen.append(query.questions[0].name)

                answer = query.reply()
                answer.answers = DNSRecords("example.test 300 IN A 192.0.2.1")
                await connection.send(answer)

        async with Running(counting) as server:
            async with client(server, cache=True) as resolver_client:
                first = await resolver_client.resolve("example.test", DNSRecordType.A)
                second = await resolver_client.resolve("example.test", DNSRecordType.A)

                assert first == second
                assert len(seen) == 1

    def test_entries_expire_by_ttl(self):
        cache = DNSCache()
        records = DNSRecords("example.test 300 IN A 192.0.2.1")

        cache.put(("example.test", 1, 1), 0, records, ttl=300, now=1000.0)

        assert cache.get(("example.test", 1, 1), now=1200.0) == (0, records)
        assert cache.get(("example.test", 1, 1), now=1301.0) is None

    def test_the_cache_is_bounded(self):
        cache = DNSCache(DNSClientLimits(max_cache_entries=4))

        for index in range(10):
            cache.put((f"name{index}.test", 1, 1), 0, DNSRecords(), ttl=300, now=1000.0 + index)

        assert len(cache.entries) <= 4

    def test_a_zero_ttl_is_not_cached(self):
        cache = DNSCache()
        cache.put(("example.test", 1, 1), 0, DNSRecords(), ttl=0, now=1000.0)

        assert cache.get(("example.test", 1, 1), now=1000.0) is None
