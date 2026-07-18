import asyncio

import pytest

from kaede.udp import UDPPort, UDPClient, UDPServer, UDPServerConfig, UDPServerLimits, UDPHandler
from kaede.udp.api.client import UDPClientConfig
from kaede.udp.errors import UDPClosedError, UDPTimeoutError

LOCAL = "127.0.0.1"

class Running:
    """Starts a UDPServer on an ephemeral port for the duration of the block."""

    def __init__(self, on_connection, limits=None, idle_timeout=None):
        config = UDPServerConfig()

        if limits is not None:
            config.limits = limits

        if idle_timeout is not None:
            config.idle_timeout = idle_timeout

        self.server = UDPServer(config)
        self.handler = UDPHandler(on_connection)

    async def __aenter__(self):
        await self.server.listen(self.handler, [(LOCAL, UDPPort(0))])
        return self.server

    async def __aexit__(self, *_):
        await self.server.close(timeout=2)

async def upper(connection):
    """Answer every datagram with its uppercase form until the peer goes away."""

    while True:
        await connection.send((await connection.receive()).upper())

async def once(connection):
    await connection.send((await connection.receive()).upper())

class Talker(asyncio.DatagramProtocol):
    """A standard library datagram client, so the server is checked against
    something other than Kaede's own client."""

    def __init__(self):
        self.received = asyncio.Queue()
        self.transport = None

    async def __aenter__(self):
        loop = asyncio.get_running_loop()
        self.transport, _ = await loop.create_datagram_endpoint(lambda: self, local_addr=(LOCAL, 0))

        return self

    async def __aexit__(self, *_):
        self.transport.close()
        await asyncio.sleep(0)  # let the transport hand its socket back

    def datagram_received(self, data, addr):
        self.received.put_nowait(data)

    def connection_made(self, transport):
        self.transport = transport

    async def ask(self, data, address, timeout=2):
        self.transport.sendto(data, (address[0], int(address[1])))

        return await asyncio.wait_for(self.received.get(), timeout)

class TestServing:
    async def test_serves_a_client(self):
        async with Running(upper) as server:
            async with Talker() as talker:
                assert await talker.ask(b"hello", server.ports[0]) == b"HELLO"

    async def test_serves_many_clients(self):
        async with Running(upper) as server:
            address = server.ports[0]

            async def exchange():
                async with Talker() as talker:
                    return await talker.ask(b"hello", address)

            assert await asyncio.gather(*[exchange() for _ in range(20)]) == [b"HELLO"] * 20

    async def test_reports_the_bound_port(self):
        async with Running(upper) as server:
            host, port = server.ports[0]

            assert host == LOCAL
            assert isinstance(port, UDPPort)
            assert port != 0

    async def test_listens_on_several_ports(self):
        server = UDPServer()

        try:
            await server.listen(UDPHandler(upper), [(LOCAL, UDPPort(0)), (LOCAL, UDPPort(0))])

            assert len(server.ports) == 2
            assert server.ports[0][1] != server.ports[1][1]

        finally:
            await server.close(timeout=2)

    async def test_a_synchronous_handler_is_supported(self):
        seen = []

        def note(connection):
            seen.append(connection.dst[0])

        async with Running(note) as server:
            async with Talker() as talker:
                talker.transport.sendto(b"hello", (server.ports[0][0], int(server.ports[0][1])))
                await asyncio.sleep(0.1)

        assert seen == [LOCAL]

    async def test_message_boundaries_survive_the_server(self):
        async with Running(upper) as server:
            async with Talker() as talker:
                address = server.ports[0]

                assert await talker.ask(b"one", address) == b"ONE"
                assert await talker.ask(b"two", address) == b"TWO"
                assert await talker.ask(b"three", address) == b"THREE"

    async def test_serve_blocks_until_close(self):
        server = UDPServer()
        serving = asyncio.ensure_future(server.serve(UDPHandler(upper), [(LOCAL, UDPPort(0))]))

        while not server.sockets:
            await asyncio.sleep(0)

        assert not serving.done()

        await server.close(timeout=2)
        await asyncio.wait_for(serving, 2)

class TestPeers:
    async def test_each_peer_gets_its_own_connection(self):
        seen = []

        async def note(connection):
            seen.append(connection.dst)
            await connection.send(b"ok")

        async with Running(note) as server:
            async with Talker() as first, Talker() as second:
                await first.ask(b"hello", server.ports[0])
                await second.ask(b"hello", server.ports[0])

        assert len(seen) == 2
        assert seen[0] != seen[1]

    async def test_datagrams_from_one_peer_share_a_connection(self):
        # The handler is entered once per peer, not once per datagram, so a
        # single run of it must see everything that peer sends.
        collected = []

        async def collect(connection):
            while True:
                collected.append(await connection.receive())
                await connection.send(b"ok")

        async with Running(collect) as server:
            async with Talker() as talker:
                address = server.ports[0]

                await talker.ask(b"first", address)
                await talker.ask(b"second", address)
                await talker.ask(b"third", address)

        assert collected == [b"first", b"second", b"third"]

    async def test_the_handler_sees_the_peer_address(self):
        seen = []

        async def note(connection):
            seen.append(connection.dst)
            await connection.send(b"ok")

        async with Running(note) as server:
            async with Talker() as talker:
                await talker.ask(b"hello", server.ports[0])

                host, port = talker.transport.get_extra_info("sockname")[:2]

        assert seen == [(host, UDPPort(port))]

class TestIdleExpiry:
    async def test_an_idle_peer_is_expired(self):
        # Nothing in UDP says a peer has finished, so the table must be pruned
        # or it grows for the lifetime of the process. The handler here never
        # returns on its own, so expiry is the only thing that can end it.
        async with Running(upper, idle_timeout=0.05) as server:
            async with Talker() as talker:
                await talker.ask(b"hello", server.ports[0])

                assert len(server.connections) == 1

                await asyncio.sleep(0.1)
                server.expire()
                await asyncio.sleep(0.01)  # let the woken handler finish

                assert server.connections == set()

    async def test_a_busy_peer_is_kept(self):
        async with Running(upper, idle_timeout=30) as server:
            async with Talker() as talker:
                await talker.ask(b"hello", server.ports[0])

                server.expire()
                assert len(server.connections) == 1

    async def test_expiry_releases_the_slot(self):
        limits = UDPServerLimits()
        limits.max_connection_nums = 1
        limits.max_connection_rate = []

        async with Running(upper, limits=limits, idle_timeout=0.05) as server:
            async with Talker() as talker:
                await talker.ask(b"hello", server.ports[0])
                assert server.gate.connections == 1

            await asyncio.sleep(0.1)
            server.expire()
            await asyncio.sleep(0.01)

            assert server.gate.connections == 0

    async def test_a_peer_heard_from_again_is_served_again(self):
        # Expiry must not blacklist a peer: the same address coming back simply
        # starts a new connection.
        async with Running(upper, idle_timeout=0.05) as server:
            async with Talker() as talker:
                address = server.ports[0]

                assert await talker.ask(b"hello", address) == b"HELLO"

                await asyncio.sleep(0.1)
                server.expire()
                await asyncio.sleep(0.01)

                assert server.connections == set()
                assert await talker.ask(b"again", address) == b"AGAIN"

    async def test_the_sweep_interval_follows_the_idle_timeout(self):
        server = UDPServer(UDPServerConfig(idle_timeout=40))
        assert server.interval == 10

        # It must never spin, however short the timeout is set.
        assert UDPServer(UDPServerConfig(idle_timeout=0.1)).interval == 1.0

class TestLimits:
    async def test_refuses_peers_beyond_the_count_limit(self):
        limits = UDPServerLimits()
        limits.max_connection_nums = 2
        limits.max_connection_rate = []

        async with Running(upper, limits=limits) as server:
            address = server.ports[0]

            async with Talker() as first, Talker() as second, Talker() as third:
                assert await first.ask(b"hello", address) == b"HELLO"
                assert await second.ask(b"hello", address) == b"HELLO"

                # The third peer is over the limit, so its datagrams are dropped.
                with pytest.raises(asyncio.TimeoutError):
                    await third.ask(b"hello", address, timeout=0.2)

    async def test_refuses_peers_beyond_the_rate_limit(self):
        limits = UDPServerLimits()
        limits.max_connection_rate = [(60, 2)]

        async with Running(once, limits=limits) as server:
            address = server.ports[0]
            served = 0

            for _ in range(5):
                async with Talker() as talker:
                    try:
                        if await talker.ask(b"hello", address, timeout=0.2) == b"HELLO":
                            served += 1
                    except asyncio.TimeoutError:
                        pass

            assert served == 2

class TestFailures:
    async def test_a_failing_handler_does_not_stop_the_server(self):
        async def crash(connection):
            raise RuntimeError("handler failed")

        async with Running(crash) as server:
            address = server.ports[0]

            async with Talker() as talker:
                talker.transport.sendto(b"hello", (address[0], int(address[1])))
                await asyncio.sleep(0.05)

            # A later peer must still be served, so the server has to be alive.
            assert server.endpoints

    async def test_a_handler_error_is_reported_through_the_loop(self):
        reported = []
        loop = asyncio.get_running_loop()
        previous = loop.get_exception_handler()
        loop.set_exception_handler(lambda _, context: reported.append(context))

        async def crash(connection):
            raise RuntimeError("handler failed")

        try:
            async with Running(crash) as server:
                async with Talker() as talker:
                    talker.transport.sendto(b"hello", (server.ports[0][0], int(server.ports[0][1])))
                    await asyncio.sleep(0.05)

        finally:
            loop.set_exception_handler(previous)

        assert any(isinstance(context.get("exception"), RuntimeError) for context in reported)

    async def test_closing_the_server_ends_the_handlers(self):
        # A UDP handler waits on a receive that no peer will ever satisfy, so
        # closing has to wake it rather than wait for an end of stream.
        entered = asyncio.Event()

        async def wait(connection):
            entered.set()
            await connection.receive()

        server = UDPServer()

        await server.listen(UDPHandler(wait), [(LOCAL, UDPPort(0))])

        async with Talker() as talker:
            talker.transport.sendto(b"hello", (server.ports[0][0], int(server.ports[0][1])))
            await asyncio.wait_for(entered.wait(), 2)

        await asyncio.wait_for(server.close(timeout=2), 3)

        assert server.tasks == set()

class TestClient:
    async def test_exchanges_datagrams(self):
        async with Running(upper) as server:
            async with UDPClient(server.ports[0]) as connection:
                await connection.send(b"hello")
                assert await connection.receive(timeout=2) == b"HELLO"

    async def test_works_without_the_context_manager(self):
        async with Running(upper) as server:
            client = UDPClient(server.ports[0])
            connection = await client.open()

            await connection.send(b"hello")
            assert await connection.receive(timeout=2) == b"HELLO"

            await client.close()

    async def test_closing_the_client_closes_its_connections(self):
        async with Running(upper) as server:
            client = UDPClient(server.ports[0])

            first = await client.open()
            second = await client.open()

            await client.close()

            for connection in (first, second):
                with pytest.raises(UDPClosedError):
                    await connection.send(b"late")

    async def test_boundaries_survive_a_round_trip(self):
        async with Running(upper) as server:
            async with UDPClient(server.ports[0]) as connection:
                for payload in (b"one", b"two", b"three"):
                    await connection.send(payload)

                assert await connection.receive(timeout=2) == b"ONE"
                assert await connection.receive(timeout=2) == b"TWO"
                assert await connection.receive(timeout=2) == b"THREE"

    async def test_binds_an_ephemeral_source_port(self):
        async with Running(upper) as server:
            async with UDPClient(server.ports[0]) as connection:
                assert connection.src[1] != 0

    async def test_rejects_an_invalid_port(self):
        with pytest.raises(ValueError):
            UDPClient((LOCAL, UDPPort(70000)))

    async def test_a_receive_can_time_out(self):
        # Nothing is listening, so this only returns because of the timeout.
        async with UDPClient((LOCAL, UDPPort(9))) as connection:
            with pytest.raises(UDPTimeoutError):
                await connection.receive(timeout=0.05)
