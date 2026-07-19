import asyncio

import pytest

from kaede.tcp import TCPPort, TCPClient, TCPServer, TCPServerConfig, TCPServerLimits, TCPHandler
from kaede.tcp.api.client import TCPClientConfig
from kaede.tcp.errors import TCPClosedError

LOCAL = "127.0.0.1"

class Running:
    """Starts a TCPServer on an ephemeral port for the duration of the block."""

    def __init__(self, on_connection, limits=None):
        config = TCPServerConfig()

        if limits is not None:
            config.limits = limits

        self.server = TCPServer(config)
        self.handler = TCPHandler(on_connection)

    async def __aenter__(self):
        await self.server.listen(self.handler, [(LOCAL, TCPPort(0))])
        return self.server

    async def __aexit__(self, *_):
        await self.server.close(timeout=2)

    @property
    def address(self):
        return self.server.ports[0]

async def upper(connection):
    data = await connection.receive_exactly(5)
    await connection.send(data.upper())

class TestServing:
    async def test_serves_a_client(self):
        async with Running(upper) as server:
            reader, writer = await asyncio.open_connection(LOCAL, int(server.ports[0][1]))
            writer.write(b"hello")
            await writer.drain()

            assert await reader.read(5) == b"HELLO"
            writer.close()

    async def test_serves_many_clients(self):
        async with Running(upper) as server:
            port = int(server.ports[0][1])

            async def once():
                reader, writer = await asyncio.open_connection(LOCAL, port)
                writer.write(b"hello")
                await writer.drain()
                data = await reader.read(5)
                writer.close()
                return data

            assert await asyncio.gather(*[once() for _ in range(25)]) == [b"HELLO"] * 25

    async def test_reports_the_bound_port(self):
        async with Running(upper) as server:
            host, port = server.ports[0]

            assert host == LOCAL
            assert isinstance(port, TCPPort)
            assert port != 0

    async def test_listens_on_several_ports(self):
        server = TCPServer()

        try:
            await server.listen(TCPHandler(upper), [(LOCAL, TCPPort(0)), (LOCAL, TCPPort(0))])
            assert len(server.ports) == 2
            assert server.ports[0][1] != server.ports[1][1]

        finally:
            await server.close(timeout=2)

    async def test_a_failed_bind_does_not_leave_earlier_listeners_open(self):
        # listen() opens one server per port in turn. If a later bind fails, the
        # listeners already opened for the earlier ports must be closed rather
        # than left serving, and must not linger in the server's list.
        import socket

        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            blocker.bind((LOCAL, 0))
            blocker.listen()
            taken = TCPPort(blocker.getsockname()[1])

            server = TCPServer()

            with pytest.raises(OSError):
                await server.listen(TCPHandler(upper), [(LOCAL, TCPPort(0)), (LOCAL, taken)])

            assert server.servers == []

        finally:
            blocker.close()

    async def test_a_synchronous_handler_is_supported(self):
        seen = []

        def note(connection):
            seen.append(connection.dst[0])

        async with Running(note) as server:
            reader, writer = await asyncio.open_connection(LOCAL, int(server.ports[0][1]))
            assert await reader.read() == b""  # the server closes once the handler returns
            writer.close()

        assert seen == [LOCAL]

    async def test_the_connection_is_closed_after_the_handler_returns(self):
        async def greet(connection):
            await connection.send(b"bye")

        async with Running(greet) as server:
            reader, writer = await asyncio.open_connection(LOCAL, int(server.ports[0][1]))

            assert await reader.read() == b"bye"  # read() returns only at EOF
            writer.close()

    async def test_a_failing_handler_does_not_stop_the_server(self):
        async def crash(connection):
            raise RuntimeError("handler failed")

        async with Running(crash) as server:
            port = int(server.ports[0][1])

            reader, writer = await asyncio.open_connection(LOCAL, port)
            await reader.read()
            writer.close()

            # The next client must still be served.
            reader, writer = await asyncio.open_connection(LOCAL, port)
            await reader.read()
            writer.close()

    async def test_a_handler_error_is_reported_through_the_loop(self):
        # It must not surface as "Task exception was never retrieved" on stderr.
        reported = []
        loop = asyncio.get_running_loop()
        previous = loop.get_exception_handler()
        loop.set_exception_handler(lambda _, context: reported.append(context))

        async def crash(connection):
            raise RuntimeError("handler failed")

        try:
            async with Running(crash) as server:
                reader, writer = await asyncio.open_connection(LOCAL, int(server.ports[0][1]))
                await reader.read()
                writer.close()
                await writer.wait_closed()

        finally:
            loop.set_exception_handler(previous)

        assert any(isinstance(context.get("exception"), RuntimeError) for context in reported)

    async def test_a_peer_reset_is_not_reported_as_a_handler_error(self):
        # A client vanishing mid-exchange is routine and must stay quiet.
        reported = []
        loop = asyncio.get_running_loop()
        previous = loop.get_exception_handler()
        loop.set_exception_handler(lambda _, context: reported.append(context))

        async def expect(connection):
            await connection.receive_exactly(1024)

        try:
            async with Running(expect) as server:
                reader, writer = await asyncio.open_connection(LOCAL, int(server.ports[0][1]))
                writer.write(b"partial")
                await writer.drain()

                # Abort rather than close, so the peer sees RST.
                writer.transport.abort()
                await asyncio.sleep(0.05)

        finally:
            loop.set_exception_handler(previous)

        assert reported == []

    async def test_serve_blocks_until_close(self):
        server = TCPServer()
        serving = asyncio.ensure_future(server.serve(TCPHandler(upper), [(LOCAL, TCPPort(0))]))

        while not server.servers:
            await asyncio.sleep(0)

        assert not serving.done()

        await server.close(timeout=2)
        await asyncio.wait_for(serving, 2)

class TestLimits:
    async def test_refuses_connections_beyond_the_count_limit(self):
        limits = TCPServerLimits()
        limits.max_connection_nums = 2
        limits.max_connection_rate = []

        held = asyncio.Event()

        async def hold(connection):
            await held.wait()

        async with Running(hold, limits) as server:
            port = int(server.ports[0][1])

            kept = [await asyncio.open_connection(LOCAL, port) for _ in range(2)]

            # The third is admitted by the kernel but aborted by the gate.
            reader, writer = await asyncio.open_connection(LOCAL, port)
            assert await reader.read() == b""

            writer.close()
            held.set()

            for _, other in kept:
                other.close()

    async def test_refuses_connections_beyond_the_rate_limit(self):
        limits = TCPServerLimits()
        limits.max_connection_rate = [(60, 3)]

        async def bye(connection):
            await connection.send(b"ok")

        async with Running(bye, limits) as server:
            port = int(server.ports[0][1])
            served = 0

            for _ in range(6):
                reader, writer = await asyncio.open_connection(LOCAL, port)

                if await reader.read() == b"ok":
                    served += 1

                writer.close()

            assert served == 3

    async def test_a_closed_connection_frees_its_slot(self):
        limits = TCPServerLimits()
        limits.max_connection_nums = 1
        limits.max_connection_rate = []

        async def bye(connection):
            await connection.send(b"ok")

        async with Running(bye, limits) as server:
            port = int(server.ports[0][1])

            for _ in range(5):
                reader, writer = await asyncio.open_connection(LOCAL, port)
                assert await reader.read() == b"ok"

                writer.close()
                await writer.wait_closed()

class TestClient:
    async def test_opens_a_connection(self):
        async with Running(upper) as server:
            client = TCPClient(server.ports[0])
            connection = await client.open()

            await connection.send(b"hello")
            assert await connection.receive_exactly(5) == b"HELLO"

            await client.close()

    async def test_works_as_a_context_manager(self):
        async with Running(upper) as server:
            async with TCPClient(server.ports[0]) as connection:
                await connection.send(b"hello")
                assert await connection.receive_exactly(5) == b"HELLO"

    async def test_closing_the_client_closes_its_connections(self):
        async with Running(upper) as server:
            client = TCPClient(server.ports[0])

            first = await client.open()
            second = await client.open()

            await client.close()

            for connection in (first, second):
                with pytest.raises(TCPClosedError):
                    await connection.send(b"late")

    async def test_binds_the_requested_source_port(self):
        async with Running(upper) as server:
            client = TCPClient(server.ports[0], TCPPort(0))
            connection = await client.open()

            assert connection.src[1] != 0  # the OS assigned one

            await client.close()

    async def test_rejects_an_invalid_port(self):
        with pytest.raises(ValueError):
            TCPClient((LOCAL, TCPPort(70000)))

    async def test_the_connect_timeout_is_configurable(self):
        config = TCPClientConfig(connect_timeout=0.05)
        client = TCPClient(("203.0.113.1", TCPPort(80)), config=config)  # TEST-NET-3, unroutable

        with pytest.raises(Exception):
            await client.open()

class TestIdle:
    # A client may finish the handshake and then fall silent, holding a
    # connection slot forever. With an idle_timeout the server reaps such a
    # connection and unblocks the handler waiting on it.

    async def test_an_idle_connection_is_reaped(self):
        woken = asyncio.Event()

        async def stall(connection):
            await connection.receive(1)  # blocks until the reaper drops the connection
            woken.set()

        server = TCPServer(TCPServerConfig(idle_timeout=0.05))
        await server.listen(TCPHandler(stall), [(LOCAL, TCPPort(0))])

        try:
            async with TCPClient(server.ports[0]):
                await asyncio.sleep(0.15)  # go idle past idle_timeout
                server.expire()            # force the sweep deterministically

                await asyncio.wait_for(woken.wait(), 2)

        finally:
            await server.close(timeout=2)

    async def test_a_fresh_connection_is_kept(self):
        async def hold(connection):
            await connection.receive(1)

        server = TCPServer(TCPServerConfig(idle_timeout=100.0))
        await server.listen(TCPHandler(hold), [(LOCAL, TCPPort(0))])

        try:
            async with TCPClient(server.ports[0]):
                await asyncio.sleep(0.1)
                server.expire()  # idle_timeout is far away, so the connection survives

                assert len(server.connections) == 1

        finally:
            await server.close(timeout=2)

    async def test_reaping_is_off_without_an_idle_timeout(self):
        async def hold(connection):
            await connection.receive(1)

        server = TCPServer(TCPServerConfig())  # idle_timeout defaults to None
        await server.listen(TCPHandler(hold), [(LOCAL, TCPPort(0))])

        try:
            async with TCPClient(server.ports[0]):
                await asyncio.sleep(0.1)
                server.expire()

                assert len(server.connections) == 1

        finally:
            await server.close(timeout=2)
