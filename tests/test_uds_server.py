import os
import stat
import asyncio

import pytest

from kaede.uds import UDSPort, UDSClient, UDSServer, UDSServerConfig, UDSServerLimits, UDSHandler
from kaede.uds.api.client import UDSClientConfig, UDSClientLimits
from kaede.uds.errors import UDSClosedError

class Running:
    """Starts a UDSServer on a temporary socket path for the duration of the block."""

    def __init__(self, path, on_connection, limits=None, config=None):
        self.path = path
        config = config or UDSServerConfig()

        if limits is not None:
            config.limits = limits

        self.server = UDSServer(config)
        self.handler = UDSHandler(on_connection)

    async def __aenter__(self):
        await self.server.listen(self.handler, [self.path])
        return self.server

    async def __aexit__(self, *_):
        await self.server.close(timeout=2)

@pytest.fixture
def socket_path(uds_dir):
    return UDSPort(os.path.join(uds_dir, "kaede.sock"))

async def upper(connection):
    data = await connection.receive_exactly(5)
    await connection.send(data.upper())

class TestServing:
    async def test_serves_a_client(self, socket_path):
        async with Running(socket_path, upper):
            reader, writer = await asyncio.open_unix_connection(str(socket_path))
            writer.write(b"hello")
            await writer.drain()

            assert await reader.read(5) == b"HELLO"
            writer.close()

    async def test_serves_many_clients(self, socket_path):
        async with Running(socket_path, upper):
            async def once():
                reader, writer = await asyncio.open_unix_connection(str(socket_path))
                writer.write(b"hello")
                await writer.drain()
                data = await reader.read(5)
                writer.close()
                return data

            assert await asyncio.gather(*[once() for _ in range(25)]) == [b"HELLO"] * 25

    async def test_reports_the_bound_path(self, socket_path):
        async with Running(socket_path, upper) as server:
            assert server.paths == [socket_path]

    async def test_creates_the_socket_file(self, socket_path):
        async with Running(socket_path, upper):
            assert os.path.exists(str(socket_path))
            assert stat.S_ISSOCK(os.stat(str(socket_path)).st_mode)

    async def test_removes_the_socket_file_on_close(self, socket_path):
        async with Running(socket_path, upper):
            pass

        assert not os.path.exists(str(socket_path))

    async def test_replaces_a_stale_socket_file(self, socket_path):
        # A socket file left behind by a crashed previous run must not block
        # a fresh bind with "address already in use".
        with open(str(socket_path), "w") as f:
            f.write("stale")

        async with Running(socket_path, upper):
            assert stat.S_ISSOCK(os.stat(str(socket_path)).st_mode)

    async def test_applies_the_configured_permission_mode(self, socket_path):
        config = UDSServerConfig(mode=0o600)

        async with Running(socket_path, upper, config=config):
            assert stat.S_IMODE(os.stat(str(socket_path)).st_mode) == 0o600

    async def test_listens_on_several_paths(self, uds_dir):
        first = UDSPort(os.path.join(uds_dir, "a.sock"))
        second = UDSPort(os.path.join(uds_dir, "b.sock"))

        server = UDSServer()

        try:
            await server.listen(UDSHandler(upper), [first, second])
            assert sorted(server.paths) == sorted([first, second])

        finally:
            await server.close(timeout=2)

    async def test_a_failure_partway_through_listening_leaks_nothing(self, uds_dir, monkeypatch):
        # If create_unix_server fails for one of several paths, every socket
        # bound so far -- attached or not -- must be closed and unlinked, and
        # the server must be left with no partially-attached state.
        first = UDSPort(os.path.join(uds_dir, "a.sock"))
        second = UDSPort(os.path.join(uds_dir, "b.sock"))

        server = UDSServer()
        loop = asyncio.get_running_loop()
        original = loop.create_unix_server
        attempts = []

        async def flaky(factory, *, sock, **kwargs):
            attempts.append(sock)

            if len(attempts) == 2:
                raise RuntimeError("boom")

            return await original(factory, sock=sock, **kwargs)

        monkeypatch.setattr(loop, "create_unix_server", flaky)

        with pytest.raises(RuntimeError):
            await server.listen(UDSHandler(upper), [first, second])

        assert server.servers == []
        assert not os.path.exists(str(first))
        assert not os.path.exists(str(second))

        for sock in attempts:
            assert sock.fileno() == -1

    async def test_rejects_listening_without_any_path(self):
        server = UDSServer()

        with pytest.raises(ValueError):
            await server.listen(UDSHandler(upper), [])

    async def test_a_synchronous_handler_is_supported(self, socket_path):
        # Unlike TCP, a client that never bound has no address of its own, so
        # it is the accepted connection's local (src) side, not its peer
        # (dst), that identifies the server's own listening path.
        seen = []

        def note(connection):
            seen.append(connection.src)

        async with Running(socket_path, note):
            reader, writer = await asyncio.open_unix_connection(str(socket_path))
            assert await reader.read() == b""  # the server closes once the handler returns
            writer.close()

        assert seen == [socket_path]

    async def test_the_connection_is_closed_after_the_handler_returns(self, socket_path):
        async def greet(connection):
            await connection.send(b"bye")

        async with Running(socket_path, greet):
            reader, writer = await asyncio.open_unix_connection(str(socket_path))

            assert await reader.read() == b"bye"  # read() returns only at EOF
            writer.close()

    async def test_a_failing_handler_does_not_stop_the_server(self, socket_path):
        async def crash(connection):
            raise RuntimeError("handler failed")

        async with Running(socket_path, crash):
            reader, writer = await asyncio.open_unix_connection(str(socket_path))
            await reader.read()
            writer.close()

            # The next client must still be served.
            reader, writer = await asyncio.open_unix_connection(str(socket_path))
            await reader.read()
            writer.close()

    async def test_a_handler_error_is_reported_through_the_loop(self, socket_path):
        # It must not surface as "Task exception was never retrieved" on stderr.
        reported = []
        loop = asyncio.get_running_loop()
        previous = loop.get_exception_handler()
        loop.set_exception_handler(lambda _, context: reported.append(context))

        async def crash(connection):
            raise RuntimeError("handler failed")

        try:
            async with Running(socket_path, crash):
                reader, writer = await asyncio.open_unix_connection(str(socket_path))
                await reader.read()
                writer.close()
                await writer.wait_closed()

        finally:
            loop.set_exception_handler(previous)

        assert any(isinstance(context.get("exception"), RuntimeError) for context in reported)

    async def test_a_peer_reset_is_not_reported_as_a_handler_error(self, socket_path):
        # A client vanishing mid-exchange is routine and must stay quiet.
        reported = []
        loop = asyncio.get_running_loop()
        previous = loop.get_exception_handler()
        loop.set_exception_handler(lambda _, context: reported.append(context))

        async def expect(connection):
            await connection.receive_exactly(1024)

        try:
            async with Running(socket_path, expect):
                reader, writer = await asyncio.open_unix_connection(str(socket_path))
                writer.write(b"partial")
                await writer.drain()

                # Abort rather than close, so the peer sees a reset.
                writer.transport.abort()
                await asyncio.sleep(0.05)

        finally:
            loop.set_exception_handler(previous)

        assert reported == []

    async def test_serve_blocks_until_close(self, socket_path):
        server = UDSServer()
        serving = asyncio.ensure_future(server.serve(UDSHandler(upper), [socket_path]))

        while not server.servers:
            await asyncio.sleep(0)

        assert not serving.done()

        await server.close(timeout=2)
        await asyncio.wait_for(serving, 2)

class TestLimits:
    async def test_refuses_connections_beyond_the_count_limit(self, socket_path):
        limits = UDSServerLimits()
        limits.max_connection_nums = 2
        limits.max_connection_rate = []

        held = asyncio.Event()

        async def hold(connection):
            await held.wait()

        async with Running(socket_path, hold, limits):
            kept = [await asyncio.open_unix_connection(str(socket_path)) for _ in range(2)]

            # The third is admitted by the kernel but aborted by the gate.
            reader, writer = await asyncio.open_unix_connection(str(socket_path))
            assert await reader.read() == b""

            writer.close()
            held.set()

            for _, other in kept:
                other.close()

    async def test_refuses_connections_beyond_the_rate_limit(self, socket_path):
        limits = UDSServerLimits()
        limits.max_connection_rate = [(60, 3)]

        async def bye(connection):
            await connection.send(b"ok")

        async with Running(socket_path, bye, limits):
            served = 0

            for _ in range(6):
                reader, writer = await asyncio.open_unix_connection(str(socket_path))

                if await reader.read() == b"ok":
                    served += 1

                writer.close()

            assert served == 3

    async def test_a_closed_connection_frees_its_slot(self, socket_path):
        limits = UDSServerLimits()
        limits.max_connection_nums = 1
        limits.max_connection_rate = []

        async def bye(connection):
            await connection.send(b"ok")

        async with Running(socket_path, bye, limits):
            for _ in range(5):
                reader, writer = await asyncio.open_unix_connection(str(socket_path))
                assert await reader.read() == b"ok"

                writer.close()
                await writer.wait_closed()

class TestClient:
    async def test_opens_a_connection(self, socket_path):
        async with Running(socket_path, upper):
            client = UDSClient(socket_path)
            connection = await client.open()

            await connection.send(b"hello")
            assert await connection.receive_exactly(5) == b"HELLO"

            await client.close()

    async def test_works_as_a_context_manager(self, socket_path):
        async with Running(socket_path, upper):
            async with UDSClient(socket_path) as connection:
                await connection.send(b"hello")
                assert await connection.receive_exactly(5) == b"HELLO"

    async def test_closing_the_client_closes_its_connections(self, socket_path):
        async with Running(socket_path, upper):
            client = UDSClient(socket_path)

            first = await client.open()
            second = await client.open()

            await client.close()

            for connection in (first, second):
                with pytest.raises(UDSClosedError):
                    await connection.send(b"late")

    async def test_rejects_a_path_beyond_the_limit(self):
        with pytest.raises(ValueError):
            UDSClient(UDSPort("/" + "a" * UDSPort.limit))

    async def test_rejects_connecting_to_a_missing_socket(self, uds_dir):
        client = UDSClient(UDSPort(os.path.join(uds_dir, "nobody-home.sock")))

        with pytest.raises(Exception):
            await client.open()

    async def test_the_connect_timeout_is_configurable(self, socket_path, monkeypatch):
        async def stall(*args, **kwargs):
            await asyncio.sleep(10)

        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, "create_unix_connection", stall)

        config = UDSClientConfig(limits=UDSClientLimits(timeout_connection=0.05))
        client = UDSClient(socket_path, config=config)

        with pytest.raises(Exception):
            await client.open()

class TestIdle:
    # Unlike UDP, a stream socket has a real lifecycle, but a peer that connects
    # and then falls silent still holds a slot. With an idle_timeout the server
    # reaps it and unblocks the handler.

    async def test_an_idle_connection_is_reaped(self, socket_path):
        woken = asyncio.Event()

        async def stall(connection):
            await connection.receive(1)  # blocks until the reaper drops the connection
            woken.set()

        async with Running(socket_path, stall, config=UDSServerConfig(limits=UDSServerLimits(idle_timeout=0.05))) as server:
            async with UDSClient(socket_path):
                await asyncio.sleep(0.15)
                server.expire()

                await asyncio.wait_for(woken.wait(), 2)

    async def test_a_fresh_connection_is_kept(self, socket_path):
        async def hold(connection):
            await connection.receive(1)

        async with Running(socket_path, hold, config=UDSServerConfig(limits=UDSServerLimits(idle_timeout=100.0))) as server:
            async with UDSClient(socket_path):
                await asyncio.sleep(0.1)
                server.expire()

                assert len(server.connections) == 1

    async def test_the_mode_is_applied_before_the_socket_accepts(self, socket_path):
        # The socket file must never be reachable with looser permissions than
        # requested; binding under a tightened umask means even the moment before
        # the explicit chmod is already restricted.
        async with Running(socket_path, upper, config=UDSServerConfig(mode=0o600)):
            assert stat.S_IMODE(os.stat(str(socket_path)).st_mode) == 0o600
