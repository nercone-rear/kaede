import asyncio
import os

import pytest

from kaede.uds import UDSAddress, UDSConnection, UDSProtocol
from kaede.uds.errors import UDSConnectionError, UDSClosedError, UDSTimeoutError, UDSBusyError, UDSLimitError

# The peer in these tests is the standard library's asyncio unix server rather
# than Kaede itself, so that the behaviour is checked against an independent
# implementation of the stream semantics rather than against Kaede's own
# assumptions.

class Server:
    """A stdlib asyncio unix server that runs `serve` for each accepted connection."""

    def __init__(self, serve, path):
        self.serve = serve
        self.path = path
        self.server = None

    async def __aenter__(self):
        self.server = await asyncio.start_unix_server(self.serve, str(self.path))
        return self

    async def __aexit__(self, *_):
        self.server.close()
        await self.server.wait_closed()

    @property
    def address(self):
        return self.path

def connection(server) -> UDSConnection:
    return UDSConnection(UDSAddress(""), server.address)

async def echo(reader, writer):
    while True:
        data = await reader.read(4096)
        if not data:
            break
        writer.write(data)
        await writer.drain()

    writer.close()

@pytest.fixture
def socket_path(uds_dir):
    return UDSAddress(os.path.join(uds_dir, "kaede.sock"))

class TestRoundTrip:
    async def test_sends_and_receives(self, socket_path):
        async with Server(echo, socket_path) as server:
            uds = connection(server)
            await uds.connect()

            await uds.send(b"hello")
            assert await uds.receive_exactly(5) == b"hello"

            await uds.close()

    async def test_preserves_stream_order_and_content(self, socket_path):
        async with Server(echo, socket_path) as server:
            uds = connection(server)
            await uds.connect()

            expected = b""
            for i in range(100):
                chunk = bytes([i % 256]) * (i + 1)
                await uds.send(chunk)
                expected += chunk

            assert await uds.receive_exactly(len(expected)) == expected
            await uds.close()

    async def test_carries_data_larger_than_the_buffer_limit(self, socket_path):
        # Flow control must not lose or reorder data when the receive buffer
        # fills and the transport is paused.
        payload = bytes(range(256)) * 8192 # 2 MiB, far above buffer_limit

        async def send(reader, writer):
            writer.write(payload)
            await writer.drain()
            writer.close()

        async with Server(send, socket_path) as server:
            uds = connection(server)
            await uds.connect()

            assert await uds.receive(-1) == payload
            await uds.close()

    async def test_records_the_local_and_remote_addresses(self, socket_path):
        async with Server(echo, socket_path) as server:
            uds = connection(server)
            await uds.connect()

            assert uds.dst == server.address

            await uds.close()

class TestReceive:
    async def test_receive_all_reads_until_eof(self, socket_path):
        async def send(reader, writer):
            writer.write(b"abc")
            await writer.drain()
            writer.close()

        async with Server(send, socket_path) as server:
            uds = connection(server)
            await uds.connect()

            assert await uds.receive(-1) == b"abc"
            await uds.close()

    async def test_receive_returns_at_most_n_bytes(self, socket_path):
        async def send(reader, writer):
            writer.write(b"abcdef")
            await writer.drain()
            await reader.read()  # stay open until the client closes
            writer.close()

        async with Server(send, socket_path) as server:
            uds = connection(server)
            await uds.connect()

            first = await uds.receive(2)
            assert len(first) <= 2
            assert b"abcdef".startswith(first)

            await uds.close()

    async def test_receive_zero_returns_empty(self, socket_path):
        async with Server(echo, socket_path) as server:
            uds = connection(server)
            await uds.connect()

            assert await uds.receive(0) == b""
            await uds.close()

    async def test_receive_after_eof_returns_empty(self, socket_path):
        async def close(reader, writer):
            writer.close()

        async with Server(close, socket_path) as server:
            uds = connection(server)
            await uds.connect()

            assert await uds.receive(-1) == b""
            assert await uds.receive(-1) == b""

            await uds.close()

    async def test_receive_exactly_waits_for_every_byte(self, socket_path):
        async def dribble(reader, writer):
            for byte in b"abcdefghij":
                writer.write(bytes([byte]))
                await writer.drain()
                await asyncio.sleep(0)

            writer.close()

        async with Server(dribble, socket_path) as server:
            uds = connection(server)
            await uds.connect()

            assert await uds.receive_exactly(10) == b"abcdefghij"
            await uds.close()

    async def test_receive_exactly_beyond_the_buffer_limit(self, socket_path):
        # A request larger than buffer_limit must not deadlock against flow control.
        size = UDSConnection.buffer_limit * 4
        payload = b"K" * size

        async def send(reader, writer):
            writer.write(payload)
            await writer.drain()
            writer.close()

        async with Server(send, socket_path) as server:
            uds = connection(server)
            await uds.connect()

            assert await uds.receive_exactly(size) == payload
            await uds.close()

    async def test_receive_exactly_rejects_a_short_stream(self, socket_path):
        async def send(reader, writer):
            writer.write(b"abc")
            await writer.drain()
            writer.close()

        async with Server(send, socket_path) as server:
            uds = connection(server)
            await uds.connect()

            with pytest.raises(UDSClosedError):
                await uds.receive_exactly(10)

            await uds.close()

    async def test_receive_until_splits_on_the_separator(self, socket_path):
        async def send(reader, writer):
            writer.write(b"one\r\ntwo\r\nthree")
            await writer.drain()
            writer.close()

        async with Server(send, socket_path) as server:
            uds = connection(server)
            await uds.connect()

            assert await uds.receive_until(b"\r\n") == b"one\r\n"
            assert await uds.receive_until(b"\r\n") == b"two\r\n"

            with pytest.raises(UDSClosedError):
                await uds.receive_until(b"\r\n")

            await uds.close()

    async def test_receive_until_finds_a_separator_split_across_segments(self, socket_path):
        async def send(reader, writer):
            writer.write(b"line\r")
            await writer.drain()
            await asyncio.sleep(0.01)
            writer.write(b"\nrest")
            await writer.drain()
            await reader.read()  # stay open until the client closes
            writer.close()

        async with Server(send, socket_path) as server:
            uds = connection(server)
            await uds.connect()

            assert await uds.receive_until(b"\r\n") == b"line\r\n"
            await uds.close()

    async def test_receive_until_enforces_its_limit(self, socket_path):
        async def send(reader, writer):
            writer.write(b"x" * 4096)
            await writer.drain()
            await reader.read()  # stay open until the client closes
            writer.close()

        async with Server(send, socket_path) as server:
            uds = connection(server)
            await uds.connect()

            with pytest.raises(UDSLimitError):
                await uds.receive_until(b"\n", limit=128)

            await uds.close()

    async def test_receive_until_rejects_an_empty_separator(self, socket_path):
        async with Server(echo, socket_path) as server:
            uds = connection(server)
            await uds.connect()

            with pytest.raises(ValueError):
                await uds.receive_until(b"")

            await uds.close()

class TestHalfClose:
    async def test_half_close_sends_fin_but_keeps_receiving(self, socket_path):
        async def reply(reader, writer):
            assert await reader.read() == b"question"  # completes only once FIN arrives
            writer.write(b"answer")
            await writer.drain()
            writer.close()

        async with Server(reply, socket_path) as server:
            uds = connection(server)
            await uds.connect()

            await uds.send(b"question")
            await uds.close(half_close=True)

            assert await uds.receive(-1) == b"answer"
            await uds.close()

    async def test_sending_after_half_close_is_rejected(self, socket_path):
        async with Server(echo, socket_path) as server:
            uds = connection(server)
            await uds.connect()

            await uds.close(half_close=True)

            with pytest.raises(UDSClosedError):
                await uds.send(b"late")

class TestErrors:
    async def test_connecting_to_a_missing_path_is_refused(self, socket_path):
        uds = UDSConnection(UDSAddress(""), socket_path)  # nothing is listening there

        with pytest.raises(UDSConnectionError):
            await uds.connect()

    async def test_connect_timeout_is_reported(self, socket_path, monkeypatch):
        # A local connect() cannot be made to hang the way an unroutable IP
        # does for TCP, so the timeout wrapping itself is checked directly by
        # making the underlying asyncio call never resolve.
        async def stall(*args, **kwargs):
            await asyncio.sleep(10)

        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, "create_unix_connection", stall)

        uds = UDSConnection(UDSAddress(""), socket_path)

        with pytest.raises(UDSTimeoutError):
            await uds.connect(timeout=0.05)

    async def test_connecting_twice_is_rejected(self, socket_path):
        async with Server(echo, socket_path) as server:
            uds = connection(server)
            await uds.connect()

            with pytest.raises(UDSConnectionError):
                await uds.connect()

            await uds.close()

    async def test_sending_before_connecting_is_rejected(self, socket_path):
        uds = UDSConnection(UDSAddress(""), socket_path)

        with pytest.raises(UDSClosedError):
            await uds.send(b"early")

    async def test_sending_after_close_is_rejected(self, socket_path):
        async with Server(echo, socket_path) as server:
            uds = connection(server)
            await uds.connect()
            await uds.close()

            with pytest.raises(UDSClosedError):
                await uds.send(b"late")

    async def test_concurrent_receive_is_rejected(self, socket_path):
        async with Server(echo, socket_path) as server:
            uds = connection(server)
            await uds.connect()

            first = asyncio.ensure_future(uds.receive(1))
            await asyncio.sleep(0)

            with pytest.raises(UDSBusyError):
                await uds.receive(1)

            first.cancel()
            await uds.close()

    async def test_close_is_idempotent(self, socket_path):
        async with Server(echo, socket_path) as server:
            uds = connection(server)
            await uds.connect()

            await uds.close()
            await uds.close()

    async def test_close_without_connecting_is_harmless(self, socket_path):
        uds = UDSConnection(UDSAddress(""), socket_path)
        await uds.close()

class TestServerSide:
    async def test_kaede_protocol_accepts_a_stdlib_client(self, socket_path):
        # The same connection object must work when Kaede is the accepting side.
        received = asyncio.get_event_loop().create_future()

        class Accepting(UDSProtocol):
            def connection_made(self, transport):
                super().connection_made(transport)
                asyncio.ensure_future(self.run())

            async def run(self):
                data = await self.connection.receive_exactly(5)
                await self.connection.send(data.upper())
                await self.connection.close()
                received.set_result(data)

        loop = asyncio.get_running_loop()
        server = await loop.create_unix_server(lambda: Accepting(), str(socket_path))

        reader, writer = await asyncio.open_unix_connection(str(socket_path))
        writer.write(b"hello")
        await writer.drain()

        assert await reader.read() == b"HELLO"
        assert await received == b"hello"

        writer.close()
        server.close()
        await server.wait_closed()
