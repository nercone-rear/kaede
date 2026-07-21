import asyncio
import socket

import pytest

from kaede.tcp import TCPPort, TCPConnection, TCPProtocol, TCPLimits
from kaede.tcp.errors import TCPConnectionError, TCPClosedError, TCPTimeoutError, TCPBusyError, TCPLimitError

# The peer in these tests is the standard library's asyncio server rather than
# Kaede itself, so that the behaviour is checked against an independent
# implementation of RFC 9293 rather than against Kaede's own assumptions.

class Server:
    """A stdlib asyncio server that runs `serve` for each accepted connection."""

    def __init__(self, serve):
        self.serve = serve
        self.server = None
        self.host = "127.0.0.1"
        self.port = 0

    async def __aenter__(self):
        self.server = await asyncio.start_server(self.serve, self.host, 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *_):
        self.server.close()
        await self.server.wait_closed()

    @property
    def address(self):
        return (self.host, TCPPort(self.port))

def connection(server) -> TCPConnection:
    return TCPConnection(("", TCPPort(0)), server.address)

async def echo(reader, writer):
    while True:
        data = await reader.read(4096)
        if not data:
            break
        writer.write(data)
        await writer.drain()

    writer.close()

class TestRoundTrip:
    async def test_sends_and_receives(self):
        async with Server(echo) as server:
            tcp = connection(server)
            await tcp.connect()

            await tcp.send(b"hello")
            assert await tcp.receive_exactly(5) == b"hello"

            await tcp.close()

    async def test_preserves_stream_order_and_content(self):
        # TCP is a byte stream: what is written must arrive in the same order,
        # regardless of how it was split into segments.
        async with Server(echo) as server:
            tcp = connection(server)
            await tcp.connect()

            expected = b""
            for i in range(100):
                chunk = bytes([i % 256]) * (i + 1)
                await tcp.send(chunk)
                expected += chunk

            assert await tcp.receive_exactly(len(expected)) == expected
            await tcp.close()

    async def test_carries_data_larger_than_the_buffer_limit(self):
        # Flow control must not lose or reorder data when the receive buffer
        # fills and the transport is paused.
        payload = bytes(range(256)) * 8192 # 2 MiB, far above buffer_limit

        async def send(reader, writer):
            writer.write(payload)
            await writer.drain()
            writer.close()

        async with Server(send) as server:
            tcp = connection(server)
            await tcp.connect()

            assert await tcp.receive(-1) == payload
            await tcp.close()

    async def test_records_the_local_and_remote_addresses(self):
        async with Server(echo) as server:
            tcp = connection(server)
            await tcp.connect()

            assert tcp.dst == server.address
            assert tcp.src[0] == "127.0.0.1"
            assert 0 < tcp.src[1] <= 65535

            await tcp.close()

class TestReceive:
    async def test_receive_all_reads_until_eof(self):
        async def send(reader, writer):
            writer.write(b"abc")
            await writer.drain()
            writer.close()

        async with Server(send) as server:
            tcp = connection(server)
            await tcp.connect()

            assert await tcp.receive(-1) == b"abc"
            await tcp.close()

    async def test_receive_returns_at_most_n_bytes(self):
        async def send(reader, writer):
            writer.write(b"abcdef")
            await writer.drain()
            await reader.read()  # stay open until the client closes
            writer.close()

        async with Server(send) as server:
            tcp = connection(server)
            await tcp.connect()

            first = await tcp.receive(2)
            assert len(first) <= 2
            assert b"abcdef".startswith(first)

            await tcp.close()

    async def test_receive_zero_returns_empty(self):
        async with Server(echo) as server:
            tcp = connection(server)
            await tcp.connect()

            assert await tcp.receive(0) == b""
            await tcp.close()

    async def test_receive_after_eof_returns_empty(self):
        async def close(reader, writer):
            writer.close()

        async with Server(close) as server:
            tcp = connection(server)
            await tcp.connect()

            assert await tcp.receive(-1) == b""
            assert await tcp.receive(-1) == b""

            await tcp.close()

    async def test_receive_exactly_waits_for_every_byte(self):
        async def dribble(reader, writer):
            for byte in b"abcdefghij":
                writer.write(bytes([byte]))
                await writer.drain()
                await asyncio.sleep(0)

            writer.close()

        async with Server(dribble) as server:
            tcp = connection(server)
            await tcp.connect()

            assert await tcp.receive_exactly(10) == b"abcdefghij"
            await tcp.close()

    async def test_receive_exactly_beyond_the_buffer_limit(self):
        # A request larger than buffer_limit must not deadlock against flow control.
        size = TCPLimits().max_buffer_size * 4
        payload = b"K" * size

        async def send(reader, writer):
            writer.write(payload)
            await writer.drain()
            writer.close()

        async with Server(send) as server:
            tcp = connection(server)
            await tcp.connect()

            assert await tcp.receive_exactly(size) == payload
            await tcp.close()

    async def test_receive_exactly_rejects_a_short_stream(self):
        async def send(reader, writer):
            writer.write(b"abc")
            await writer.drain()
            writer.close()

        async with Server(send) as server:
            tcp = connection(server)
            await tcp.connect()

            with pytest.raises(TCPClosedError):
                await tcp.receive_exactly(10)

            await tcp.close()

    async def test_receive_until_splits_on_the_separator(self):
        async def send(reader, writer):
            writer.write(b"one\r\ntwo\r\nthree")
            await writer.drain()
            writer.close()

        async with Server(send) as server:
            tcp = connection(server)
            await tcp.connect()

            assert await tcp.receive_until(b"\r\n") == b"one\r\n"
            assert await tcp.receive_until(b"\r\n") == b"two\r\n"

            with pytest.raises(TCPClosedError):
                await tcp.receive_until(b"\r\n")

            await tcp.close()

    async def test_receive_until_finds_a_separator_split_across_segments(self):
        async def send(reader, writer):
            writer.write(b"line\r")
            await writer.drain()
            await asyncio.sleep(0.01)
            writer.write(b"\nrest")
            await writer.drain()
            await reader.read()  # stay open until the client closes
            writer.close()

        async with Server(send) as server:
            tcp = connection(server)
            await tcp.connect()

            assert await tcp.receive_until(b"\r\n") == b"line\r\n"
            await tcp.close()

    async def test_receive_until_enforces_its_limit(self):
        async def send(reader, writer):
            writer.write(b"x" * 4096)
            await writer.drain()
            await reader.read()  # stay open until the client closes
            writer.close()

        async with Server(send) as server:
            tcp = connection(server)
            await tcp.connect()

            with pytest.raises(TCPLimitError):
                await tcp.receive_until(b"\n", limit=128)

            await tcp.close()

    async def test_receive_until_rejects_an_empty_separator(self):
        async with Server(echo) as server:
            tcp = connection(server)
            await tcp.connect()

            with pytest.raises(ValueError):
                await tcp.receive_until(b"")

            await tcp.close()

class TestHalfClose:
    async def test_half_close_sends_fin_but_keeps_receiving(self):
        # RFC 9293 section 3.6: after sending FIN a connection may still receive.
        async def reply(reader, writer):
            assert await reader.read() == b"question"  # completes only once FIN arrives
            writer.write(b"answer")
            await writer.drain()
            writer.close()

        async with Server(reply) as server:
            tcp = connection(server)
            await tcp.connect()

            await tcp.send(b"question")
            await tcp.close(half_close=True)

            assert await tcp.receive(-1) == b"answer"
            await tcp.close()

    async def test_sending_after_half_close_is_rejected(self):
        async with Server(echo) as server:
            tcp = connection(server)
            await tcp.connect()

            await tcp.close(half_close=True)

            with pytest.raises(TCPClosedError):
                await tcp.send(b"late")

            await tcp.close()

class TestErrors:
    async def test_connecting_to_a_closed_port_is_refused(self):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        tcp = TCPConnection(("", TCPPort(0)), ("127.0.0.1", TCPPort(port)))

        with pytest.raises(TCPConnectionError):
            await tcp.connect()

    async def test_connect_timeout_is_reported(self):
        # 203.0.113.0/24 is TEST-NET-3 (RFC 5737) and is not routable.
        tcp = TCPConnection(("", TCPPort(0)), ("203.0.113.1", TCPPort(80)))

        with pytest.raises(TCPTimeoutError):
            await tcp.connect(timeout=0.2)

    async def test_connecting_twice_is_rejected(self):
        async with Server(echo) as server:
            tcp = connection(server)
            await tcp.connect()

            with pytest.raises(TCPConnectionError):
                await tcp.connect()

            await tcp.close()

    async def test_sending_before_connecting_is_rejected(self):
        tcp = TCPConnection(("", TCPPort(0)), ("127.0.0.1", TCPPort(9)))

        with pytest.raises(TCPClosedError):
            await tcp.send(b"early")

    async def test_sending_after_close_is_rejected(self):
        async with Server(echo) as server:
            tcp = connection(server)
            await tcp.connect()
            await tcp.close()

            with pytest.raises(TCPClosedError):
                await tcp.send(b"late")

    async def test_concurrent_receive_is_rejected(self):
        async with Server(echo) as server:
            tcp = connection(server)
            await tcp.connect()

            first = asyncio.ensure_future(tcp.receive(1))
            await asyncio.sleep(0)

            with pytest.raises(TCPBusyError):
                await tcp.receive(1)

            first.cancel()
            await tcp.close()

    async def test_close_is_idempotent(self):
        async with Server(echo) as server:
            tcp = connection(server)
            await tcp.connect()

            await tcp.close()
            await tcp.close()

    async def test_close_without_connecting_is_harmless(self):
        tcp = TCPConnection(("", TCPPort(0)), ("127.0.0.1", TCPPort(9)))
        await tcp.close()

class TestServerSide:
    async def test_kaede_protocol_accepts_a_stdlib_client(self):
        # The same connection object must work when Kaede is the accepting side.
        received = asyncio.get_event_loop().create_future()

        class Handler:
            def __init__(self):
                self.on_connection = self.serve

            async def serve(self, tcp):
                data = await tcp.receive_exactly(5)
                await tcp.send(data.upper())
                await tcp.close()

        async def accept():
            loop = asyncio.get_running_loop()
            server = await loop.create_server(lambda: Accepting(), "127.0.0.1", 0)
            return server

        class Accepting(TCPProtocol):
            def connection_made(self, transport):
                super().connection_made(transport)
                asyncio.ensure_future(self.run())

            async def run(self):
                data = await self.connection.receive_exactly(5)
                await self.connection.send(data.upper())
                await self.connection.close()
                received.set_result(data)

        server = await accept()
        port = server.sockets[0].getsockname()[1]

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"hello")
        await writer.drain()

        assert await reader.read() == b"HELLO"
        assert await received == b"hello"

        writer.close()
        server.close()
        await server.wait_closed()
