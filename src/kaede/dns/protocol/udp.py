import asyncio
import secrets
from typing import Optional, Tuple, TYPE_CHECKING

from ...udp import UDPPort, UDPConnection
from ...udp.errors import UDPError, UDPTimeoutError
from ..models import DNSMessage
from ..errors import DNSError, DNSConnectionError, DNSTimeoutError
from .base import DNSConnection, DNSProtocol

if TYPE_CHECKING:
    from ..api.client import DNSClientLimits

class DNSUDPConnection(DNSConnection):
    def __init__(self, transport, *, server: bool = False):
        super().__init__(transport, stream=False, server=server)

class DNSUDPProtocol(DNSProtocol):
    def __init__(self, dst: Tuple[str, int], *, limits: Optional["DNSClientLimits"] = None):
        from ..api.client import DNSClientLimits

        self.dst = dst
        self.limits = limits or DNSClientLimits()

    async def query(self, message: DNSMessage, *, timeout: Optional[float] = None) -> DNSMessage:
        timeout = self.limits.timeout_query if timeout is None else timeout
        last: Optional[DNSError] = None

        for _ in range(max(1, self.limits.max_retries + 1)):
            message.id = secrets.randbits(16)

            try:
                return await self.attempt(message, timeout)

            except DNSTimeoutError as e:
                last = e

        raise last

    async def attempt(self, message: DNSMessage, timeout: float) -> DNSMessage:
        connection = UDPConnection(("", UDPPort(0)), (self.dst[0], UDPPort(self.dst[1])))

        try:
            await connection.connect(timeout)
            await connection.send(message.pack())

            loop = asyncio.get_running_loop()
            deadline = loop.time() + timeout

            while True:
                remaining = deadline - loop.time()

                if remaining <= 0:
                    raise DNSTimeoutError(f"{self.dst[0]} did not answer within {timeout} seconds.")

                try:
                    data = await connection.receive(timeout=remaining)

                except UDPTimeoutError:
                    raise DNSTimeoutError(f"{self.dst[0]} did not answer within {timeout} seconds.")

                try:
                    response = DNSMessage.unpack(data)

                except DNSError:
                    continue

                if message.matches(response):
                    return response

        except UDPError as e:
            raise DNSConnectionError(f"The UDP exchange with {self.dst[0]} failed: {e}") from e

        finally:
            await connection.close()

    async def close(self):
        return
