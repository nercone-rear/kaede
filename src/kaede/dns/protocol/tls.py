from typing import Optional, Tuple, TYPE_CHECKING

from ...tls import TLSConfig
from ...tls.openssl import TLSContext
from ...tcp.tls import TLSConnection
from .tcp import DNSTCPConnection, DNSTCPProtocol

if TYPE_CHECKING:
    from ..api.client import DNSClientLimits

class DNSTLSConnection(DNSTCPConnection):
    pass

class DNSTLSProtocol(DNSTCPProtocol):
    carrier = DNSTLSConnection

    def __init__(self, dst: Tuple[str, int], *, tls: Optional[TLSConfig] = None, hostname: Optional[str] = None, limits: Optional["DNSClientLimits"] = None):
        super().__init__(dst, limits=limits)

        self.hostname = hostname
        self.context = TLSContext(tls or TLSConfig(), server=False, alpn=["dot"])

    async def open(self):
        connection = await super().open()

        try:
            return await TLSConnection.connect(connection, hostname=self.hostname or self.dst[0], timeout=self.limits.timeout_connection, context=self.context)

        except BaseException:
            await connection.close()
            raise
