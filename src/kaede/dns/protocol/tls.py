from typing import Optional, Tuple

from ...tls import TLSConfig
from ...tls.openssl import TLSContext
from ...tcp.tls import TLSConnection
from .tcp import DNSTCPTransport

class DNSTLSTransport(DNSTCPTransport):
    def __init__(self, dst: Tuple[str, int], *, tls: Optional[TLSConfig] = None, hostname: Optional[str] = None, connect_timeout: float = 5.0):
        super().__init__(dst, connect_timeout=connect_timeout)

        self.hostname = hostname
        self.context = TLSContext(tls or TLSConfig(), server=False, alpn=["dot"])

    async def open(self):
        connection = await super().open()

        try:
            return await TLSConnection.connect(connection, hostname=self.hostname or self.dst[0], timeout=self.connect_timeout, context=self.context)

        except BaseException:
            await connection.close()
            raise
