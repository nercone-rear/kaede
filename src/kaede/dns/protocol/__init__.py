from .handler import DNSConnection
from .udp import DNSUDPTransport
from .tcp import DNSTCPTransport
from .tls import DNSTLSTransport
from .quic import DNSQUICTransport, DNSStream

__all__ = ["DNSConnection", "DNSUDPTransport", "DNSTCPTransport", "DNSTLSTransport", "DNSQUICTransport", "DNSStream"]

def __getattr__(name):
    if name in ("DNSHTTPSTransport", "DNSHTTPSHandler"):
        from .https import DNSHTTPSTransport, DNSHTTPSHandler
        return {"DNSHTTPSTransport": DNSHTTPSTransport, "DNSHTTPSHandler": DNSHTTPSHandler}[name]

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
