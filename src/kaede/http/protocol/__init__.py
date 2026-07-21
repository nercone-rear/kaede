from .common import HTTPState
from .base import HTTPConnection, HTTPProtocol
from .h1 import H1Connection, H1Protocol
from .handler import HTTPUDSHandler, HTTPTCPHandler, HTTPQUICHandler

__all__ = ["HTTPState", "HTTPConnection", "HTTPProtocol", "H1Connection", "H1Protocol", "HTTPUDSHandler", "HTTPTCPHandler", "HTTPQUICHandler"]

def __getattr__(name):
    if name in ("H2Connection", "H2Protocol"):
        from .h2 import H2Connection, H2Protocol
        return {"H2Connection": H2Connection, "H2Protocol": H2Protocol}[name]

    if name in ("H3Connection", "H3Protocol"):
        from .h3 import H3Connection, H3Protocol
        return {"H3Connection": H3Connection, "H3Protocol": H3Protocol}[name]

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
