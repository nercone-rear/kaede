from .models import HTTPVersion, HTTPMethod, HTTPBroadRole, HTTPRole, HTTPPort, HTTPHeaderCase, HTTPHeaders, HTTPMessage, HTTPRequest, HTTPResponse
from .api.common import HTTPLimits, HTTPConfig

__all__ = ["HTTPVersion", "HTTPMethod", "HTTPBroadRole", "HTTPRole", "HTTPPort", "HTTPHeaderCase", "HTTPHeaders", "HTTPLimits", "HTTPConfig", "HTTPMessage", "HTTPRequest", "HTTPResponse"]

def __getattr__(name):
    if name in ("HTTPClient", "HTTPClientConfig", "HTTPClientLimits"):
        from .api.client import HTTPClient, HTTPClientConfig, HTTPClientLimits
        return {"HTTPClient": HTTPClient, "HTTPClientConfig": HTTPClientConfig, "HTTPClientLimits": HTTPClientLimits}[name]

    if name in ("HTTPServer", "HTTPServerConfig", "HTTPServerLimits", "HTTPHandler"):
        from .api.server import HTTPServer, HTTPServerConfig, HTTPServerLimits, HTTPHandler
        return {"HTTPServer": HTTPServer, "HTTPServerConfig": HTTPServerConfig, "HTTPServerLimits": HTTPServerLimits, "HTTPHandler": HTTPHandler}[name]

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
