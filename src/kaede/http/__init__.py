from .models import HTTPVersion, HTTPMethod, HTTPBroadRole, HTTPRole, HTTPPort, HTTPHeaderCase, HTTPHeaders, HTTPLimits, HTTPMessage, HTTPRequest, HTTPResponse

__all__ = ["HTTPVersion", "HTTPMethod", "HTTPBroadRole", "HTTPRole", "HTTPPort", "HTTPHeaderCase", "HTTPHeaders", "HTTPLimits", "HTTPMessage", "HTTPRequest", "HTTPResponse"]

def __getattr__(name):
    if name in ("HTTPClient", "HTTPClientConfig"):
        from .api.client import HTTPClient, HTTPClientConfig
        return {"HTTPClient": HTTPClient, "HTTPClientConfig": HTTPClientConfig}[name]

    if name in ("HTTPServer", "HTTPServerConfig", "HTTPServerLimits", "HTTPHandler"):
        from .api.server import HTTPServer, HTTPServerConfig, HTTPServerLimits, HTTPHandler
        return {"HTTPServer": HTTPServer, "HTTPServerConfig": HTTPServerConfig, "HTTPServerLimits": HTTPServerLimits, "HTTPHandler": HTTPHandler}[name]

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
