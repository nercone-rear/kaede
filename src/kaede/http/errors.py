# HTTP
class HTTPError(Exception):
    """Generic exceptions with HTTP responses"""

    def __init__(self, code: int = 400, message: str = "Bad Request"):
        self.code = code
        self.message = message
        super().__init__(message)

class HTTPNotImplementedError(HTTPError):
    """An exception that occurs when a feature that has not been implemented is required."""

    def __init__(self, message: str = "Not Implemented"):
        self.code = 501
        self.message = message

class HTTPVersionNotSupportedError(HTTPError):
    """An exception that occurs when handling an unsupported HTTP version is required."""

    def __init__(self, message: str = "HTTP Version Not Supported"):
        self.code = 505
        self.message = message

# HTTP: Violation
class HTTPViolationError(Exception):
    """An exception that occurs when an HTTP specification violation is detected."""

class HTTPReportedViolationError(HTTPError, HTTPViolationError):
    """An exception accompanied by an HTTP response due to an HTTP specification violation."""

# WebSocket
class WebSocketError(Exception):
    """Generic exception with WebSocket closing code"""

    def __init__(self, code: int, message: str = ""):
        self.code = code
        self.message = message
        super().__init__(message)
