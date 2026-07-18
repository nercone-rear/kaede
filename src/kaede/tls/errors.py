class TLSError(Exception):
    ...

class TLSLibraryNotFoundError(TLSError):
    ...

class TLSLibraryError(TLSError):
    """An exception that occurs when the OpenSSL library is unusable or too old."""

class TLSConfigError(TLSError):
    """An exception that occurs when a TLS configuration is rejected by OpenSSL."""

class TLSHandshakeError(TLSError):
    """An exception that occurs when a handshake cannot be completed."""

class TLSVerificationError(TLSHandshakeError):
    """An exception that occurs when the peer's certificate is not trusted."""

    def __init__(self, message: str, code: int = 0):
        self.code = code
        super().__init__(message)

class TLSClosedError(TLSError):
    """An exception that occurs when an operation is attempted after the session ended."""

class TLSProtocolError(TLSError):
    """An exception that occurs when OpenSSL reports a protocol level failure."""
