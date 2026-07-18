class QUICError(Exception):
    """Generic exception for QUIC processing"""

class QUICConnectionError(QUICError):
    """An exception that occurs when a connection cannot be established."""

class QUICClosedError(QUICError):
    """An exception that occurs when an operation is attempted on a connection that is already closed."""

class QUICLostError(QUICError):
    """An exception that occurs when a connection is lost before the peer closed it cleanly."""

class QUICTimeoutError(QUICError):
    """An exception that occurs when an operation does not complete within the allowed time."""

class QUICBusyError(QUICError):
    """An exception that occurs when a connection is used concurrently by more than one coroutine."""

class QUICLimitError(QUICError):
    """An exception that occurs when a configured limit is exceeded."""

class QUICStreamError(QUICError):
    """An exception that occurs when the peer abandons a stream rather than ending it."""

    def __init__(self, message: str, code: int = 0):
        self.code = code
        super().__init__(message)
