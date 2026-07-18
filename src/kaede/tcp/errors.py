class TCPError(Exception):
    """Generic exception for TCP processing"""

class TCPConnectionError(TCPError):
    """An exception that occurs when a connection cannot be established."""

class TCPClosedError(TCPError):
    """An exception that occurs when an operation is attempted on a connection that is already closed."""

class TCPLostError(TCPError):
    """An exception that occurs when a connection is lost before the peer closed it cleanly."""

class TCPTimeoutError(TCPError):
    """An exception that occurs when an operation does not complete within the allowed time."""

class TCPBusyError(TCPError):
    """An exception that occurs when a connection is used concurrently by more than one coroutine."""

class TCPLimitError(TCPError):
    """An exception that occurs when a configured limit is exceeded."""
