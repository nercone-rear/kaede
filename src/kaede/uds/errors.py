class UDSError(Exception):
    """Generic exception for UDS processing"""

class UDSConnectionError(UDSError):
    """An exception that occurs when a connection cannot be established."""

class UDSClosedError(UDSError):
    """An exception that occurs when an operation is attempted on a connection that is already closed."""

class UDSLostError(UDSError):
    """An exception that occurs when a connection is lost before the peer closed it cleanly."""

class UDSTimeoutError(UDSError):
    """An exception that occurs when an operation does not complete within the allowed time."""

class UDSBusyError(UDSError):
    """An exception that occurs when a connection is used concurrently by more than one coroutine."""

class UDSLimitError(UDSError):
    """An exception that occurs when a configured limit is exceeded."""
