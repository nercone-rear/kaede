class UDPError(Exception):
    """Generic exception for UDP processing"""

class UDPConnectionError(UDPError):
    """An exception that occurs when an endpoint cannot be established."""

class UDPClosedError(UDPError):
    """An exception that occurs when an operation is attempted on a connection that is already closed."""

class UDPLostError(UDPError):
    """An exception that occurs when the endpoint reports a failure, such as an ICMP port unreachable."""

class UDPTimeoutError(UDPError):
    """An exception that occurs when an operation does not complete within the allowed time."""

class UDPBusyError(UDPError):
    """An exception that occurs when a connection is used concurrently by more than one coroutine."""

class UDPLimitError(UDPError):
    """An exception that occurs when a configured limit is exceeded."""
