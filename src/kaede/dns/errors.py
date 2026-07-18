class DNSError(Exception):
    """Generic exception for DNS processing"""

class DNSFormatError(DNSError):
    """An exception that occurs when a DNS message cannot be parsed or built."""

class DNSNameError(DNSFormatError):
    """An exception that occurs when a domain name violates the DNS length or label limits."""

class DNSConnectionError(DNSError):
    """An exception that occurs when a DNS transport cannot be established."""

class DNSClosedError(DNSError):
    """An exception that occurs when an operation is attempted on a transport that is already closed."""

class DNSTimeoutError(DNSError):
    """An exception that occurs when no acceptable response arrives within the allowed time."""

class DNSServerError(DNSError):
    """An exception that occurs when a server answers with an error response code."""

    def __init__(self, message: str, rcode=None):
        super().__init__(message)
        self.rcode = rcode

class DNSSECError(DNSError):
    """An exception that occurs when DNSSEC material cannot be validated."""
