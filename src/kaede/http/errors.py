class HTTPVersionNotSupportedError(ValueError):
    pass

class HTTPMethodNotImplementedError(ValueError):
    pass

class StructuredFieldError(ValueError):
    pass

class QpackError(Exception):
    pass

class QpackBlocked(QpackError):
    pass
