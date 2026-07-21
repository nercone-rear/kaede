import asyncio

from ...tcp.errors import TCPError, TCPClosedError, TCPLostError, TCPTimeoutError
from ...udp.errors import UDPError, UDPClosedError, UDPLostError, UDPTimeoutError
from ...quic.errors import QUICError, QUICClosedError, QUICLostError, QUICStreamError, QUICTimeoutError

TRANSPORT_CLOSED  = (TCPClosedError, TCPLostError, UDPClosedError, UDPLostError, QUICClosedError, QUICLostError, QUICStreamError)
TRANSPORT_TIMEOUT = (asyncio.TimeoutError, TCPTimeoutError, UDPTimeoutError, QUICTimeoutError)
TRANSPORT_ERRORS  = (TCPError, UDPError, QUICError)
