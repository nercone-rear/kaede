from typing import Optional, Union, Callable, Tuple, TYPE_CHECKING

from ...tcp import TCPConnection
from ...udp import UDPConnection
from ...quic import QUICConnection
from ..models import HTTPVersion, HTTPPort, HTTPMessage
from ..api.common import HTTPLimits
from .common import HTTPState

if TYPE_CHECKING:
    from ..api.server import HTTPHandler, HTTPServer

class HTTPConnection:
    def __init__(self, src: Tuple[str, HTTPPort], dst: Tuple[str, HTTPPort], *, transport: Union[TCPConnection, UDPConnection, QUICConnection], state: Optional[HTTPState] = None, version: Optional[HTTPVersion] = None, limits: Optional[HTTPLimits] = None, observer: Optional[Callable[[HTTPMessage], None]] = None):
        self.src = src
        self.dst = dst

        self.transport = transport

        self.state = state or HTTPState.CONNECTION_STARTED
        self.version = version
        self.limits = limits or HTTPLimits()
        self.observer = observer

    def observe(self, message: HTTPMessage):
        if self.observer is not None:
            self.observer(message)

    async def send(self, value: Union[bytes, HTTPMessage], *, final: bool = True):
        if isinstance(value, bytes):
            await self.send_raw(value, final=final)
        elif isinstance(value, HTTPMessage):
            await self.send_message(value, final=final)

    async def send_raw(self, data: bytes, *, final: bool = True):
        raise NotImplementedError()

    async def send_message(self, message: HTTPMessage, *, final: bool = True):
        raise NotImplementedError()

    async def receive(self, n: int = -1, *, raw: bool = False) -> Optional[Union[bytes, HTTPMessage]]:
        if raw:
            return await self.receive_raw(n)

        return await self.receive_message()

    async def receive_raw(self, n: int = -1) -> Optional[bytes]:
        raise NotImplementedError()

    async def receive_message(self) -> Optional[HTTPMessage]:
        raise NotImplementedError()

    async def accept(self):
        raise NotImplementedError()

    async def reject(self):
        raise NotImplementedError()

    async def close(self, *, half_close: bool = False, send_pending: bool = False):
        raise NotImplementedError()

    async def reset(self):
        raise NotImplementedError()

    async def wait(self, value: HTTPState):
        raise NotImplementedError()

class HTTPProtocol:
    async def start(self):
        return

    async def run(self, handler: "HTTPHandler", server: "HTTPServer"):
        raise NotImplementedError()

    async def request(self, message: HTTPMessage) -> HTTPConnection:
        raise NotImplementedError()

    async def shutdown(self):
        raise NotImplementedError()
