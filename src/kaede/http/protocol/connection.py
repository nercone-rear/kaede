from enum import Enum
from typing import Optional, Union, Tuple

from ...tcp import TCPConnection
from ...udp import UDPConnection
from ...quic import QUICConnection
from ..models import HTTPVersion, HTTPPort, HTTPLimits, HTTPMessage

class HTTPState(Enum):
    CONNECTION_STARTED = "Connection Started"
    CONNECTION_ENDED   = "Connection Ended"

    SENT           = "Sent"
    SENT_STARTLINE = "Sent Start line"
    SENT_HEADERS   = "Sent Headers"
    SENT_BODY      = "Sent Body"
    SENT_TRAILERS  = "Sent Trailers"

    RECEIVED           = "Received"
    RECEIVED_STARTLINE = "Received Start line"
    RECEIVED_HEADERS   = "Received Headers"
    RECEIVED_BODY      = "Received Body"
    RECEIVED_TRAILERS  = "Received Trailers"

class HTTPConnection:
    def __init__(self, src: Tuple[str, HTTPPort], dst: Tuple[str, HTTPPort], *, transport: Union[TCPConnection, UDPConnection, QUICConnection], state: Optional[HTTPState] = None, version: Optional[HTTPVersion] = None, limits: Optional[HTTPLimits] = None):
        self.src = src
        self.dst = dst

        self.transport = transport

        self.state = state or HTTPState.CONNECTION_STARTED
        self.version = version
        self.limits = limits or HTTPLimits()

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
