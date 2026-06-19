from __future__ import annotations

import socket
from typing import Literal, Awaitable, TYPE_CHECKING
from dataclasses import dataclass

if TYPE_CHECKING:
    from ..http import Request, Response
    from ..websocket import WebSocket

@dataclass
class Listener:
    sock: socket.socket
    kind: Literal["http", "https", "quic", "unix"]

class Callback:
    def __init__(self):
        self.websocket_subprotocols: list[str] = []

    async def on_request(self, request: Request) -> Response | Awaitable[Response]:
        return Response("Hello, World! This is the Response from the default Kaede Callback.".encode(), content_type="text/plain")

    async def on_websocket(self, request: Request, ws: WebSocket):
        await ws.close(1008, "WebSocket not configured")
