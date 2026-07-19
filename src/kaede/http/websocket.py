import os
import struct
import asyncio
import hashlib
from base64 import b64encode
from typing import Optional, Union, Tuple

from ..tcp.errors import TCPError, TCPClosedError, TCPLostError
from ..uds.errors import UDSError, UDSClosedError, UDSLostError
from ..tls.errors import TLSError
from .errors import WebSocketError

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

class Opcode:
    CONTINUATION = 0x0
    TEXT         = 0x1
    BINARY       = 0x2
    CLOSE        = 0x8
    PING         = 0x9
    PONG         = 0xA

class Close:
    NORMAL   = 1000
    PROTOCOL = 1002
    INVALID  = 1007
    ABSENT   = 1005
    ABNORMAL = 1006
    TLS      = 1015

    UNSPEAKABLE = frozenset({1004, ABSENT, ABNORMAL, TLS})

    @staticmethod
    def sendable(code: int) -> bool:
        return code not in Close.UNSPEAKABLE and (1000 <= code <= 1011 or 3000 <= code <= 4999)

    @staticmethod
    def receivable(code: int) -> bool:
        return code not in Close.UNSPEAKABLE and (1000 <= code <= 1014 or 3000 <= code <= 4999)

    @staticmethod
    def clip(reason: str, room: int = 123) -> bytes:
        raw = reason.encode()[:room]

        while raw:
            try:
                raw.decode()
                break

            except UnicodeDecodeError:
                raw = raw[:-1]

        return raw

class WSFrame:
    @staticmethod
    def accept(key: str) -> str:
        return b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()

    @staticmethod
    def build(opcode: int, payload: bytes, *, fin: bool = True, mask: bool = False) -> bytes:
        first = (0x80 if fin else 0) | opcode
        length = len(payload)

        if length < 126:
            header = bytes([first, (0x80 if mask else 0) | length])
        elif length < 65536:
            header = bytes([first, (0x80 if mask else 0) | 126]) + struct.pack(">H", length)
        else:
            header = bytes([first, (0x80 if mask else 0) | 127]) + struct.pack(">Q", length)

        if not mask:
            return header + payload

        key = os.urandom(4)
        masked = bytes(byte ^ key[index % 4] for index, byte in enumerate(payload))

        return header + key + masked

    @staticmethod
    async def read(transport, *, limit: int) -> Tuple[bool, int, bytes]:
        head = await transport.receive_exactly(2)

        fin = bool(head[0] & 0x80)
        reserved = head[0] & 0x70
        opcode = head[0] & 0x0F
        masked = bool(head[1] & 0x80)
        length = head[1] & 0x7F

        if reserved:
            raise WebSocketError(1002, "A reserved bit is set.")

        if length == 126:
            length = struct.unpack(">H", await transport.receive_exactly(2))[0]

            if length < 126:
                raise WebSocketError(Close.PROTOCOL, "A payload length is not minimally encoded.")

        elif length == 127:
            length = struct.unpack(">Q", await transport.receive_exactly(8))[0]

            if length < 65536:
                raise WebSocketError(Close.PROTOCOL, "A payload length is not minimally encoded.")

            if length > 0x7FFFFFFFFFFFFFFF:
                raise WebSocketError(Close.PROTOCOL, "A payload length has its most significant bit set.")

        if opcode >= 0x8:
            if length > 125:
                raise WebSocketError(1002, "A control frame is longer than 125 bytes.")

            if not fin:
                raise WebSocketError(1002, "A control frame is fragmented.")

        if length > limit:
            raise WebSocketError(1009, f"A frame of {length} bytes is over the {limit} byte limit.")

        key = await transport.receive_exactly(4) if masked else b""
        payload = await transport.receive_exactly(length) if length else b""

        if masked:
            payload = bytes(byte ^ key[index % 4] for index, byte in enumerate(payload))

        return (fin, opcode, payload, masked)

class WSConnection:
    def __init__(self, src: Tuple[str, "object"], dst: Tuple[str, "object"], *, transport, server: bool = False, subprotocol: Optional[str] = None, limit: int = 16 * 1024 * 1024):
        self.src = src
        self.dst = dst

        self.transport = transport
        self.server = server
        self.subprotocol = subprotocol
        self.limit = limit

        self.closed = False
        self.close_sent = False
        self.close_received = False

    CLOSED = (TCPClosedError, TCPLostError, UDSClosedError, UDSLostError)

    async def violate(self, code: int, message: str):
        await self.close(code, message, linger=False)

        raise WebSocketError(code, message)

    async def read(self, size: int = -1) -> Optional[Union[str, bytes]]:
        fragments = bytearray()
        first: Optional[int] = None

        while True:
            try:
                fin, opcode, payload, masked = await WSFrame.read(self.transport, limit=self.limit)

            except WebSocketError as e:
                await self.close(e.code, str(e))
                raise

            except (TCPError, UDSError, TLSError):
                self.closed = True
                return None

            if self.server and not masked:
                await self.violate(Close.PROTOCOL, "A client frame was not masked.")

            if not self.server and masked:
                await self.violate(Close.PROTOCOL, "A server frame was masked.")

            if opcode == Opcode.PING:
                await self.emit(Opcode.PONG, payload)
                continue

            if opcode == Opcode.PONG:
                continue

            if opcode == Opcode.CLOSE:
                await self.acknowledge(payload)
                return None

            if opcode in (Opcode.TEXT, Opcode.BINARY):
                if first is not None:
                    await self.violate(Close.PROTOCOL, "A new data frame arrived mid-message.")

                first = opcode

            elif opcode == Opcode.CONTINUATION:
                if first is None:
                    await self.violate(Close.PROTOCOL, "A continuation frame arrived with nothing to continue.")

            else:
                await self.violate(Close.PROTOCOL, f"The opcode {opcode:#x} is not defined.")

            fragments += payload

            if len(fragments) > self.limit:
                await self.violate(1009, "The reassembled message is over the limit.")

            if fin:
                if first == Opcode.TEXT:
                    try:
                        return fragments.decode()

                    except UnicodeDecodeError:
                        await self.violate(Close.INVALID, "The text message is not valid UTF-8.")

                return bytes(fragments)

    async def write(self, data: Union[str, bytes], *, binary: Optional[bool] = None):
        if isinstance(data, str):
            await self.emit(Opcode.TEXT, data.encode())
        else:
            await self.emit(Opcode.BINARY if binary is None else (Opcode.BINARY if binary else Opcode.TEXT), bytes(data))

    async def ping(self, payload: bytes = b""):
        await self.emit(Opcode.PING, payload)

    async def pong(self, payload: bytes = b""):
        await self.emit(Opcode.PONG, payload)

    async def emit(self, opcode: int, payload: bytes):
        if self.closed:
            raise WebSocketError(1006, "The WebSocket is already closed.")

        try:
            await self.transport.send(WSFrame.build(opcode, payload, mask=not self.server))

        except (TCPError, UDSError, TLSError) as e:
            self.closed = True
            raise WebSocketError(1006, f"The WebSocket transport failed: {e}")

    async def acknowledge(self, payload: bytes):
        self.close_received = True
        code = Close.NORMAL

        if len(payload) == 1:
            await self.violate(Close.PROTOCOL, "A close frame carries a one octet body.")

        if len(payload) >= 2:
            received = struct.unpack(">H", payload[:2])[0]

            try:
                payload[2:].decode()

            except UnicodeDecodeError:
                await self.violate(Close.INVALID, "The close reason is not valid UTF-8.")

            if not Close.receivable(received):
                await self.violate(Close.PROTOCOL, f"The close code {received} may not appear on the wire.")

            code = received

        if not self.close_sent:
            await self.close(code)

        self.closed = True

    async def close(self, code: int = Close.NORMAL, reason: str = "", *, linger: bool = True):
        if self.close_sent or self.closed:
            self.closed = True
            return

        self.close_sent = True

        if code and not Close.sendable(code):
            code = Close.NORMAL

        payload = struct.pack(">H", code) + Close.clip(reason) if code else b""

        try:
            await self.transport.send(WSFrame.build(Opcode.CLOSE, payload, mask=not self.server))

        except (TCPError, UDSError, TLSError):
            pass

        if linger and not self.close_received:
            await self.linger()

        try:
            await self.transport.close()

        except (TCPError, UDSError, TLSError):
            pass

        self.closed = True

    async def linger(self, timeout: float = 5.0):
        try:
            await asyncio.wait_for(self.settle(), timeout)

        except (asyncio.TimeoutError, WebSocketError, TCPError, UDSError, TLSError):
            pass

    async def settle(self):
        while True:
            _, opcode, _, _ = await WSFrame.read(self.transport, limit=self.limit)

            if opcode == Opcode.CLOSE:
                self.close_received = True
                return
