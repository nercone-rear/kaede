import struct
import asyncio
from typing import Optional, Final, Union, Annotated, Callable
from pydantic import Field
from dataclasses import dataclass

from ..ip.models import IPProtocolNumber
from ..ip.helpers import address_to_bytes

UDP_SEGMENT_STRUCT: Final[struct.Struct] = struct.Struct("!HHHH")

UDP_HEADER_LEN: Final[int] = 8

UDPPort = Annotated[int, Field(ge=0, le=65535)]

@dataclass
class UDPSegment:
    src_port: UDPPort
    dst_port: UDPPort
    payload: bytes = b""
    checksum: Optional[int] = None
    length: Optional[int] = None

    @staticmethod
    def calc_checksum(pseudo_header: bytes, segment: bytes) -> int:
        if len(pseudo_header) != 12:
            raise ValueError("Pseudo header must be 12 bytes")

        total = pseudo_header + segment
        if len(total) & 1:
            total += b"\x00"

        s = sum(struct.unpack(f"!{len(total) // 2}H", total))
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)

        return (~s) & 0xFFFF

    def build(self, src_addr: Union[str, bytes], dst_addr: Union[str, bytes]) -> bytes:
        data_len = UDP_HEADER_LEN + len(self.payload)
        if data_len > 0xFFFF:
            raise ValueError("UDP length exceeds 65535")

        pseudo_header = address_to_bytes(src_addr) + address_to_bytes(dst_addr) + struct.pack("!BBH", 0, IPProtocolNumber.UDP, data_len)

        segment_wo_cs = (
            UDP_SEGMENT_STRUCT.pack(
                self.src_port & 0xFFFF,
                self.dst_port & 0xFFFF,
                data_len,
                0
            )
            + self.payload
        )

        self.length = data_len

        self.checksum = UDPSegment.calc_checksum(pseudo_header, segment_wo_cs)
        if self.checksum == 0:
            self.checksum = 0xFFFF

        return (
            UDP_SEGMENT_STRUCT.pack(
                self.src_port & 0xFFFF,
                self.dst_port & 0xFFFF,
                data_len,
                self.checksum
            )
            + self.payload
        )

    @classmethod
    def parse(cls, data: bytes, src_ip: Union[str, bytes], dst_ip: Union[str, bytes], validate_checksum: bool = True) -> "UDPSegment":
        if len(data) < UDP_HEADER_LEN:
            raise ValueError("UDP segment too short")

        src_port, dst_port, length, checksum = UDP_SEGMENT_STRUCT.unpack_from(data, 0)
        if len(data) < length:
            raise ValueError("UDP segment truncated")

        payload = data[UDP_HEADER_LEN:length]

        if validate_checksum:
            pseudo_header = address_to_bytes(src_ip) + address_to_bytes(dst_ip) + struct.pack("!BBH", 0, IPProtocolNumber.UDP, length)
            if UDPSegment.calc_checksum(pseudo_header, data[:length]) != 0:
                raise ValueError("Bad UDP checksum")

        return cls(
            src_port=src_port,
            dst_port=dst_port,
            payload=payload,
            checksum=checksum,
            length=length
        )

class UDPConnection:
    def __init__(self, src: tuple[str, UDPPort], dst: tuple[str, UDPPort], *, protocol: Optional["UDPProtocol"] = None):
        self.src = src
        self.dst = dst
        self.protocol = protocol
        self.receive_queue: asyncio.Queue = asyncio.Queue()

    async def send(self, data: bytes):
        ...

    async def receive(self, n: int = -1) -> bytes:
        ...

class UDPHandler:
    def __init__(self, on_connection: Optional[Callable] = None):
        self.on_connection = on_connection  # (connection: UDPConnection) -> None

class UDPProtocol:
    def __init__(self, src: Optional[tuple[str, UDPPort]] = None, handler: Optional[UDPHandler] = None, *, validate_checksum: bool = True):
        self.src = src
        self.handler = handler
        self.validate_checksum = validate_checksum
        self.transport = None
        self.connections: dict[tuple[str, UDPPort], UDPConnection] = {}
    ...
