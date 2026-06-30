import struct
import random
import asyncio
from enum import Enum, IntFlag
from typing import Optional, Union, Final, Annotated, Callable
from pydantic import Field
from dataclasses import dataclass

from ..ip.models import IPVersion, IPProtocolNumber
from ..ip.helpers import address_to_bytes

TCP_SEGMENT_STRUCT = struct.Struct("!HHIIHHHH")

TCP_HEADER_LEN: Final[int] = 20

MSS = 1460

DEFAULT_RTO = 1.0
MIN_RTO = 1.0
MAX_RTO = 60.0
RTO_ALPHA = 1.0 / 8.0
RTO_BETA = 1.0 / 4.0

TCPPort = Annotated[int, Field(ge=0, le=65535)]

class TCPState(Enum):
    SYN_SENT     = "SYN-SENT"
    SYN_RECEIVED = "SYN-RECEIVED"
    ESTABLISHED  = "ESTABLISHED"
    FIN_WAIT_1   = "FIN-WAIT-1"
    FIN_WAIT_2   = "FIN-WAIT-2"
    CLOSE_WAIT   = "CLOSE-WAIT"
    LAST_ACK     = "LAST-ACK"
    TIME_WAIT    = "TIME-WAIT"
    CLOSED       = "CLOSED"

class TCPFlag(IntFlag):
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20

@dataclass
class TCPSegment:
    src_port: TCPPort
    dst_port: TCPPort
    seq: int
    ack: Optional[int]
    flags: TCPFlag
    window: int
    payload: bytes = b""
    checksum: Optional[int] = None
    urgent: int = 0
    options: bytes = b""

    @staticmethod
    def build_mss_option(mss: int = 1460) -> bytes:
        return struct.pack("!BBH", 2, 4, mss)

    @staticmethod
    def build_window_scale_option(scale: int = 7) -> bytes:
        return struct.pack("!BBB", 3, 3, scale)

    @staticmethod
    def build_sack_permitted_option() -> bytes:
        return struct.pack("!BB", 4, 2)

    @staticmethod
    def build_syn_options() -> bytes:
        options = b""
        options += TCPSegment.build_mss_option(1460)
        options += TCPSegment.build_sack_permitted_option()
        options += TCPSegment.build_window_scale_option(7)

        while len(options) % 4 != 0:
            options += b"\x01"

        return options

    @staticmethod
    def calc_checksum(src_addr: bytes, dst_addr: bytes, segment: bytes, ip_version: IPVersion) -> int:
        pseudo = src_addr + dst_addr

        if ip_version == IPVersion.IPv4:
            pseudo += struct.pack("!BBH", 0, IPProtocolNumber.TCP, len(segment))
        elif ip_version == IPVersion.IPv6:
            ...

        data = pseudo + segment

        if len(data) % 2:
            data += b"\x00"

        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word

        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        result = (~checksum) & 0xFFFF
        return result

    def build(self, src_addr: Union[str, bytes], dst_addr: Union[str, bytes]) -> bytes:
        padded_options = self.options
        while len(padded_options) % 4 != 0:
            padded_options += b"\x00"

        total_header_len = 20 + len(padded_options)

        offset = total_header_len // 4
        offset_and_reserved = offset << 12
        offset_reserved_flags = offset_and_reserved | int(self.flags)

        segment_without_checksum = (
            TCP_SEGMENT_STRUCT.pack(
                self.src_port & 0xFFFF,
                self.dst_port & 0xFFFF,
                self.seq & 0xFFFFFFFF,
                self.ack & 0xFFFFFFFF,
                offset_reserved_flags & 0xFFFF,
                self.window & 0xFFFF,
                0,
                self.urgent & 0xFFFF
            )
            + padded_options
            + self.payload
        )
        self.checksum = TCPSegment.calc_checksum(address_to_bytes(src_addr), address_to_bytes(dst_addr), segment_without_checksum)

        return (
            TCP_SEGMENT_STRUCT.pack(
                self.src_port & 0xFFFF,
                self.dst_port & 0xFFFF,
                self.seq & 0xFFFFFFFF,
                self.ack & 0xFFFFFFFF,
                offset_reserved_flags & 0xFFFF,
                self.window & 0xFFFF,
                self.checksum,
                self.urgent & 0xFFFF
            )
            + padded_options
            + self.payload
        )

    @classmethod
    def parse(cls, data: bytes, src_addr: Union[str, bytes], dst_addr: Union[str, bytes], validate_checksum: bool = True) -> "TCPSegment":
        if len(data) < TCP_HEADER_LEN:
            raise ValueError("TCP segment too short")

        unpacked = TCP_SEGMENT_STRUCT.unpack_from(data)
        (
            src_port,
            dst_port,
            seq,
            ack,
            offset_res_flags,
            window,
            checksum,
            urgent
        ) = unpacked

        header_len = ((offset_res_flags >> 12) & 0xF) * 4
        flags = TCPFlag(offset_res_flags & 0x3F)
        payload = data[header_len:]

        if validate_checksum:
            calc = TCPSegment.calc_checksum(address_to_bytes(src_addr), address_to_bytes(dst_addr), data)
            if calc != 0:
                raise ValueError("Bad TCP checksum")

        return cls(
            src_port=src_port,
            dst_port=dst_port,
            seq=seq,
            ack=ack,
            flags=flags,
            window=window,
            payload=payload,
            checksum=checksum,
            urgent=urgent
        )

@dataclass
class TCPRetransmitEntry:
    seq: int
    segment: TCPSegment
    send_time: float
    timer_handle: Optional[asyncio.Handle] = None
    retransmit_count: int = 0

class TCPConnection:
    def __init__(self, dst: tuple[str, TCPPort], src: tuple[str, TCPPort], *, state: TCPState = TCPState.CLOSED, smoothed_rtt: Optional[float] = None, rtt_variance: Optional[float] = None, retransmission_timeout: float = DEFAULT_RTO, cwnd: int = MSS, ssthresh: int = 65535):
        self.dst = dst
        self.src = src or random.randint(20000, 60000)
        self.state = state

        self.seq = random.randint(0, 0xFFFF_FFFF)
        self.ack = 0

        self.smoothed_rtt = smoothed_rtt
        self.rtt_variance = rtt_variance
        self.retransmission_timeout = retransmission_timeout

        self.retransmit_queue: list[TCPRetransmitEntry] = []

        self.receive_buffer = bytearray()
        self.receive_queue = asyncio.Queue()
        self.advertised_window = 29200
        self.peer_window = 65535

        self.last_ack_sent = 0
        self.last_ack_received = 0

        self.duplicate_ack_count: int = 0

        self.close_initiated: bool = False
        self.time_wait_timer: Optional[asyncio.Handle] = None
        self.on_closed_callback: Optional[Callable] = None

        self.time_wait_timeout = 5.0

        self.cwnd = cwnd
        self.ssthresh = ssthresh

        self.fast_recovery: bool = False

    async def connect(self):
        ...

    async def close(self, half_close: bool = False):
        ...

    async def send(self, data: bytes):
        ...

    async def send_ack(self):
        ...

    async def send_segment(self, segment: TCPSegment, immediate: bool = False):
        ...

    async def retransmit(self, entry: TCPRetransmitEntry, fast: bool = False):
        ...

    async def receive(self, n: int = -1) -> bytes:
        buffer = await self.receive_queue.get()
        return buffer if n == -1 else buffer[:n]

    def on_segment(self, segment: TCPSegment):
        ...

    def free(self) -> None:
        for entry in self.retransmit_queue:
            if entry.timer_handle:
                entry.timer_handle.cancel()

        if self.time_wait_timer:
            self.time_wait_timer.cancel()
            self.time_wait_timer = None

        self.retransmit_queue.clear()
        self.receive_buffer.clear()

class TCPHandler:
    def __init__(self, on_connection: Optional[Callable] = None, on_close: Optional[Callable] = None):
        self.on_connection = on_connection  # (connection: TCPConnection) -> None
        self.on_close = on_close            # (connection: TCPConnection) -> None

class TCPProtocol(asyncio.Protocol):
    def __init__(self, src: Optional[tuple[str, TCPPort]] = None, handler: Optional[TCPHandler] = None, *, validate_checksum: bool = True):
        self.src = src
        self.handler = handler
        self.validate_checksum = validate_checksum
        self.transport = None
        self.connections: dict[tuple[str, TCPPort], TCPConnection] = {}
    ...
