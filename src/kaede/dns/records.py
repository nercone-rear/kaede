import ipaddress
from dataclasses import dataclass

from .models import DNSRecordData

@dataclass(frozen=True)
class RawRecordData(DNSRecordData):
    raw: bytes
    rtype_unknown: int

    def pack(self) -> bytes:
        return self.raw

    @classmethod
    def unpack(cls, raw, message, offset, rtype_unknown=0):
        return cls(raw=raw, rtype_unknown=rtype_unknown)

@dataclass(frozen=True)
class ARecordData(DNSRecordData):
    address: ipaddress.IPv4Address

    def pack(self) -> bytes:
        return self.address.packed

    @classmethod
    def unpack(cls, raw, message, offset):
        return cls(address=ipaddress.IPv4Address(raw))

@dataclass(frozen=True)
class AAAARecordData(DNSRecordData):
    address: ipaddress.IPv6Address

    def pack(self) -> bytes:
        return self.address.packed

    @classmethod
    def unpack(cls, raw, message, offset):
        return cls(address=ipaddress.IPv6Address(raw))

@dataclass(frozen=True)
class MXRecordData(DNSRecordData):
    preference: int
    exchange: str
