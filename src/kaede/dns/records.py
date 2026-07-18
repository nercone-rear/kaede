import base64
import ipaddress
from typing import Optional, Union, List, Dict, Tuple
from dataclasses import dataclass

from .errors import DNSFormatError
from .models import DNSName, DNSRecordType, DNSRecordData

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

    @classmethod
    def from_text(cls, tokens):
        return cls(address=ipaddress.IPv4Address(tokens[0]))

    @property
    def text(self) -> str:
        return str(self.address)

@dataclass(frozen=True)
class AAAARecordData(DNSRecordData):
    address: ipaddress.IPv6Address

    def pack(self) -> bytes:
        return self.address.packed

    @classmethod
    def unpack(cls, raw, message, offset):
        return cls(address=ipaddress.IPv6Address(raw))

    @classmethod
    def from_text(cls, tokens):
        return cls(address=ipaddress.IPv6Address(tokens[0]))

    @property
    def text(self) -> str:
        return str(self.address)

@dataclass(frozen=True)
class NameRecordData(DNSRecordData):
    target: str

    def pack(self) -> bytes:
        return DNSName.wire(self.target)

    @classmethod
    def unpack(cls, raw, message, offset):
        name, _ = DNSName.unpack(message, offset)
        return cls(target=name)

    @classmethod
    def from_text(cls, tokens):
        return cls(target=tokens[0])

    @property
    def text(self) -> str:
        return self.target

class NSRecordData(NameRecordData):
    ...

class CNAMERecordData(NameRecordData):
    ...

class PTRRecordData(NameRecordData):
    ...

class DNAMERecordData(NameRecordData):
    ...

@dataclass(frozen=True)
class SOARecordData(DNSRecordData):
    mname: str
    rname: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int

    def pack(self) -> bytes:
        wire = bytearray(DNSName.wire(self.mname))
        wire += DNSName.wire(self.rname)

        for value in (self.serial, self.refresh, self.retry, self.expire, self.minimum):
            wire += value.to_bytes(4, "big")

        return bytes(wire)

    @classmethod
    def unpack(cls, raw, message, offset):
        mname, offset = DNSName.unpack(message, offset)
        rname, offset = DNSName.unpack(message, offset)

        if offset + 20 > len(message):
            raise DNSFormatError("The SOA record ends in the middle of its counters.")

        fields = [int.from_bytes(message[offset + at:offset + at + 4], "big") for at in (0, 4, 8, 12, 16)]

        return cls(mname, rname, *fields)

    @classmethod
    def from_text(cls, tokens):
        return cls(tokens[0], tokens[1], *(int(value) for value in tokens[2:7]))

    @property
    def text(self) -> str:
        return f"{self.mname} {self.rname} {self.serial} {self.refresh} {self.retry} {self.expire} {self.minimum}"

@dataclass(frozen=True)
class MXRecordData(DNSRecordData):
    preference: int
    exchange: str

    def pack(self) -> bytes:
        return self.preference.to_bytes(2, "big") + DNSName.wire(self.exchange)

    @classmethod
    def unpack(cls, raw, message, offset):
        if len(raw) < 3:
            raise DNSFormatError(f"The MX record data is {len(raw)} bytes, which cannot carry a preference and a name.")

        name, _ = DNSName.unpack(message, offset + 2)

        return cls(preference=int.from_bytes(raw[0:2], "big"), exchange=name)

    @classmethod
    def from_text(cls, tokens):
        return cls(preference=int(tokens[0]), exchange=tokens[1])

    @property
    def text(self) -> str:
        return f"{self.preference} {self.exchange}"

@dataclass(frozen=True)
class TXTRecordData(DNSRecordData):
    strings: Tuple[bytes, ...]

    def pack(self) -> bytes:
        wire = bytearray()

        for string in self.strings:
            if len(string) > 255:
                raise DNSFormatError(f"A TXT string is {len(string)} bytes, but one carries at most 255.")

            wire.append(len(string))
            wire += string

        return bytes(wire)

    @classmethod
    def unpack(cls, raw, message, offset):
        strings: List[bytes] = []
        at = 0

        while at < len(raw):
            length = raw[at]

            if at + 1 + length > len(raw):
                raise DNSFormatError("The TXT record ends in the middle of a string.")

            strings.append(bytes(raw[at + 1:at + 1 + length]))
            at += 1 + length

        return cls(strings=tuple(strings))

    @classmethod
    def from_text(cls, tokens):
        return cls(strings=tuple(token.encode() for token in tokens))

    @property
    def text(self) -> str:
        return " ".join('"' + string.decode(errors="replace") + '"' for string in self.strings)

@dataclass(frozen=True)
class SRVRecordData(DNSRecordData):
    priority: int
    weight: int
    port: int
    target: str

    def pack(self) -> bytes:
        return self.priority.to_bytes(2, "big") + self.weight.to_bytes(2, "big") + self.port.to_bytes(2, "big") + DNSName.wire(self.target)

    @classmethod
    def unpack(cls, raw, message, offset):
        if len(raw) < 7:
            raise DNSFormatError(f"The SRV record data is {len(raw)} bytes, which cannot carry its fields.")

        name, _ = DNSName.unpack(message, offset + 6)

        return cls(
            priority=int.from_bytes(raw[0:2], "big"),
            weight=int.from_bytes(raw[2:4], "big"),
            port=int.from_bytes(raw[4:6], "big"),
            target=name
        )

    @classmethod
    def from_text(cls, tokens):
        return cls(priority=int(tokens[0]), weight=int(tokens[1]), port=int(tokens[2]), target=tokens[3])

    @property
    def text(self) -> str:
        return f"{self.priority} {self.weight} {self.port} {self.target}"

@dataclass(frozen=True)
class CAARecordData(DNSRecordData):
    flags: int
    tag: str
    value: bytes

    def pack(self) -> bytes:
        tag = self.tag.encode()

        if not 0 < len(tag) < 256:
            raise DNSFormatError(f"The CAA tag {self.tag!r} must be between 1 and 255 bytes.")

        return bytes([self.flags, len(tag)]) + tag + self.value

    @classmethod
    def unpack(cls, raw, message, offset):
        if len(raw) < 2 or 2 + raw[1] > len(raw):
            raise DNSFormatError("The CAA record ends in the middle of its tag.")

        return cls(flags=raw[0], tag=raw[2:2 + raw[1]].decode(errors="replace"), value=bytes(raw[2 + raw[1]:]))

    @classmethod
    def from_text(cls, tokens):
        return cls(flags=int(tokens[0]), tag=tokens[1], value=tokens[2].encode())

    @property
    def text(self) -> str:
        return f'{self.flags} {self.tag} "{self.value.decode(errors="replace")}"'

@dataclass(frozen=True)
class DSRecordData(DNSRecordData):
    key_tag: int
    algorithm: int
    digest_type: int
    digest: bytes

    def pack(self) -> bytes:
        return self.key_tag.to_bytes(2, "big") + bytes([self.algorithm, self.digest_type]) + self.digest

    @classmethod
    def unpack(cls, raw, message, offset):
        if len(raw) < 4:
            raise DNSFormatError(f"The DS record data is {len(raw)} bytes, which cannot carry its fields.")

        return cls(key_tag=int.from_bytes(raw[0:2], "big"), algorithm=raw[2], digest_type=raw[3], digest=bytes(raw[4:]))

    @classmethod
    def from_text(cls, tokens):
        return cls(key_tag=int(tokens[0]), algorithm=int(tokens[1]), digest_type=int(tokens[2]), digest=bytes.fromhex("".join(tokens[3:])))

    @property
    def text(self) -> str:
        return f"{self.key_tag} {self.algorithm} {self.digest_type} {self.digest.hex().upper()}"

class CDSRecordData(DSRecordData):
    ...

@dataclass(frozen=True)
class DNSKEYRecordData(DNSRecordData):
    flags: int
    protocol: int
    algorithm: int
    key: bytes

    ZONE_KEY = 0x0100
    SEP      = 0x0001

    def pack(self) -> bytes:
        return self.flags.to_bytes(2, "big") + bytes([self.protocol, self.algorithm]) + self.key

    @classmethod
    def unpack(cls, raw, message, offset):
        if len(raw) < 4:
            raise DNSFormatError(f"The DNSKEY record data is {len(raw)} bytes, which cannot carry its fields.")

        return cls(flags=int.from_bytes(raw[0:2], "big"), protocol=raw[2], algorithm=raw[3], key=bytes(raw[4:]))

    @classmethod
    def from_text(cls, tokens):
        return cls(flags=int(tokens[0]), protocol=int(tokens[1]), algorithm=int(tokens[2]), key=base64.b64decode("".join(tokens[3:])))

    @property
    def text(self) -> str:
        return f"{self.flags} {self.protocol} {self.algorithm} {base64.b64encode(self.key).decode()}"

class CDNSKEYRecordData(DNSKEYRecordData):
    ...

@dataclass(frozen=True)
class RRSIGRecordData(DNSRecordData):
    type_covered: Union[DNSRecordType, int]
    algorithm: int
    labels: int
    original_ttl: int
    expiration: int
    inception: int
    key_tag: int
    signer: str
    signature: bytes

    def pack(self) -> bytes:
        from .models import DNSMessage

        wire = bytearray()
        wire += DNSMessage.code(self.type_covered).to_bytes(2, "big")
        wire += bytes([self.algorithm, self.labels])
        wire += self.original_ttl.to_bytes(4, "big")
        wire += self.expiration.to_bytes(4, "big")
        wire += self.inception.to_bytes(4, "big")
        wire += self.key_tag.to_bytes(2, "big")
        wire += DNSName.wire(self.signer)
        wire += self.signature

        return bytes(wire)

    @classmethod
    def unpack(cls, raw, message, offset):
        if len(raw) < 19:
            raise DNSFormatError(f"The RRSIG record data is {len(raw)} bytes, which cannot carry its fields.")

        signer, following = DNSName.unpack(message, offset + 18)

        return cls(
            type_covered=DNSRecordType.of(int.from_bytes(raw[0:2], "big")),
            algorithm=raw[2],
            labels=raw[3],
            original_ttl=int.from_bytes(raw[4:8], "big"),
            expiration=int.from_bytes(raw[8:12], "big"),
            inception=int.from_bytes(raw[12:16], "big"),
            key_tag=int.from_bytes(raw[16:18], "big"),
            signer=signer,
            signature=bytes(message[following:offset + len(raw)])
        )

class Bitmap:
    @staticmethod
    def pack(types: Tuple[Union[DNSRecordType, int], ...]) -> bytes:
        from .models import DNSMessage

        windows: Dict[int, bytearray] = {}

        for rtype in types:
            code = DNSMessage.code(rtype)
            window, bit = code >> 8, code & 0xFF
            block = windows.setdefault(window, bytearray(32))
            block[bit >> 3] |= 0x80 >> (bit & 7)

        wire = bytearray()

        for window in sorted(windows):
            block = windows[window]

            while block and not block[-1]:
                block.pop()

            wire += bytes([window, len(block)]) + block

        return bytes(wire)

    @staticmethod
    def unpack(raw: bytes) -> Tuple[Union[DNSRecordType, int], ...]:
        types: List[Union[DNSRecordType, int]] = []
        at = 0

        while at < len(raw):
            if at + 2 > len(raw) or raw[at + 1] < 1 or raw[at + 1] > 32 or at + 2 + raw[at + 1] > len(raw):
                raise DNSFormatError("The type bitmap ends in the middle of a window block.")

            window = raw[at]

            for index, value in enumerate(raw[at + 2:at + 2 + raw[at + 1]]):
                for bit in range(8):
                    if value & (0x80 >> bit):
                        types.append(DNSRecordType.of((window << 8) | (index << 3) | bit))

            at += 2 + raw[at + 1]

        return tuple(types)

@dataclass(frozen=True)
class NSECRecordData(DNSRecordData):
    next_domain: str
    types: Tuple[Union[DNSRecordType, int], ...] = ()

    def pack(self) -> bytes:
        return DNSName.wire(self.next_domain) + Bitmap.pack(self.types)

    @classmethod
    def unpack(cls, raw, message, offset):
        name, following = DNSName.unpack(message, offset)

        return cls(next_domain=name, types=Bitmap.unpack(message[following:offset + len(raw)]))

@dataclass(frozen=True)
class NSEC3RecordData(DNSRecordData):
    algorithm: int
    flags: int
    iterations: int
    salt: bytes
    next_hashed: bytes
    types: Tuple[Union[DNSRecordType, int], ...] = ()

    def pack(self) -> bytes:
        wire = bytearray([self.algorithm, self.flags])
        wire += self.iterations.to_bytes(2, "big")
        wire += bytes([len(self.salt)]) + self.salt
        wire += bytes([len(self.next_hashed)]) + self.next_hashed
        wire += Bitmap.pack(self.types)

        return bytes(wire)

    @classmethod
    def unpack(cls, raw, message, offset):
        if len(raw) < 5 or 5 + raw[4] + 1 > len(raw):
            raise DNSFormatError("The NSEC3 record ends in the middle of its salt.")

        cut = 5 + raw[4]

        if cut + 1 + raw[cut] > len(raw):
            raise DNSFormatError("The NSEC3 record ends in the middle of its next hashed owner.")

        return cls(
            algorithm=raw[0],
            flags=raw[1],
            iterations=int.from_bytes(raw[2:4], "big"),
            salt=bytes(raw[5:cut]),
            next_hashed=bytes(raw[cut + 1:cut + 1 + raw[cut]]),
            types=Bitmap.unpack(raw[cut + 1 + raw[cut]:])
        )

@dataclass(frozen=True)
class NSEC3PARAMRecordData(DNSRecordData):
    algorithm: int
    flags: int
    iterations: int
    salt: bytes

    def pack(self) -> bytes:
        return bytes([self.algorithm, self.flags]) + self.iterations.to_bytes(2, "big") + bytes([len(self.salt)]) + self.salt

    @classmethod
    def unpack(cls, raw, message, offset):
        if len(raw) < 5 or 5 + raw[4] > len(raw):
            raise DNSFormatError("The NSEC3PARAM record ends in the middle of its salt.")

        return cls(algorithm=raw[0], flags=raw[1], iterations=int.from_bytes(raw[2:4], "big"), salt=bytes(raw[5:5 + raw[4]]))

@dataclass(frozen=True)
class TLSARecordData(DNSRecordData):
    usage: int
    selector: int
    matching_type: int
    data: bytes

    def pack(self) -> bytes:
        return bytes([self.usage, self.selector, self.matching_type]) + self.data

    @classmethod
    def unpack(cls, raw, message, offset):
        if len(raw) < 3:
            raise DNSFormatError(f"The TLSA record data is {len(raw)} bytes, which cannot carry its fields.")

        return cls(usage=raw[0], selector=raw[1], matching_type=raw[2], data=bytes(raw[3:]))

    @classmethod
    def from_text(cls, tokens):
        return cls(usage=int(tokens[0]), selector=int(tokens[1]), matching_type=int(tokens[2]), data=bytes.fromhex("".join(tokens[3:])))

    @property
    def text(self) -> str:
        return f"{self.usage} {self.selector} {self.matching_type} {self.data.hex().upper()}"

class SMIMEARecordData(TLSARecordData):
    ...

@dataclass(frozen=True)
class SVCBRecordData(DNSRecordData):
    priority: int
    target: str
    params: Tuple[Tuple[int, bytes], ...] = ()

    MANDATORY       = 0
    ALPN            = 1
    NO_DEFAULT_ALPN = 2
    PORT            = 3
    IPV4HINT        = 4
    ECH             = 5
    IPV6HINT        = 6

    def value(self, key: int) -> Optional[bytes]:
        for code, raw in self.params:
            if code == key:
                return raw

    @property
    def alpn(self) -> List[str]:
        raw = self.value(SVCBRecordData.ALPN)

        if raw is None:
            return []

        names: List[str] = []
        at = 0

        while at < len(raw):
            length = raw[at]

            if length == 0 or at + 1 + length > len(raw):
                raise DNSFormatError("The alpn SvcParam ends in the middle of a protocol name.")

            names.append(raw[at + 1:at + 1 + length].decode(errors="replace"))
            at += 1 + length

        return names

    @property
    def port(self) -> Optional[int]:
        raw = self.value(SVCBRecordData.PORT)

        if raw is None:
            return None

        if len(raw) != 2:
            raise DNSFormatError(f"The port SvcParam is {len(raw)} bytes rather than 2.")

        return int.from_bytes(raw, "big")

    @property
    def ipv4hints(self) -> List[ipaddress.IPv4Address]:
        raw = self.value(SVCBRecordData.IPV4HINT) or b""

        if len(raw) % 4:
            raise DNSFormatError(f"The ipv4hint SvcParam is {len(raw)} bytes, which is not a whole number of addresses.")

        return [ipaddress.IPv4Address(raw[at:at + 4]) for at in range(0, len(raw), 4)]

    @property
    def ipv6hints(self) -> List[ipaddress.IPv6Address]:
        raw = self.value(SVCBRecordData.IPV6HINT) or b""

        if len(raw) % 16:
            raise DNSFormatError(f"The ipv6hint SvcParam is {len(raw)} bytes, which is not a whole number of addresses.")

        return [ipaddress.IPv6Address(raw[at:at + 16]) for at in range(0, len(raw), 16)]

    @property
    def ech(self) -> Optional[bytes]:
        return self.value(SVCBRecordData.ECH)

    def pack(self) -> bytes:
        wire = bytearray(self.priority.to_bytes(2, "big"))
        wire += DNSName.wire(self.target)

        for code, raw in sorted(self.params):
            wire += code.to_bytes(2, "big")
            wire += len(raw).to_bytes(2, "big")
            wire += raw

        return bytes(wire)

    @classmethod
    def unpack(cls, raw, message, offset):
        if len(raw) < 3:
            raise DNSFormatError(f"The SVCB record data is {len(raw)} bytes, which cannot carry its fields.")

        target, following = DNSName.unpack(message, offset + 2)
        params: List[Tuple[int, bytes]] = []
        at = following - offset

        while at < len(raw):
            if at + 4 > len(raw):
                raise DNSFormatError("The SVCB record ends in the middle of a SvcParam header.")

            code = int.from_bytes(raw[at:at + 2], "big")
            length = int.from_bytes(raw[at + 2:at + 4], "big")
            at += 4

            if at + length > len(raw):
                raise DNSFormatError("The SVCB record ends in the middle of a SvcParam value.")

            if params and code <= params[-1][0]:
                raise DNSFormatError("The SvcParam keys are not in strictly increasing order.")

            params.append((code, bytes(raw[at:at + length])))
            at += length

        return cls(priority=int.from_bytes(raw[0:2], "big"), target=target, params=tuple(params))

class HTTPSRecordData(SVCBRecordData):
    ...

RECORD_MAP: Dict[DNSRecordType, type] = {
    DNSRecordType.A:          ARecordData,
    DNSRecordType.AAAA:       AAAARecordData,
    DNSRecordType.NS:         NSRecordData,
    DNSRecordType.CNAME:      CNAMERecordData,
    DNSRecordType.PTR:        PTRRecordData,
    DNSRecordType.DNAME:      DNAMERecordData,
    DNSRecordType.SOA:        SOARecordData,
    DNSRecordType.MX:         MXRecordData,
    DNSRecordType.TXT:        TXTRecordData,
    DNSRecordType.SRV:        SRVRecordData,
    DNSRecordType.CAA:        CAARecordData,
    DNSRecordType.DS:         DSRecordData,
    DNSRecordType.CDS:        CDSRecordData,
    DNSRecordType.DNSKEY:     DNSKEYRecordData,
    DNSRecordType.CDNSKEY:    CDNSKEYRecordData,
    DNSRecordType.RRSIG:      RRSIGRecordData,
    DNSRecordType.NSEC:       NSECRecordData,
    DNSRecordType.NSEC3:      NSEC3RecordData,
    DNSRecordType.NSEC3PARAM: NSEC3PARAMRecordData,
    DNSRecordType.TLSA:       TLSARecordData,
    DNSRecordType.SMIMEA:     SMIMEARecordData,
    DNSRecordType.SVCB:       SVCBRecordData,
    DNSRecordType.HTTPS:      HTTPSRecordData,
}
