from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional, Union, Literal, List, Dict, Tuple
from dataclasses import dataclass, field

from ..tcp import TCPPort
from ..udp import UDPPort
from ..http import HTTPPort
from .errors import DNSFormatError, DNSNameError

@dataclass
class DNSPort:
    type: Literal["tcp", "udp", "quic", "https"] = "tcp"
    value: Union[str, int, TCPPort, UDPPort, HTTPPort] = TCPPort(53)
    secure: bool = False

    @property
    def valid(self) -> bool:
        if self.type == "tcp":
            return isinstance(self.value, TCPPort) or (isinstance(self.value, int) and 0 <= self.value < 65536)
        elif self.type == "udp":
            return isinstance(self.value, UDPPort) or (isinstance(self.value, int) and 0 <= self.value < 65536)
        elif self.type == "quic":
            return (isinstance(self.value, UDPPort) or (isinstance(self.value, int) and 0 <= self.value < 65536)) and self.secure
        elif self.type == "https":
            return (isinstance(self.value, HTTPPort) or (isinstance(self.value, int) and 0 <= self.value < 65536)) and self.secure

class DNSOpcode(Enum):
    QUERY  = 0
    IQUERY = 1
    STATUS = 2
    NOTIFY = 4
    UPDATE = 5
    DSO    = 6

    @staticmethod
    def of(value: int) -> Union["DNSOpcode", int]:
        try:
            return DNSOpcode(value)
        except ValueError:
            return value

class DNSResponseCode(Enum):
    NOERROR   = 0
    FORMERR   = 1
    SERVFAIL  = 2
    NXDOMAIN  = 3
    NOTIMP    = 4
    REFUSED   = 5
    YXDOMAIN  = 6
    YXRRSET   = 7
    NXRRSET   = 8
    NOTAUTH   = 9
    NOTZONE   = 10
    DSOTYPENI = 11
    BADVERS   = 16
    BADKEY    = 17
    BADTIME   = 18
    BADMODE   = 19
    BADNAME   = 20
    BADALG    = 21
    BADTRUNC  = 22
    BADCOOKIE = 23

    @staticmethod
    def of(value: int) -> Union["DNSResponseCode", int]:
        try:
            return DNSResponseCode(value)
        except ValueError:
            return value

class DNSRecordType(Enum):
    A          = 1
    AAAA       = 28
    AFSDB      = 18
    APL        = 42
    CAA        = 257
    CDNSKEY    = 60
    CDS        = 59
    CERT       = 37
    CNAME      = 5
    CSYNC      = 62
    DHCID      = 49
    DLV        = 32769
    DNAME      = 39
    DNSKEY     = 48
    DS         = 43
    EUI48      = 108
    EUI64      = 109
    HINFO      = 13
    HIP        = 55
    HTTPS      = 65
    IPSECKEY   = 45
    KEY        = 25
    KX         = 36
    LOC        = 29
    MX         = 15
    NAPTR      = 35
    NS         = 2
    NSEC       = 47
    NSEC3      = 50
    NSEC3PARAM = 51
    OPENPGPKEY = 61
    PTR        = 12
    RP         = 17
    RRSIG      = 46
    SIG        = 24
    SMIMEA     = 53
    SOA        = 6
    SRV        = 33
    SSHFP      = 44
    SVCB       = 64
    TA         = 32768
    TKEY       = 249
    TLSA       = 52
    TSIG       = 250
    TXT        = 16
    URI        = 256
    ZONEMD     = 63

    ANY        = 255
    AXFR       = 252
    IXFR       = 251
    OPT        = 41

    @staticmethod
    def of(value: int) -> Union["DNSRecordType", int]:
        try:
            return DNSRecordType(value)
        except ValueError:
            return value

    @staticmethod
    def from_name(value: str) -> Union["DNSRecordType", int]:
        upper = value.upper()

        if upper.startswith("TYPE") and upper[4:].isdigit():
            return DNSRecordType.of(int(upper[4:]))

        try:
            return DNSRecordType[upper]
        except KeyError:
            raise DNSFormatError(f"{value!r} is not a known record type.")

    @staticmethod
    def mnemonic(value: Union["DNSRecordType", int]) -> str:
        # RFC 3597 section 5: an unknown type renders as TYPENNN, the inverse of from_name.
        return value.name if isinstance(value, DNSRecordType) else f"TYPE{value}"

class DNSRecordClass(Enum):
    IN = "Internet"
    CS = "CSNET"
    CH = "Chaosnet"
    HS = "Hesiod"

    @property
    def number(self) -> int:
        return {"IN": 1, "CS": 2, "CH": 3, "HS": 4}[self.name]

    @staticmethod
    def of(value: int) -> Union["DNSRecordClass", int]:
        for rclass in DNSRecordClass:
            if rclass.number == value:
                return rclass

        return value

class DNSName:
    MAX_LENGTH = 255
    MAX_LABEL  = 63
    MAX_JUMPS  = 128

    @staticmethod
    def key(name: str) -> str:
        return name.rstrip(".").lower()

    @staticmethod
    def escape(label: bytes) -> str:
        parts: List[str] = []

        for value in label:
            if value in (0x2E, 0x5C): # "." and "\\"
                parts.append("\\" + chr(value))
            elif 0x21 <= value <= 0x7E:
                parts.append(chr(value))
            else:
                parts.append("\\%03d" % value)

        return "".join(parts)

    @staticmethod
    def split(name: str) -> List[bytes]:
        if not name.isascii():
            name = name.encode("idna").decode()

        if name in ("", "."):
            return []

        labels: List[bytes] = []
        current = bytearray()
        index = 0

        while index < len(name):
            character = name[index]

            if character == "\\":
                if name[index + 1:index + 4].isdigit():
                    value = int(name[index + 1:index + 4])

                    if value > 255:
                        raise DNSNameError(f"The escape \\{value:03d} in {name!r} does not fit into one byte.")

                    current.append(value)
                    index += 4

                elif index + 1 < len(name):
                    current.append(ord(name[index + 1]))
                    index += 2

                else:
                    raise DNSNameError(f"The name {name!r} ends in a bare escape character.")

            elif character == ".":
                labels.append(bytes(current))
                current.clear()
                index += 1

            else:
                current.append(ord(character))
                index += 1

        labels.append(bytes(current))

        if labels and not labels[-1]:
            labels.pop()

        total = 1

        for label in labels:
            if not label:
                raise DNSNameError(f"The name {name!r} contains an empty label.")

            if len(label) > DNSName.MAX_LABEL:
                raise DNSNameError(f"The label {label!r} is {len(label)} bytes, but a label carries at most {DNSName.MAX_LABEL}.")

            total += len(label) + 1

        if total > DNSName.MAX_LENGTH:
            raise DNSNameError(f"The name {name!r} is {total} wire bytes, but a name carries at most {DNSName.MAX_LENGTH}.")

        return labels

    @staticmethod
    def pack(name: str, message: bytearray, pointers: Optional[Dict[Tuple[bytes, ...], int]] = None, compress: bool = True):
        labels = DNSName.split(name)

        for index in range(len(labels)):
            suffix = tuple(label.lower() for label in labels[index:])

            if compress and pointers is not None and suffix in pointers:
                message += (0xC000 | pointers[suffix]).to_bytes(2, "big")
                return

            if pointers is not None and suffix not in pointers and len(message) < 0x4000:
                pointers[suffix] = len(message)

            message.append(len(labels[index]))
            message += labels[index]

        message.append(0)

    @staticmethod
    def wire(name: str) -> bytes:
        message = bytearray()
        DNSName.pack(name, message, None, compress=False)

        return bytes(message)

    @staticmethod
    def unpack(message: bytes, offset: int) -> Tuple[str, int]:
        labels: List[str] = []
        position = offset
        following: Optional[int] = None
        jumps = 0
        total = 1

        while True:
            if position >= len(message):
                raise DNSFormatError("The message ends in the middle of a name.")

            length = message[position]

            if length & 0xC0 == 0xC0:
                if position + 1 >= len(message):
                    raise DNSFormatError("The message ends in the middle of a compression pointer.")

                target = ((length & 0x3F) << 8) | message[position + 1]

                if following is None:
                    following = position + 2

                if target >= position:
                    raise DNSFormatError("A compression pointer must point backward.")

                jumps += 1

                if jumps > DNSName.MAX_JUMPS:
                    raise DNSFormatError(f"The name chains more than {DNSName.MAX_JUMPS} compression pointers.")

                position = target

            elif length & 0xC0:
                raise DNSFormatError(f"The label length {length:#04x} uses the reserved 0x40/0x80 bits.")

            elif length == 0:
                if following is None:
                    following = position + 1

                return (".".join(labels), following)

            else:
                if position + 1 + length > len(message):
                    raise DNSFormatError("The message ends in the middle of a label.")

                total += length + 1

                if total > DNSName.MAX_LENGTH:
                    raise DNSNameError(f"The name grows past {DNSName.MAX_LENGTH} wire bytes.")

                labels.append(DNSName.escape(message[position + 1:position + 1 + length]))
                position += 1 + length

    @staticmethod
    def within(message: bytes, offset: int, end: int) -> Tuple[str, int]:
        # A name embedded in record data must have its own encoding (labels and
        # any leading compression pointer) end within that record's RDLENGTH; a
        # name that runs past it, e.g. a label with no terminator inside the
        # RDATA, would otherwise be read from the bytes of the following record.
        name, following = DNSName.unpack(message, offset)

        if following > end:
            raise DNSFormatError("A name runs past the end of its record data.")

        return name, following

class DNSRecordData(ABC):
    @abstractmethod
    def pack(self) -> bytes:
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def unpack(cls, raw: bytes, message: bytes, offset: int) -> "DNSRecordData":
        raise NotImplementedError()

    @classmethod
    def from_text(cls, tokens: List[str]) -> "DNSRecordData":
        raise DNSFormatError(f"{cls.__name__} does not support the presentation format.")

    @staticmethod
    def of(rtype: Union["DNSRecordType", int]) -> type:
        from .records import (
            RawRecordData, ARecordData, AAAARecordData, NSRecordData, CNAMERecordData,
            PTRRecordData, DNAMERecordData, SOARecordData, MXRecordData, TXTRecordData,
            SRVRecordData, CAARecordData, DSRecordData, CDSRecordData, DNSKEYRecordData,
            CDNSKEYRecordData, RRSIGRecordData, NSECRecordData, NSEC3RecordData,
            NSEC3PARAMRecordData, TLSARecordData, SMIMEARecordData, SVCBRecordData, HTTPSRecordData
        )

        return {
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
        }.get(rtype, RawRecordData)

@dataclass(frozen=True)
class DNSQuestion:
    name: str
    type: Union[DNSRecordType, int] = DNSRecordType.A
    rclass: Union[DNSRecordClass, int] = DNSRecordClass.IN

    def matches(self, other: "DNSQuestion") -> bool:
        return DNSName.key(self.name) == DNSName.key(other.name) and self.type == other.type and self.rclass == other.rclass

@dataclass(frozen=True)
class DNSRecord:
    name: str
    type: Union[DNSRecordType, int]
    data: DNSRecordData
    ttl: int = 0
    rclass: Union[DNSRecordClass, int] = DNSRecordClass.IN

class DNSRecords:
    def __init__(self, value: Union[str, List, Tuple, "DNSRecords"] = ()):
        if isinstance(value, (bytes, bytearray, memoryview)):
            raise DNSFormatError("Wire records cannot be parsed without their message: compression pointers reach into the whole message, so use DNSMessage.unpack instead.")

        if isinstance(value, str):
            self.raw: List[DNSRecord] = DNSRecords.parse(value).raw
        elif isinstance(value, DNSRecords):
            self.raw = list(value.raw)
        else:
            self.raw = list(value)

    def __iter__(self):
        return iter(self.raw)

    def __len__(self) -> int:
        return len(self.raw)

    def __getitem__(self, index) -> DNSRecord:
        return self.raw[index]

    def __bool__(self) -> bool:
        return bool(self.raw)

    def __eq__(self, other) -> bool:
        return isinstance(other, DNSRecords) and self.raw == other.raw

    def __repr__(self) -> str:
        return f"DNSRecords({self.raw!r})"

    def append(self, record: DNSRecord):
        self.raw.append(record)

    def find(self, type: Optional[Union[DNSRecordType, int]] = None, name: Optional[str] = None) -> "DNSRecords":
        found = self.raw

        if type is not None:
            found = [record for record in found if record.type == type]

        if name is not None:
            found = [record for record in found if DNSName.key(record.name) == DNSName.key(name)]

        return DNSRecords(found)

    def first(self, type: Optional[Union[DNSRecordType, int]] = None, name: Optional[str] = None) -> Optional[DNSRecord]:
        found = self.find(type, name)

        return found[0] if found else None

    @staticmethod
    def tokenize(line: str) -> List[str]:
        tokens: List[str] = []
        current: List[str] = []
        quoted = False
        index = 0

        while index < len(line):
            character = line[index]

            if character == "\\" and index + 1 < len(line):
                current.append(character + line[index + 1])
                index += 2

            elif character == '"':
                if quoted:
                    tokens.append("".join(current))
                    current.clear()

                quoted = not quoted
                index += 1

            elif not quoted and character == ";":
                break

            elif not quoted and character.isspace():
                if current:
                    tokens.append("".join(current))
                    current.clear()

                index += 1

            else:
                current.append(character)
                index += 1

        if quoted:
            raise DNSFormatError(f"The line {line!r} ends inside a quoted string.")

        if current:
            tokens.append("".join(current))

        return tokens

    @classmethod
    def parse(cls, text: str) -> "DNSRecords":
        records: List[DNSRecord] = []

        for line in text.splitlines():
            tokens = DNSRecords.tokenize(line)

            if not tokens:
                continue

            name = tokens.pop(0)
            ttl = 0
            rclass: Union[DNSRecordClass, int] = DNSRecordClass.IN

            while tokens:
                if tokens[0].isdigit():
                    ttl = int(tokens.pop(0))
                elif tokens[0].upper() in DNSRecordClass.__members__:
                    rclass = DNSRecordClass[tokens.pop(0).upper()]
                else:
                    break

            if not tokens:
                raise DNSFormatError(f"The line for {name!r} names no record type.")

            rtype = DNSRecordType.from_name(tokens.pop(0))
            data = DNSRecordData.of(rtype).from_text(tokens)

            records.append(DNSRecord(name=name, type=rtype, data=data, ttl=ttl, rclass=rclass))

        return cls(records)

@dataclass
class EDNS:
    payload_size: int = 1232
    version: int = 0
    do: bool = False
    options: List[Tuple[int, bytes]] = field(default_factory=list)

@dataclass
class DNSMessage:
    id: int = 0

    response: bool = False
    opcode: Union[DNSOpcode, int] = DNSOpcode.QUERY

    authoritative: bool = False
    truncated: bool = False
    recursion_desired: bool = True
    recursion_available: bool = False
    authentic: bool = False
    check_disabled: bool = False

    rcode: Union[DNSResponseCode, int] = DNSResponseCode.NOERROR

    questions: List[DNSQuestion] = field(default_factory=list)
    answers: DNSRecords = field(default_factory=DNSRecords)
    authorities: DNSRecords = field(default_factory=DNSRecords)
    additionals: DNSRecords = field(default_factory=DNSRecords)

    edns: Optional[EDNS] = None

    @staticmethod
    def code(value: Union[Enum, int]) -> int:
        return value.value if isinstance(value, Enum) else int(value)

    @staticmethod
    def classify(value: Union[DNSRecordClass, int]) -> int:
        return value.number if isinstance(value, DNSRecordClass) else int(value)

    def matches(self, response: "DNSMessage") -> bool:
        if response.id != self.id or not response.response:
            return False

        if response.questions:
            return len(response.questions) == len(self.questions) and all(a.matches(b) for a, b in zip(response.questions, self.questions))

        return DNSMessage.code(response.rcode) != 0

    def reply(self, *, rcode: Union[DNSResponseCode, int] = DNSResponseCode.NOERROR) -> "DNSMessage":
        return DNSMessage(
            id=self.id, response=True, opcode=self.opcode,
            recursion_desired=self.recursion_desired, rcode=rcode,
            questions=list(self.questions),
            edns=EDNS() if self.edns is not None else None
        )

    def pack(self) -> bytes:
        if not 0 <= self.id < 65536:
            raise DNSFormatError(f"The message ID {self.id} does not fit into 16 bits.")

        rcode = DNSMessage.code(self.rcode)
        opcode = DNSMessage.code(self.opcode)

        if not 0 <= rcode < 4096:
            raise DNSFormatError(f"The response code {rcode} does not fit into 12 bits.")

        if rcode > 15 and self.edns is None:
            raise DNSFormatError(f"The response code {rcode} needs EDNS to carry its upper bits.")

        flags = (int(self.response) << 15) | (opcode << 11) | (int(self.authoritative) << 10) | (int(self.truncated) << 9) \
              | (int(self.recursion_desired) << 8) | (int(self.recursion_available) << 7) \
              | (int(self.authentic) << 5) | (int(self.check_disabled) << 4) | (rcode & 0xF)

        message = bytearray()
        message += self.id.to_bytes(2, "big")
        message += flags.to_bytes(2, "big")
        message += len(self.questions).to_bytes(2, "big")
        message += len(self.answers).to_bytes(2, "big")
        message += len(self.authorities).to_bytes(2, "big")
        message += (len(self.additionals) + (1 if self.edns is not None else 0)).to_bytes(2, "big")

        pointers: Dict[Tuple[bytes, ...], int] = {}

        for question in self.questions:
            DNSName.pack(question.name, message, pointers)
            message += DNSMessage.code(question.type).to_bytes(2, "big")
            message += DNSMessage.classify(question.rclass).to_bytes(2, "big")

        for section in (self.answers, self.authorities, self.additionals):
            for record in section:
                self.place(record, message, pointers)

        if self.edns is not None:
            self.opt(message, rcode >> 4)

        return bytes(message)

    def place(self, record: DNSRecord, message: bytearray, pointers: Dict[Tuple[bytes, ...], int]):
        if not 0 <= record.ttl < 2 ** 32:
            raise DNSFormatError(f"The TTL {record.ttl} does not fit into 32 bits.")

        rdata = record.data.pack()

        if len(rdata) > 65535:
            raise DNSFormatError(f"The record data is {len(rdata)} bytes, but 65535 is the most a record carries.")

        DNSName.pack(record.name, message, pointers)
        message += DNSMessage.code(record.type).to_bytes(2, "big")
        message += DNSMessage.classify(record.rclass).to_bytes(2, "big")
        message += record.ttl.to_bytes(4, "big")
        message += len(rdata).to_bytes(2, "big")
        message += rdata

    def opt(self, message: bytearray, extended: int):
        edns = self.edns

        if not 0 <= edns.payload_size < 65536:
            raise DNSFormatError(f"The EDNS payload size {edns.payload_size} does not fit into 16 bits.")

        options = bytearray()

        for code, value in edns.options:
            options += code.to_bytes(2, "big")
            options += len(value).to_bytes(2, "big")
            options += value

        message.append(0)
        message += DNSRecordType.OPT.value.to_bytes(2, "big")
        message += edns.payload_size.to_bytes(2, "big")
        message += ((extended << 24) | (edns.version << 16) | (0x8000 if edns.do else 0)).to_bytes(4, "big")
        message += len(options).to_bytes(2, "big")
        message += options

    @classmethod
    def unpack(cls, raw: bytes) -> "DNSMessage":
        if len(raw) < 12:
            raise DNSFormatError(f"The message is {len(raw)} bytes, but the header alone is 12.")

        flags = int.from_bytes(raw[2:4], "big")
        counts = [int.from_bytes(raw[at:at + 2], "big") for at in (4, 6, 8, 10)]

        questions: List[DNSQuestion] = []
        offset = 12

        for _ in range(counts[0]):
            name, offset = DNSName.unpack(raw, offset)

            if offset + 4 > len(raw):
                raise DNSFormatError("The message ends in the middle of a question.")

            questions.append(DNSQuestion(
                name=name,
                type=DNSRecordType.of(int.from_bytes(raw[offset:offset + 2], "big")),
                rclass=DNSRecordClass.of(int.from_bytes(raw[offset + 2:offset + 4], "big"))
            ))
            offset += 4

        answers, offset = cls.section(raw, offset, counts[1])
        authorities, offset = cls.section(raw, offset, counts[2])
        additionals, offset = cls.section(raw, offset, counts[3])

        if offset != len(raw):
            raise DNSFormatError(f"The message carries {len(raw) - offset} bytes beyond its last record.")

        rcode = flags & 0xF
        edns: Optional[EDNS] = None
        kept: List[DNSRecord] = []

        for record in additionals:
            if record.type != DNSRecordType.OPT:
                kept.append(record)
                continue

            if edns is not None:
                raise DNSFormatError("The message carries more than one OPT record.")

            if DNSName.key(record.name):
                raise DNSFormatError("The OPT record must be owned by the root name.")

            rcode |= (record.ttl >> 24) << 4
            edns = EDNS(
                payload_size=DNSMessage.classify(record.rclass),
                version=(record.ttl >> 16) & 0xFF,
                do=bool(record.ttl & 0x8000),
                options=cls.tlvs(record.data.pack())
            )

        return cls(
            id=int.from_bytes(raw[0:2], "big"),
            response=bool(flags & 0x8000),
            opcode=DNSOpcode.of((flags >> 11) & 0xF),
            authoritative=bool(flags & 0x0400),
            truncated=bool(flags & 0x0200),
            recursion_desired=bool(flags & 0x0100),
            recursion_available=bool(flags & 0x0080),
            authentic=bool(flags & 0x0020),
            check_disabled=bool(flags & 0x0010),
            rcode=DNSResponseCode.of(rcode),
            questions=questions,
            answers=DNSRecords(answers),
            authorities=DNSRecords(authorities),
            additionals=DNSRecords(kept),
            edns=edns
        )

    @classmethod
    def section(cls, raw: bytes, offset: int, count: int) -> Tuple[List[DNSRecord], int]:
        from .records import RawRecordData

        records: List[DNSRecord] = []

        for _ in range(count):
            name, offset = DNSName.unpack(raw, offset)

            if offset + 10 > len(raw):
                raise DNSFormatError("The message ends in the middle of a record header.")

            code = int.from_bytes(raw[offset:offset + 2], "big")
            rclass = int.from_bytes(raw[offset + 2:offset + 4], "big")
            ttl = int.from_bytes(raw[offset + 4:offset + 8], "big")
            length = int.from_bytes(raw[offset + 8:offset + 10], "big")
            offset += 10

            if offset + length > len(raw):
                raise DNSFormatError("The message ends in the middle of record data.")

            rtype = DNSRecordType.of(code)
            rdata = raw[offset:offset + length]
            kind = DNSRecordData.of(rtype)

            if kind is RawRecordData:
                data: DNSRecordData = RawRecordData(rdata, code)
            else:
                try:
                    data = kind.unpack(rdata, raw, offset)
                except DNSFormatError:
                    raise
                except (ValueError, IndexError, OverflowError) as e:
                    raise DNSFormatError(f"The {getattr(rtype, 'name', code)} record data could not be parsed: {e}") from e

            offset += length
            records.append(DNSRecord(name=name, type=rtype, data=data, ttl=ttl, rclass=DNSRecordClass.of(rclass)))

        return records, offset

    @staticmethod
    def tlvs(raw: bytes) -> List[Tuple[int, bytes]]:
        options: List[Tuple[int, bytes]] = []
        offset = 0

        while offset < len(raw):
            if offset + 4 > len(raw):
                raise DNSFormatError("The OPT record ends in the middle of an option header.")

            code = int.from_bytes(raw[offset:offset + 2], "big")
            length = int.from_bytes(raw[offset + 2:offset + 4], "big")
            offset += 4

            if offset + length > len(raw):
                raise DNSFormatError("The OPT record ends in the middle of an option value.")

            options.append((code, raw[offset:offset + length]))
            offset += length

        return options
