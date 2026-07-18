import time
import ctypes
import hashlib
from typing import Optional, Union, Dict, List, Tuple
from dataclasses import replace

from ...tls.openssl import OpenSSL, VOID_P
from ..models import DNSName, DNSRecordType, DNSRecordData, DNSRecord, DNSRecords, DNSMessage
from ..records import NameRecordData, SOARecordData, MXRecordData, SRVRecordData, DSRecordData, DNSKEYRecordData, RRSIGRecordData
from ..errors import DNSError, DNSSECError

class DNSSECCrypto:
    RSA     = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])
    EC      = bytes([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])
    P256    = bytes([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
    P384    = bytes([0x2B, 0x81, 0x04, 0x00, 0x22])
    ED25519 = bytes([0x2B, 0x65, 0x70])

    def __init__(self, library: Optional[OpenSSL] = None):
        self.library = library or OpenSSL()

        VOID = None
        INT  = ctypes.c_int
        LONG = ctypes.c_long
        SIZE = ctypes.c_size_t
        STR  = ctypes.c_char_p

        bind = self.library.bind
        crypto = self.library.crypto

        self.context_new  = bind(crypto, "EVP_MD_CTX_new", VOID_P, [])
        self.context_free = bind(crypto, "EVP_MD_CTX_free", VOID, [VOID_P])
        self.initialize   = bind(crypto, "EVP_DigestVerifyInit", INT, [VOID_P, VOID_P, VOID_P, VOID_P, VOID_P])
        self.check        = bind(crypto, "EVP_DigestVerify", INT, [VOID_P, STR, SIZE, STR, SIZE])
        self.key_free     = bind(crypto, "EVP_PKEY_free", VOID, [VOID_P])
        self.decode       = bind(crypto, "d2i_PUBKEY", VOID_P, [VOID_P, ctypes.POINTER(VOID_P), LONG])
        self.sha256       = bind(crypto, "EVP_sha256", VOID_P, [])
        self.sha384       = bind(crypto, "EVP_sha384", VOID_P, [])
        self.sha512       = bind(crypto, "EVP_sha512", VOID_P, [])

    @staticmethod
    def measure(length: int) -> bytes:
        if length < 0x80:
            return bytes([length])

        raw = length.to_bytes((length.bit_length() + 7) // 8, "big")

        return bytes([0x80 | len(raw)]) + raw

    @staticmethod
    def block(tag: int, content: bytes) -> bytes:
        return bytes([tag]) + DNSSECCrypto.measure(len(content)) + content

    @staticmethod
    def integer(raw: bytes) -> bytes:
        raw = raw.lstrip(b"\x00") or b"\x00"

        if raw[0] & 0x80:
            raw = b"\x00" + raw

        return DNSSECCrypto.block(0x02, raw)

    @staticmethod
    def spki(identifier: bytes, key: bytes) -> bytes:
        return DNSSECCrypto.block(0x30, identifier + DNSSECCrypto.block(0x03, b"\x00" + key))

    def prepare(self, algorithm: int, key: bytes, signature: bytes) -> Tuple[bytes, Optional[ctypes.c_void_p], bytes]:
        if algorithm in (8, 10): # RSASHA256 / RSASHA512
            if len(key) < 3:
                raise DNSSECError("The RSA key material is too short to carry an exponent.")

            cut = 1 + key[0] if key[0] else 3 + int.from_bytes(key[1:3], "big")

            if key[0] == 0 and len(key) < 3:
                raise DNSSECError("The RSA key material is too short to carry its exponent length.")

            exponent, modulus = key[1 if key[0] else 3:cut], key[cut:]

            if not exponent or not (64 <= len(modulus.lstrip(b"\x00")) <= 512):
                raise DNSSECError("The RSA key material does not carry a usable exponent and modulus.")

            identifier = DNSSECCrypto.block(0x30, DNSSECCrypto.block(0x06, DNSSECCrypto.RSA) + b"\x05\x00")
            public = DNSSECCrypto.block(0x30, DNSSECCrypto.integer(modulus) + DNSSECCrypto.integer(exponent))

            return (DNSSECCrypto.spki(identifier, public), self.sha256() if algorithm == 8 else self.sha512(), signature)

        if algorithm in (13, 14): # ECDSAP256SHA256 / ECDSAP384SHA384
            size = 32 if algorithm == 13 else 48

            if len(key) != size * 2 or len(signature) != size * 2:
                raise DNSSECError(f"The ECDSA material does not have the {size * 2} byte key and signature this algorithm uses.")

            curve = DNSSECCrypto.P256 if algorithm == 13 else DNSSECCrypto.P384
            identifier = DNSSECCrypto.block(0x30, DNSSECCrypto.block(0x06, DNSSECCrypto.EC) + DNSSECCrypto.block(0x06, curve))
            wrapped = DNSSECCrypto.block(0x30, DNSSECCrypto.integer(signature[:size]) + DNSSECCrypto.integer(signature[size:]))

            return (DNSSECCrypto.spki(identifier, b"\x04" + key), self.sha256() if algorithm == 13 else self.sha384(), wrapped)

        if algorithm == 15: # Ed25519
            if len(key) != 32 or len(signature) != 64:
                raise DNSSECError("The Ed25519 material does not have a 32 byte key and a 64 byte signature.")

            identifier = DNSSECCrypto.block(0x30, DNSSECCrypto.block(0x06, DNSSECCrypto.ED25519))

            return (DNSSECCrypto.spki(identifier, key), None, signature)

        raise DNSSECError(f"The DNSSEC algorithm {algorithm} is not supported.")

    def verify(self, algorithm: int, key: bytes, data: bytes, signature: bytes) -> bool:
        try:
            document, digest, signature = self.prepare(algorithm, key, signature)

        except DNSSECError:
            return False

        raw = ctypes.create_string_buffer(document, len(document))
        cursor = VOID_P(ctypes.addressof(raw))

        self.library.error_clear()
        pointer = self.decode(None, ctypes.byref(cursor), len(document))

        if not pointer:
            self.library.error_clear()
            return False

        context = self.context_new()

        try:
            if not context or self.initialize(context, None, digest, None, pointer) != 1:
                return False

            return self.check(context, signature, len(signature), data, len(data)) == 1

        finally:
            if context:
                self.context_free(context)

            self.key_free(pointer)
            self.library.error_clear()

class DNSSECValidator:
    ANCHORS = [ # https://data.iana.org/root-anchors/root-anchors.xml
        DNSRecord("", DNSRecordType.DS, DSRecordData(20326, 8, 2, bytes.fromhex("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"))),
        DNSRecord("", DNSRecordType.DS, DSRecordData(38696, 8, 2, bytes.fromhex("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16")))
    ]

    def __init__(self, crypto: Optional[DNSSECCrypto] = None):
        self.crypto = crypto or DNSSECCrypto()

    def keytag(self, data: DNSKEYRecordData) -> int:
        total = 0

        for index, value in enumerate(data.pack()):
            total += (value << 8) if index % 2 == 0 else value

        return (total + ((total >> 16) & 0xFFFF)) & 0xFFFF

    def canonize(self, data: DNSRecordData) -> DNSRecordData:
        if isinstance(data, NameRecordData):
            return replace(data, target=data.target.lower())

        if isinstance(data, SOARecordData):
            return replace(data, mname=data.mname.lower(), rname=data.rname.lower())

        if isinstance(data, MXRecordData):
            return replace(data, exchange=data.exchange.lower())

        if isinstance(data, SRVRecordData):
            return replace(data, target=data.target.lower())

        return data

    def canonical(self, records: DNSRecords, rrsig: RRSIGRecordData) -> bytes:
        if not records:
            raise DNSSECError("An empty RRset cannot be signed or verified.")

        owner = records[0].name.lower()
        labels = DNSName.split(owner)

        if len(labels) > rrsig.labels:
            owner = "*." + ".".join(label.decode(errors="replace") for label in labels[len(labels) - rrsig.labels:])

        head = replace(rrsig, signature=b"").pack()
        entry = DNSName.wire(owner) + DNSMessage.code(records[0].type).to_bytes(2, "big") + DNSMessage.classify(records[0].rclass).to_bytes(2, "big") + rrsig.original_ttl.to_bytes(4, "big")

        pieces = sorted({self.canonize(record.data).pack() for record in records})

        return head + b"".join(entry + len(piece).to_bytes(2, "big") + piece for piece in pieces)

    def within(self, rrsig: RRSIGRecordData, now: float) -> bool:
        def ordered(early: int, late: int) -> bool:
            return ((late - early) & 0xFFFFFFFF) < 0x80000000

        moment = int(now) & 0xFFFFFFFF

        return ordered(rrsig.inception, moment) and ordered(moment, rrsig.expiration)

    def verify_rrset(self, records: DNSRecords, rrsig: DNSRecord, dnskey: DNSRecord, *, now: Optional[float] = None) -> bool:
        signature = rrsig.data
        key = dnskey.data

        if not isinstance(signature, RRSIGRecordData) or not isinstance(key, DNSKEYRecordData):
            return False

        if not records or any(record.type != signature.type_covered for record in records):
            return False

        if DNSName.key(dnskey.name) != DNSName.key(signature.signer):
            return False

        if key.protocol != 3 or not (key.flags & DNSKEYRecordData.ZONE_KEY):
            return False

        if key.algorithm != signature.algorithm or self.keytag(key) != signature.key_tag:
            return False

        if not self.within(signature, time.time() if now is None else now):
            return False

        return self.crypto.verify(signature.algorithm, key.key, self.canonical(records, signature), signature.signature)

    def verify_ds(self, dnskey: DNSRecord, ds: DNSRecord) -> bool:
        key = dnskey.data
        delegation = ds.data

        if not isinstance(key, DNSKEYRecordData) or not isinstance(delegation, DSRecordData):
            return False

        if delegation.key_tag != self.keytag(key) or delegation.algorithm != key.algorithm:
            return False

        digests = {1: hashlib.sha1, 2: hashlib.sha256, 4: hashlib.sha384}
        digest = digests.get(delegation.digest_type)

        if digest is None:
            return False

        return digest(DNSName.wire(dnskey.name.lower()) + key.pack()).digest() == delegation.digest

    async def chain(self, client, name: str, type: Union[DNSRecordType, int], *, now: Optional[float] = None) -> bool:
        return await self.attest(client, await client.query(name, type, do=True), now=now)

    async def attest(self, client, response: DNSMessage, *, now: Optional[float] = None) -> bool:
        groups: Dict[Tuple[str, int], List[DNSRecord]] = {}
        signatures: Dict[Tuple[str, int], List[DNSRecord]] = {}

        for record in response.answers:
            spot = (DNSName.key(record.name), DNSMessage.code(record.data.type_covered if isinstance(record.data, RRSIGRecordData) else record.type))

            (signatures if record.type == DNSRecordType.RRSIG else groups).setdefault(spot, []).append(record)

        if not groups:
            return False

        zones: Dict[str, Union[DNSRecords, bool]] = {}
        secure = True

        for spot, members in groups.items():
            covering = signatures.get(spot, [])

            if not covering:
                secure = False
                continue

            if not await self.endorse(client, DNSRecords(members), covering, zones, now):
                secure = False

        return secure

    async def endorse(self, client, records: DNSRecords, covering: List[DNSRecord], zones: Dict, now: Optional[float], depth: int = 0) -> bool:
        for rrsig in covering:
            keys = await self.establish(client, rrsig.data.signer, zones, now, depth + 1)

            if keys is False:
                return False

            for dnskey in keys:
                if self.verify_rrset(records, rrsig, dnskey, now=now):
                    return True

        raise DNSSECError(f"No signature over the {getattr(records[0].type, 'name', records[0].type)} RRset of {records[0].name!r} verifies.")

    async def establish(self, client, zone: str, zones: Dict, now: Optional[float], depth: int = 0) -> Union[DNSRecords, bool]:
        spot = DNSName.key(zone)

        if spot in zones:
            return zones[spot]

        if depth > 32:
            raise DNSSECError(f"The trust chain under {zone!r} is deeper than any real delegation.")

        zones[spot] = False

        response = await client.query(zone, DNSRecordType.DNSKEY, do=True)
        keys = response.answers.find(DNSRecordType.DNSKEY, zone)
        covering = [record for record in response.answers.find(DNSRecordType.RRSIG, zone) if isinstance(record.data, RRSIGRecordData) and record.data.type_covered == DNSRecordType.DNSKEY]

        if spot == "":
            trusted: Union[List[DNSRecord], DNSRecords] = DNSSECValidator.ANCHORS

        else:
            delegation = await client.query(zone, DNSRecordType.DS, do=True)
            trusted = delegation.answers.find(DNSRecordType.DS, zone)

            if not trusted:
                zones[spot] = False
                return False

            signatures = [record for record in delegation.answers.find(DNSRecordType.RRSIG, zone) if isinstance(record.data, RRSIGRecordData) and record.data.type_covered == DNSRecordType.DS]

            if not signatures:
                raise DNSSECError(f"The DS RRset of {zone!r} arrived without a signature.")

            if not await self.endorse(client, DNSRecords(trusted), signatures, zones, now, depth):
                zones[spot] = False
                return False

        if not keys or not covering:
            raise DNSSECError(f"{zone!r} has a secure delegation but did not answer with a signed DNSKEY RRset.")

        anchored = [key for key in keys if any(self.verify_ds(key, ds) for ds in trusted)]

        if not anchored:
            raise DNSSECError(f"No DNSKEY of {zone!r} matches its delegation signer records.")

        for rrsig in covering:
            for dnskey in anchored:
                if self.verify_rrset(keys, rrsig, dnskey, now=now):
                    zones[spot] = keys
                    return keys

        raise DNSSECError(f"The DNSKEY RRset of {zone!r} is not verifiably signed by an anchored key.")
