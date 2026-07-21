import time
import ipaddress
from typing import Optional, Union, List, Dict, Tuple
from dataclasses import dataclass, field

from ...models import ClientLimits, ClientConfig
from ...udp import UDPPort
from ..models import DNSPort, DNSRecordName, DNSRecordType, DNSRecordClass, DNSResponseCode, DNSQuestion, DNSRecords, DNSExtension, DNSMessage
from ..errors import DNSError, DNSFormatError, DNSConnectionError, DNSServerError, DNSSECError
from ..protocol.base import DNSProtocol
from ..protocol.udp import DNSUDPProtocol
from ..protocol.tcp import DNSTCPProtocol
from ..protocol.tls import DNSTLSProtocol
from ..protocol.quic import DNSQUICProtocol
from ..helpers.dnssec import DNSSECValidator
from .common import DNSLimits, DNSConfig

@dataclass
class DNSClientLimits(DNSLimits, ClientLimits):
    max_retries: int = 3

    max_cache_entries: int = 4096
    max_cache_ttl: float = 86400

    max_edns_payload_size: int = 1232

    timeout_query: float = 3.0

@dataclass
class DNSClientConfig(DNSConfig, ClientConfig):
    limits: DNSClientLimits = field(default_factory=lambda: DNSClientLimits())

    servers: List[Tuple[str, DNSPort]] = field(default_factory=lambda: [
        ("1.1.1.1", DNSPort("udp", UDPPort(53))),
        ("8.8.8.8", DNSPort("udp", UDPPort(53)))
    ])

    cache: bool = True

    hostname: Optional[str] = None

    doh_path: str = "/dns-query"

class DNSCache:
    def __init__(self, limits: Optional[DNSClientLimits] = None):
        self.limits = limits or DNSClientLimits()
        self.entries: Dict[Tuple[str, int, int], Tuple[float, Union[DNSResponseCode, int], DNSRecords]] = {}

    def get(self, key: Tuple[str, int, int], now: Optional[float] = None) -> Optional[Tuple[Union[DNSResponseCode, int], DNSRecords]]:
        entry = self.entries.get(key)

        if entry is None:
            return None

        expires, rcode, records = entry

        if (time.monotonic() if now is None else now) >= expires:
            del self.entries[key]
            return None

        return (rcode, records)

    def put(self, key: Tuple[str, int, int], rcode: Union[DNSResponseCode, int], records: DNSRecords, ttl: float, now: Optional[float] = None):
        if ttl <= 0:
            return

        now = time.monotonic() if now is None else now

        if len(self.entries) >= self.limits.max_cache_entries:
            self.evict(now)

        self.entries[key] = (now + min(ttl, self.limits.max_cache_ttl), rcode, records)

    def evict(self, now: float):
        for key in [key for key, (expires, _, _) in self.entries.items() if expires <= now]:
            del self.entries[key]

        while len(self.entries) >= self.limits.max_cache_entries:
            del self.entries[min(self.entries, key=lambda key: self.entries[key][0])]

    def clear(self):
        self.entries.clear()

class DNSClient:
    def __init__(self, *, config: Optional[DNSClientConfig] = None):
        self.config = config or DNSClientConfig()

        self.cache = DNSCache(self.config.limits) if self.config.cache else None
        self.transports: Dict[Tuple, DNSProtocol] = {}
        self.validator: Optional[DNSSECValidator] = None

    async def __aenter__(self) -> "DNSClient":
        return self

    async def __aexit__(self, *_):
        await self.close()

    async def close(self):
        transports, self.transports = self.transports, {}

        for transport in transports.values():
            await transport.close()

    async def query(self, name: str, type: Union[DNSRecordType, int] = DNSRecordType.A, *, rclass: Union[DNSRecordClass, int] = DNSRecordClass.IN, recursion_desired: bool = True, do: bool = False) -> DNSMessage:
        message = DNSMessage(
            recursion_desired=recursion_desired,
            questions=[DNSQuestion(name, type, rclass)],
            edns=DNSExtension(payload_size=self.config.limits.max_edns_payload_size, do=do)
        )

        failures: List[DNSError] = []

        for host, port in self.config.servers:
            try:
                return await self.attempt(host, port, message)

            except DNSError as e:
                failures.append(e)

        if failures:
            raise failures[-1]

        raise DNSConnectionError("No DNS server is configured.")

    async def attempt(self, host: str, port: DNSPort, message: DNSMessage) -> DNSMessage:
        if port.type == "udp":
            response = await DNSUDPProtocol((host, int(port.value)), limits=self.config.limits).query(message, timeout=self.config.limits.timeout_query)

            if not response.truncated:
                return response

            fallback = DNSTCPProtocol((host, int(port.value)), limits=self.config.limits)

            try:
                return await fallback.query(message, timeout=self.config.limits.timeout_query)

            finally:
                await fallback.close()

        if port.type in ("tcp", "quic", "https"):
            return await self.keep(host, port).query(message, timeout=self.config.limits.timeout_query)

        raise DNSConnectionError(f"The {port.type} transport is not supported.")

    def keep(self, host: str, port: DNSPort) -> DNSProtocol:
        key = (host, port.type, str(port.value))
        transport = self.transports.get(key)

        if transport is None:
            transport = self.transports[key] = self.build(host, port)

        return transport

    def build(self, host: str, port: DNSPort) -> DNSProtocol:
        if port.type == "https":
            from ..protocol.https import DNSHTTPSProtocol

            return DNSHTTPSProtocol((host, int(port.value)), path=self.config.doh_path, tls=self.config.tls, hostname=self.config.hostname, limits=self.config.limits)

        if port.type == "quic":
            return DNSQUICProtocol((host, int(port.value)), tls=self.config.tls, hostname=self.config.hostname, limits=self.config.limits)

        if self.config.tls:
            return DNSTLSProtocol((host, int(port.value)), tls=self.config.tls, hostname=self.config.hostname, limits=self.config.limits)

        return DNSTCPProtocol((host, int(port.value)), limits=self.config.limits)

    async def resolve(self, name: str, type: Union[DNSRecordType, int] = DNSRecordType.A, *, rclass: Union[DNSRecordClass, int] = DNSRecordClass.IN, validate: bool = False) -> DNSRecords:
        key = (DNSRecordName.key(name), DNSMessage.code(type), DNSMessage.classify(rclass))

        if self.cache is not None and not validate:
            kept = self.cache.get(key)

            if kept is not None:
                rcode, records = kept

                if DNSMessage.code(rcode) != 0:
                    raise DNSServerError(f"The server answered {name!r} with {getattr(rcode, 'name', rcode)}.", rcode)

                return records

        response = await self.query(name, type, rclass=rclass, do=validate)

        if validate and DNSMessage.code(response.rcode) == 0:
            if self.validator is None:
                self.validator = DNSSECValidator()

            if not await self.validator.attest(self, response):
                raise DNSSECError(f"{name!r} could not be validated: the chain of trust ends at an unsigned zone.")

        rcode = DNSMessage.code(response.rcode)

        if rcode == 0:
            records = self.chase(response, name, type)

            if self.cache is not None:
                self.cache.put(key, response.rcode, records, self.lifetime(response, records))

            return records

        if rcode == DNSResponseCode.NXDOMAIN.value and self.cache is not None:
            self.cache.put(key, response.rcode, DNSRecords(), self.lifetime(response, DNSRecords()))

        raise DNSServerError(f"The server answered {name!r} with {getattr(response.rcode, 'name', response.rcode)}.", response.rcode)

    def chase(self, response: DNSMessage, name: str, type: Union[DNSRecordType, int]) -> DNSRecords:
        current = name
        visited = set()

        while True:
            found = response.answers.find(type, current)

            if found or type == DNSRecordType.CNAME:
                return found

            alias = response.answers.first(DNSRecordType.CNAME, current)

            if alias is None:
                return DNSRecords()

            if DNSRecordName.key(current) in visited:
                raise DNSFormatError(f"The CNAME chain for {name!r} loops.")

            visited.add(DNSRecordName.key(current))
            current = alias.data.target

    def lifetime(self, response: DNSMessage, records: DNSRecords) -> float:
        if records:
            return float(min(record.ttl for record in records))

        start = response.authorities.first(DNSRecordType.SOA)

        if start is None:
            return 0.0

        return float(min(start.ttl, start.data.minimum))

    async def addresses(self, name: str) -> List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
        found: List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = []
        failures: List[DNSError] = []

        for type in (DNSRecordType.A, DNSRecordType.AAAA):
            try:
                found += [record.data.address for record in await self.resolve(name, type)]

            except DNSError as e:
                failures.append(e)

        if not found and failures:
            raise failures[0]

        return found
