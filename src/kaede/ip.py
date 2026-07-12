import ipaddress
from enum import Enum
from typing import Union

class IPVersion(Enum):
    IPv4 = "IPv4"
    IPv6 = "IPv6"

    @staticmethod
    def from_address(address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> "IPVersion":
        if isinstance(address, ipaddress.IPv4Address):
            return IPVersion.IPv4
        elif isinstance(address, ipaddress.IPv6Address):
            return IPVersion.IPv6
