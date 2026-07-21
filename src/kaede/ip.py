import ipaddress
from enum import Enum
from typing import Union, Optional

from .constants import Characters

class IPVersion(Enum):
    IPv4 = "IPv4"
    IPv6 = "IPv6"

    @staticmethod
    def from_address(address: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]) -> Optional["IPVersion"]:
        if isinstance(address, str):
            if Characters.IP_ADDRESS_V4.issuperset(address):
                return IPVersion.IPv4
            elif Characters.IP_ADDRESS_V6.issuperset(address):
                return IPVersion.IPv6

        elif isinstance(address, ipaddress.IPv4Address):
            return IPVersion.IPv4

        elif isinstance(address, ipaddress.IPv6Address):
            return IPVersion.IPv6
