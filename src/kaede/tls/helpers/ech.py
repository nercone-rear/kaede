from typing import Optional, List
from dataclasses import dataclass

from ..errors import TLSConfigError

@dataclass(frozen=True)
class ECHConfig:
    """A single parsed ECHConfig entry from an ECHConfigList (RFC 9849)."""

    version: int
    public_name: str
    max_name_length: int

class ECHConfigList:
    """The ECHConfigList wire format (RFC 9849): a length-prefixed list of ECHConfig entries."""

    RFC9849_VERSION = 0xfe0d

    @staticmethod
    def parse(raw: bytes) -> List[ECHConfig]:
        if len(raw) < 2:
            raise TLSConfigError("The ECHConfigList is too short to carry its length prefix.")

        length = int.from_bytes(raw[:2], "big")

        if length != len(raw) - 2:
            raise TLSConfigError(f"The ECHConfigList declares {length} bytes of configs but carries {len(raw) - 2}.")

        configs: List[ECHConfig] = []
        offset = 2

        while offset < len(raw):
            if offset + 4 > len(raw):
                raise TLSConfigError("The ECHConfigList ends in the middle of an ECHConfig header.")

            version = int.from_bytes(raw[offset:offset + 2], "big")
            size = int.from_bytes(raw[offset + 2:offset + 4], "big")
            offset += 4

            if offset + size > len(raw):
                raise TLSConfigError("The ECHConfigList ends in the middle of an ECHConfig.")

            if version == ECHConfigList.RFC9849_VERSION:
                configs.append(ECHConfigList.contents(raw[offset:offset + size]))

            offset += size

        if not configs:
            raise TLSConfigError("The ECHConfigList does not contain a supported ECHConfig version.")

        return configs

    @staticmethod
    def contents(raw: bytes) -> ECHConfig:
        # config_id(1) + kem_id(2) + public_key<2 + len> + cipher_suites<2 + len> + max_name_length(1) + public_name<1 + len> + extensions<2 + len>
        if len(raw) < 1 + 2 + 2:
            raise TLSConfigError("An ECHConfig is too short to carry its fixed fields.")

        offset = 1 + 2
        key_length = int.from_bytes(raw[offset:offset + 2], "big")
        offset += 2 + key_length

        if offset + 2 > len(raw):
            raise TLSConfigError("An ECHConfig ends in the middle of its public key.")

        suite_length = int.from_bytes(raw[offset:offset + 2], "big")
        offset += 2 + suite_length

        if offset + 1 > len(raw):
            raise TLSConfigError("An ECHConfig ends in the middle of its cipher suites.")

        max_name_length = raw[offset]
        offset += 1

        if offset >= len(raw):
            raise TLSConfigError("An ECHConfig ends before its public name.")

        name_length = raw[offset]
        offset += 1

        if offset + name_length > len(raw):
            raise TLSConfigError("An ECHConfig ends in the middle of its public name.")

        public_name = raw[offset:offset + name_length].decode(errors="replace")

        return ECHConfig(version=ECHConfigList.RFC9849_VERSION, public_name=public_name, max_name_length=max_name_length)

@dataclass(frozen=True)
class ECHStatus:
    """The outcome of Encrypted Client Hello for a TLS session, from SSL_ech_get1_status."""

    BACKEND             = 4  # this side is an ECH backend: it saw an inner Client Hello directly
    GREASE_ECH          = 3  # ECH was greased and the server replied with an ECH extension
    GREASE              = 2  # ECH was greased (no real config was configured)
    SUCCESS             = 1
    FAILED              = 0
    BAD_CALL            = -100
    NOT_TRIED           = -101
    BAD_NAME            = -102 # ECH succeeded but the certificate does not match the inner name
    NOT_CONFIGURED      = -103
    FAILED_ECH          = -105 # ECH failed, but the server (identified by a trusted certificate) returned retry configs
    FAILED_ECH_BAD_NAME = -106 # as FAILED_ECH, but the certificate does not even match the outer (public) name

    code: int
    inner_sni: Optional[str] = None
    outer_sni: Optional[str] = None

    @property
    def succeeded(self) -> bool:
        return self.code == ECHStatus.SUCCESS
