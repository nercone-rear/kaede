from typing import Optional, Union

class Characters:
    DIGIT = frozenset("0123456789")
    LOWER = frozenset("abcdefghijklmnopqrstuvwxyz")
    UPPER = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

    HEXDEC = DIGIT | frozenset("abcdefABCDEF")
    BASE64 = UPPER | LOWER | DIGIT | frozenset("+/=")

    # IP
    IP_ADDRESS_V4 = DIGIT  | frozenset(".")
    IP_ADDRESS_V6 = HEXDEC | frozenset(":.[]") # ":." also covers IPv4-mapped forms like ::ffff:192.0.2.1
    IP_ADDRESS    = IP_ADDRESS_V4 | IP_ADDRESS_V6

    # URL
    URL_GEN_DELIMS = frozenset(":/?#[]@")
    URL_SUB_DELIMS = frozenset("!$&'()*+,;=")
    URL_UNRESERVED = UPPER | LOWER | DIGIT | frozenset("-._~")
    URL_ENCODED    = URL_GEN_DELIMS | URL_SUB_DELIMS | URL_UNRESERVED | frozenset("%")

class Digits:
    @staticmethod
    def read(value: Union[str, bytes], *, charset: frozenset, base: int, width: Optional[int]) -> Optional[int]:
        if isinstance(value, str):
            text = value
        elif isinstance(value, (bytes, bytearray)):
            text = value.decode("latin-1")

        if not text or (width is not None and len(text) != width):
            return None

        if not charset.issuperset(text):
            return None

        return int(text, base)

    @staticmethod
    def decimal(value: Union[str, bytes], *, width: Optional[int] = None) -> Optional[int]:
        return Digits.read(value, charset=Characters.DIGIT, base=10, width=width)

    @staticmethod
    def hexadecimal(value: Union[str, bytes], *, width: Optional[int] = None) -> Optional[int]:
        return Digits.read(value, charset=Characters.HEXDEC, base=16, width=width)
