from typing import Optional, Union

class Characters:
    DIGIT = frozenset("0123456789")
    LOWER = frozenset("abcdefghijklmnopqrstuvwxyz")
    UPPER = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

    HEXDEC = frozenset("0123456789abcdefABCDEF")
    HEXDIG = frozenset(b"0123456789abcdefABCDEF")
    BASE64 = frozenset("+/=") | DIGIT | LOWER | UPPER

class Digits:
    DECIMAL     = Characters.DIGIT
    HEXADECIMAL = Characters.HEXDEC

    @staticmethod
    def decimal(value: Union[str, bytes], *, width: Optional[int] = None) -> Optional[int]:
        return Digits.read(value, Digits.DECIMAL, 10, width)

    @staticmethod
    def hexadecimal(value: Union[str, bytes], *, width: Optional[int] = None) -> Optional[int]:
        return Digits.read(value, Digits.HEXADECIMAL, 16, width)

    @staticmethod
    def read(value: Union[str, bytes], allowed: frozenset, base: int, width: Optional[int]) -> Optional[int]:
        text = value.decode("latin-1") if isinstance(value, (bytes, bytearray)) else value

        if not text or (width is not None and len(text) != width):
            return None

        if not allowed.issuperset(text):
            return None

        return int(text, base)
