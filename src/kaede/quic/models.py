from typing import Optional

class QUICPacket:
    limit = 20

    INITIAL   = 0x00
    ZERO_RTT  = 0x01
    HANDSHAKE = 0x02
    RETRY     = 0x03

    def __init__(self, *, long: bool, kind: Optional[int] = None, version: Optional[int] = None, destination: bytes = b"", source: bytes = b""):
        self.long = long
        self.kind = kind
        self.version = version
        self.destination = destination
        self.source = source

    def __repr__(self) -> str:
        return f"QUICPacket(long={self.long}, kind={self.kind}, destination={self.destination.hex()!r})"

    @property
    def initial(self) -> bool:
        return self.long and self.version != 0 and self.kind == QUICPacket.INITIAL

    @staticmethod
    def read(data: bytes, length: int = 0) -> Optional["QUICPacket"]:
        if len(data) < 2:
            return None

        if not data[0] & 0x80:
            if length <= 0 or len(data) < 1 + length:
                return None

            return QUICPacket(long=False, destination=data[1:1 + length])

        if len(data) < 6:
            return None

        at = 5
        destination, at = QUICPacket.identifier(data, at)

        if destination is None:
            return None

        source, at = QUICPacket.identifier(data, at)

        if source is None:
            return None

        return QUICPacket(long=True, kind=(data[0] & 0x30) >> 4, version=int.from_bytes(data[1:5], "big"), destination=destination, source=source)

    @staticmethod
    def identifier(data: bytes, at: int):
        if at >= len(data):
            return (None, at)

        size = data[at]
        at += 1

        if size > QUICPacket.limit or at + size > len(data):
            return (None, at)

        return (data[at:at + size], at + size)

class QUICStreamID(int):
    limit = 2 ** 62

    def __new__(cls, value: int = 0) -> "QUICStreamID":
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"QUIC stream id must be an integer, but got {type(value).__name__}.")

        if not 0 <= value < cls.limit:
            raise ValueError(f"QUIC stream id must be between 0 and {cls.limit - 1}, but got {value}.")

        return super().__new__(cls, value)

    def __repr__(self) -> str:
        return f"QUICStreamID({int(self)})"

    @property
    def client(self) -> bool:
        return not self & 0x1

    @property
    def server(self) -> bool:
        return bool(self & 0x1)

    @property
    def bidirectional(self) -> bool:
        return not self & 0x2

    @property
    def unidirectional(self) -> bool:
        return bool(self & 0x2)

    @property
    def ordinal(self) -> int:
        return int(self) >> 2

    @staticmethod
    def make(ordinal: int, *, server: bool = False, unidirectional: bool = False) -> "QUICStreamID":
        if isinstance(ordinal, bool) or not isinstance(ordinal, int):
            raise TypeError(f"QUIC stream ordinal must be an integer, but got {type(ordinal).__name__}.")

        if ordinal < 0:
            raise ValueError(f"QUIC stream ordinal must not be negative, but got {ordinal}.")

        return QUICStreamID((ordinal << 2) | (0x2 if unidirectional else 0x0) | (0x1 if server else 0x0))
