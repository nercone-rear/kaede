class UDPPort(int):
    def __new__(cls, value: int = 0) -> "UDPPort":
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"UDP port must be an integer, but got {type(value).__name__}.")

        if not 0 <= value <= 65535:
            raise ValueError(f"UDP port must be between 0 and 65535, but got {value}.")

        return super().__new__(cls, value)

    def __repr__(self) -> str:
        return f"UDPPort({int(self)})"

    @property
    def dynamic(self) -> bool:
        return self == 0

    @property
    def privileged(self) -> bool:
        return 0 < self < 1024
