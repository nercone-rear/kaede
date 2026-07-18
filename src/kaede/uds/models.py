import sys

class UDSAddress(str):
    limit = 103 if sys.platform == "darwin" else 107 # sizeof(sockaddr_un.sun_path) - 1, platform dependent

    def __new__(cls, value: str = "") -> "UDSAddress":
        if not isinstance(value, str):
            raise TypeError(f"UDS address must be a string, but got {type(value).__name__}.")

        if len(value.encode()) > cls.limit:
            raise ValueError(f"UDS address must be at most {cls.limit} bytes, but got {len(value.encode())}.")

        return super().__new__(cls, value)

    def __repr__(self) -> str:
        return f"UDSAddress({str.__repr__(self)})"

    @property
    def abstract(self) -> bool:
        return self.startswith("\0")

    @property
    def dynamic(self) -> bool:
        return self == ""
