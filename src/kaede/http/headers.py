from typing import Union

class Link:
    def __init__(self, value: Union[str, bytes, list[tuple[str, dict[str, str]]]]):
        if isinstance(value, (str, bytes)):
            self.raw = Link.parse(value).raw
        elif isinstance(value, list):
            self.raw = value

    @classmethod
    def parse(cls, value: Union[str, bytes]) -> "Link":
        ...

    def build(self) -> str:
        ...

class AcceptEncoding:
    def __init__(self, value: Union[str, bytes, dict[str, float]]):
        if isinstance(value, (str, bytes)):
            self.raw = AcceptEncoding.parse(value).raw
        elif isinstance(value, list):
            self.raw = value

    @classmethod
    def parse(cls, value: Union[str, bytes]) -> "AcceptEncoding":
        ...

    def build(self) -> str:
        ...

class ContentType:
    def __init__(self, value: Union[str, bytes]):
        if isinstance(value, str):
            self.value = value
        elif isinstance(value, bytes):
            self.value = value.decode()

    @property
    def essence(self) -> str:
        ...

    @property
    def charset(self) -> str:
        ...

    @property
    def boundary(self) -> str:
        ...

    def parse(self) -> dict[str, str, str]:
        ...

    def build(self) -> str:
        ...

class ETag:
    def __init__(self, value: Union[str, bytes]):
        if isinstance(value, str):
            self.value = value.strip("\"")
        elif isinstance(value, bytes):
            self.value = value.decode().strip("\"")

    def __str__(self) -> str:
        return self.value

    def match(self, other: Union[str, bytes, "ETag"]) -> bool:
        ...

    def strong_match(self, other: Union[str, bytes, "ETag"]) -> bool:
        ...

    def weak_match(self, other:Union[str, bytes, "ETag"]) -> bool:
        ...
