from typing import Optional, Union, Literal, List, Dict, Tuple, TypeVar

T = TypeVar("T")

class CommaHeader:
    def __init__(self, value: Union[str, List, Dict, Tuple[str]]):
        if isinstance(value, (str, bytes)):
            self.raw = CommaHeader.parse(value).raw
        elif isinstance(value, list):
            self.raw = value

    def __str__(self) -> str:
        return self.build()

    def __contains__(self, item: str) -> bool:
        return item in self.raw

    def set(self, value: Union[str, List, Dict, Tuple[str]]):
        if isinstance(value, str):
            self.raw = [value]
        elif isinstance(value, list):
            self.raw = value

    def append(self, value: str):
        self.raw.append(value)

    def remove(self, value: str):
        self.raw.remove(value)

    @classmethod
    def parse(cls, value: str) -> "CommaHeader":
        return cls([v.strip() for v in value.split(",") if v.strip()])

    def build(self) -> str:
        return ", ".join(self.raw)

class Link:
    def __init__(self, value: Union[str, List, Dict, Tuple[Tuple[str, Dict[str, str]]]]):
        ...

    @classmethod
    def parse(cls, value: str) -> "Link":
        ...

    def build(self) -> str:
        ...

class AcceptEncoding:
    def __init__(self, value: Union[str, List, Dict, Tuple[Tuple[str, float]]]):
        ...

    @classmethod
    def parse(cls, value: str) -> "AcceptEncoding":
        ...

    def build(self) -> str:
        ...

class ContentType:
    def __init__(self, value: str):
        ...

    @property
    def essence(self) -> str:
        ...

    @property
    def charset(self) -> str:
        ...

    @property
    def boundary(self) -> str:
        ...

    def parse(self) -> Tuple[str, str, Dict[str, str]]:
        ...

    def build(self) -> str:
        ...

class ETag:
    def __init__(self, value: Union[str, "ETag"]):
        if isinstance(value, str):
            self.value = value
            self.weak = self.value.startswith(("w/", "W/"))
        elif isinstance(value, ETag):
            self.value = value.value
            self.weak = value.weak

    def __str__(self) -> str:
        return self.value

    @property
    def opaque_tag(self) -> str:
        if self.weak:
            return self.value[2:]
        else:
            return self.value

    def match(self, other: Union[str, "ETag"], strong: bool = True, weak: bool = True) -> bool:
        if strong and self.strong_match(other):
            return True

        if weak and self.weak_match(other):
            return True

        return False

    def strong_match(self, other: Union[str, "ETag"]) -> bool:
        return (not self.weak) and (not ETag(other).weak) and (self.opaque_tag == ETag(other).opaque_tag)

    def weak_match(self, other: Union[str, "ETag"]) -> bool:
        return self.opaque_tag == ETag(other).opaque_tag

class Cookie:
    def __init__(self, value: Union[str, Dict[str, str]]):
        if isinstance(value, (str, bytes)):
            self.raw = Cookie.parse(value).raw
        elif isinstance(value, dict):
            self.raw = value
        else:
            self.raw = {}

    def __str__(self) -> str:
        return self.build()

    def __contains__(self, key: str) -> bool:
        return key in self.raw

    def __iter__(self):
        return iter(self.raw)

    def __len__(self) -> int:
        return len(self.raw)

    def get(self, key: str, default: Optional[T] = None) -> Optional[Union[str, T]]:
        return self.raw.get(key, default)

    def items(self) -> List[Tuple[str, str]]:
        return list(self.raw.items())

    @classmethod
    def parse(cls, value: str) -> "Cookie":
        ...

    def build(self) -> str:
        ...

class SetCookie:
    def __init__(self, name: str, value: str, *, expires: Optional[str] = None, max_age: Optional[int] = None, domain: Optional[str] = None, path: Optional[str] = None, secure: bool = False, httponly: bool = False, samesite: Optional[Literal["Strict", "Lax", "None"]] = None):
        self.name = name
        self.value = value
        self.expires = expires
        self.max_age = max_age
        self.domain = domain
        self.path = path
        self.secure = secure
        self.httponly = httponly
        self.samesite = samesite

    def __str__(self) -> str:
        return self.build()

    @classmethod
    def parse(self, value: str) -> "SetCookie":
        ...

    def build(self) -> str:
        ...
