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
        if isinstance(value, (str, bytes)):
            self.raw = Link.parse(value).raw
        elif isinstance(value, list):
            self.raw = value
        else:
            self.raw = []

    def __iter__(self):
        return iter(self.raw)

    @classmethod
    def parse(cls, value: str) -> "Link":
        links: List[Tuple[str, Dict[str, str]]] = []

        for entry in CommaHeader.parse(value).raw:
            if "<" not in entry or ">" not in entry:
                continue

            target = entry[entry.index("<") + 1:entry.index(">")]
            params: Dict[str, str] = {}

            for parameter in entry[entry.index(">") + 1:].split(";"):
                name, sep, raw = parameter.partition("=")

                if sep and name.strip():
                    params[name.strip().lower()] = raw.strip().strip('"')

            links.append((target, params))

        return cls(links)

    def build(self) -> str:
        parts: List[str] = []

        for target, params in self.raw:
            entry = f"<{target}>"

            for name, value in params.items():
                entry += f'; {name}="{value}"' if any(character in value for character in ' ,;"') else f"; {name}={value}"

            parts.append(entry)

        return ", ".join(parts)

class AcceptEncoding:
    def __init__(self, value: Union[str, List, Dict, Tuple[Tuple[str, float]]]):
        if isinstance(value, (str, bytes)):
            self.raw = AcceptEncoding.parse(value).raw
        elif isinstance(value, dict):
            self.raw = [(coding, float(weight)) for coding, weight in value.items()]
        elif isinstance(value, (list, tuple)):
            self.raw = [(coding, float(weight)) for coding, weight in value]
        else:
            self.raw = []

    def __str__(self) -> str:
        return self.build()

    def quality(self, coding: str) -> Optional[float]:
        direct = next((weight for name, weight in self.raw if name.lower() == coding.lower()), None)

        if direct is not None:
            return direct

        return next((weight for name, weight in self.raw if name == "*"), None)

    def acceptable(self, coding: str) -> bool:
        weight = self.quality(coding)

        return weight is not None and weight > 0

    @classmethod
    def parse(cls, value: str) -> "AcceptEncoding":
        codings: List[Tuple[str, float]] = []

        for entry in CommaHeader.parse(value).raw:
            name, _, parameters = entry.partition(";")
            weight = 1.0

            for parameter in parameters.split(";"):
                key, sep, raw = parameter.partition("=")

                if sep and key.strip().lower() == "q":
                    try:
                        weight = float(raw.strip())
                    except ValueError:
                        weight = 0.0

            codings.append((name.strip().lower(), weight))

        return cls(codings)

    def build(self) -> str:
        return ", ".join(name if weight == 1.0 else f"{name};q={weight:g}" for name, weight in self.raw)

class ContentType:
    def __init__(self, value: str):
        self.essence, self.parameters = ContentType.parse(value)

    def __str__(self) -> str:
        return self.build()

    @property
    def charset(self) -> Optional[str]:
        return self.parameters.get("charset")

    @property
    def boundary(self) -> Optional[str]:
        return self.parameters.get("boundary")

    @staticmethod
    def parse(value: str) -> Tuple[str, Dict[str, str]]:
        essence, _, rest = value.partition(";")
        parameters: Dict[str, str] = {}

        for parameter in rest.split(";"):
            name, sep, raw = parameter.partition("=")

            if sep and name.strip():
                parameters[name.strip().lower()] = raw.strip().strip('"')

        return (essence.strip().lower(), parameters)

    def build(self) -> str:
        parts = [self.essence]

        for name, value in self.parameters.items():
            parts.append(f'{name}="{value}"' if any(character in value for character in ' ;"') else f"{name}={value}")

        return "; ".join(parts)

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
        pairs: Dict[str, str] = {}

        for pair in value.split(";"):
            name, sep, raw = pair.partition("=")

            if sep and name.strip():
                pairs.setdefault(name.strip(), raw.strip().strip('"'))

        return cls(pairs)

    def build(self) -> str:
        return "; ".join(f"{name}={value}" for name, value in self.raw.items())

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
    def parse(cls, value: str) -> "SetCookie":
        parts = value.split(";")
        name, _, first = parts[0].partition("=")

        fields: Dict[str, Optional[str]] = {}

        for attribute in parts[1:]:
            key, sep, raw = attribute.partition("=")
            fields[key.strip().lower()] = raw.strip() if sep else ""

        samesite = fields.get("samesite")

        return cls(
            name.strip(), first.strip(),
            expires=fields.get("expires"),
            max_age=int(fields["max-age"]) if fields.get("max-age", "").lstrip("-").isdigit() else None,
            domain=fields.get("domain"),
            path=fields.get("path"),
            secure="secure" in fields,
            httponly="httponly" in fields,
            samesite=samesite.capitalize() if samesite else None
        )

    def build(self) -> str:
        if any(character in self.name for character in "()<>@,;:\\\"/[]?={} \t") or not self.name:
            raise ValueError(f"{self.name!r} is not a valid cookie name.")

        for character in self.value:
            if ord(character) < 0x21 or character in ' ",;\\' or ord(character) > 0x7E:
                raise ValueError(f"The cookie {self.name!r} has an invalid value character {character!r}.")

        parts = [f"{self.name}={self.value}"]

        if self.expires is not None:
            parts.append(f"Expires={self.expires}")

        if self.max_age is not None:
            parts.append(f"Max-Age={self.max_age}")

        if self.domain is not None:
            parts.append(f"Domain={self.domain}")

        if self.path is not None:
            parts.append(f"Path={self.path}")

        if self.secure:
            parts.append("Secure")

        if self.httponly:
            parts.append("HttpOnly")

        if self.samesite is not None:
            parts.append(f"SameSite={self.samesite}")

        return "; ".join(parts)
