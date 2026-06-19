from __future__ import annotations

import base64
from decimal import Decimal, ROUND_HALF_EVEN

from ..constants import Characters
from .models import StructuredFieldItem, StructuredFieldList
from .errors import StructuredFieldError

CHARS_KEY   = set("_-.*")            | Characters.DIGIT | Characters.LOWER
CHARS_TOKEN = set("!#$%&'*+-.^_`|~") | Characters.DIGIT | Characters.LOWER | Characters.UPPER

class StructuredFieldToken(str):
    __slots__ = ()

class StructuredFieldParser:
    def __init__(self, text: str):
        self.s = text
        self.i = 0
        self.n = len(text)

    def parse(self, field_type: str):
        self.skip_sp()

        if field_type == "list":
            output = self.parse_list()
        elif field_type == "dictionary":
            output = self.parse_dict()
        elif field_type == "item":
            output = self.parse_item()
        else:
            raise StructuredFieldError(f"unknown field type: {field_type}")

        self.skip_sp()

        if self.i != self.n:
            raise StructuredFieldError("trailing characters after value")

        return output

    def parse_list(self) -> list:
        members: list = []
        while self.i < self.n:
            members.append(self.parse_item_or_list())
            self.skip_ows()

            if self.i >= self.n:
                return members

            if self.s[self.i] != ",":
                raise StructuredFieldError("expected comma in list")

            self.i += 1
            self.skip_ows()

            if self.i >= self.n:
                raise StructuredFieldError("trailing comma in list")

        return members

    def parse_dict(self) -> dict:
        out: dict = {}
        while self.i < self.n:
            key = self.parse_key()

            if self.i < self.n and self.s[self.i] == "=":
                self.i += 1
                member = self.parse_item_or_list()
            else:
                member = StructuredFieldItem(True, self.parse_params())

            out[key] = member
            self.skip_ows()

            if self.i >= self.n:
                return out

            if self.s[self.i] != ",":
                raise StructuredFieldError("expected comma in dictionary")

            self.i += 1
            self.skip_ows()

            if self.i >= self.n:
                raise StructuredFieldError("trailing comma in dictionary")

        return out

    def parse_item_or_list(self) -> StructuredFieldList | StructuredFieldItem:
        if self.i < self.n and self.s[self.i] == "(":
            return self.parse_inner_list()
        return self.parse_item()

    def parse_inner_list(self) -> StructuredFieldList:
        if self.i >= self.n or self.s[self.i] != "(":
            raise StructuredFieldError("expected inner list")

        self.i += 1
        items: list[StructuredFieldItem] = []

        while self.i < self.n:
            self.skip_sp()

            if self.i < self.n and self.s[self.i] == ")":
                self.i += 1
                return StructuredFieldList(items, self.parse_params())

            items.append(self.parse_item())

            if self.i < self.n and self.s[self.i] not in " )":
                raise StructuredFieldError("expected SP or ) in inner list")

        raise StructuredFieldError("unterminated inner list")

    def parse_item(self) -> StructuredFieldItem:
        value = self.parse_bare_item()
        return StructuredFieldItem(value, self.parse_params())

    def parse_bare_item(self):
        if self.i >= self.n:
            raise StructuredFieldError("empty bare item")

        c = self.s[self.i]

        if c in Characters.DIGIT or c == "-":
            return self.parse_integer_or_decimal()

        if c == '"':
            return self.parse_string()

        if (c.isascii() and c.isalpha()) or c == "*":
            return self.parse_token()

        if c == ":":
            return self.parse_bytes()

        if c == "?":
            return self.parse_boolean()

        raise StructuredFieldError(f"unrecognized bare item: {c!r}")

    def parse_params(self) -> dict:
        params: dict = {}
        while self.i < self.n and self.s[self.i] == ";":
            self.i += 1
            self.skip_sp()

            key = self.parse_key()
            value: object = True
            if self.i < self.n and self.s[self.i] == "=":
                self.i += 1
                value = self.parse_bare_item()

            params[key] = value

        return params

    def parse_key(self) -> str:
        if self.i >= self.n or (self.s[self.i] not in Characters.LOWER and self.s[self.i] != "*"):
            raise StructuredFieldError("invalid key start")
        start = self.i
        while self.i < self.n and self.s[self.i] in CHARS_KEY:
            self.i += 1
        return self.s[start:self.i]

    def parse_integer_or_decimal(self):
        kind = "integer"
        sign = 1

        if self.s[self.i] == "-":
            sign = -1
            self.i += 1

        if self.i >= self.n or self.s[self.i] not in Characters.DIGIT:
            raise StructuredFieldError("empty integer")

        num = ""
        while self.i < self.n:
            c = self.s[self.i]

            if c in Characters.DIGIT:
                num += c
                self.i += 1

            elif kind == "integer" and c == ".":
                if len(num) > 12:
                    raise StructuredFieldError("too many integer digits before decimal")

                num += c
                kind = "decimal"
                self.i += 1

            else:
                break

            if kind == "integer" and len(num) > 15:
                raise StructuredFieldError("integer too long")

            if kind == "decimal" and len(num) > 16:
                raise StructuredFieldError("decimal too long")

        if kind == "integer":
            return sign * int(num)

        if num.endswith("."):
            raise StructuredFieldError("decimal ends with dot")

        if len(num) - num.index(".") - 1 > 3:
            raise StructuredFieldError("too many fractional digits")

        return Decimal(num) * sign

    def parse_string(self) -> str:
        if self.s[self.i] != '"':
            raise StructuredFieldError("expected string")

        self.i += 1
        out: list[str] = []

        while self.i < self.n:
            c = self.s[self.i]
            self.i += 1

            if c == "\\":
                if self.i >= self.n:
                    raise StructuredFieldError("trailing backslash in string")

                nxt = self.s[self.i]
                self.i += 1

                if nxt not in ('"', "\\"):
                    raise StructuredFieldError("invalid escape in string")

                out.append(nxt)

            elif c == '"':
                return "".join(out)

            elif ord(c) < 0x20 or ord(c) > 0x7E:
                raise StructuredFieldError("invalid character in string")

            else:
                out.append(c)

        raise StructuredFieldError("unterminated string")

    def parse_token(self) -> StructuredFieldToken:
        start = self.i
        self.i += 1

        while self.i < self.n and (self.s[self.i] in CHARS_TOKEN or self.s[self.i] in ":/"):
            self.i += 1

        return StructuredFieldToken(self.s[start:self.i])

    def parse_bytes(self) -> bytes:
        if self.s[self.i] != ":":
            raise StructuredFieldError("expected byte sequence")

        self.i += 1
        end = self.s.find(":", self.i)

        if end == -1:
            raise StructuredFieldError("unterminated byte sequence")

        b64 = self.s[self.i:end]
        self.i = end + 1

        if any(ch not in Characters.BASE64 for ch in b64):
            raise StructuredFieldError("invalid base64 in byte sequence")

        padded = b64 + "=" * (-len(b64) % 4)
        try:
            return base64.b64decode(padded)
        except Exception as exc:
            raise StructuredFieldError("base64 decode failed") from exc

    def parse_boolean(self) -> bool:
        if self.s[self.i] != "?":
            raise StructuredFieldError("expected boolean")

        self.i += 1
        if self.i < self.n and self.s[self.i] == "1":
            self.i += 1
            return True

        if self.i < self.n and self.s[self.i] == "0":
            self.i += 1
            return False

        raise StructuredFieldError("invalid boolean")

    def skip_sp(self):
        while self.i < self.n and self.s[self.i] == " ":
            self.i += 1

    def skip_ows(self):
        while self.i < self.n and self.s[self.i] in " \t":
            self.i += 1

class StructuredFieldSerializer:
    @staticmethod
    def serialize(value) -> str:
        if isinstance(value, dict):
            return StructuredFieldSerializer.serialize_dict(value)
        if isinstance(value, list):
            return ", ".join(StructuredFieldSerializer.serialize_member(member) for member in value)
        return StructuredFieldSerializer.serialize_item(value)

    @staticmethod
    def serialize_dict(value: dict) -> str:
        out: list[str] = []

        for key, member in value.items():
            member = StructuredFieldSerializer.as_item_or_list(member)

            if isinstance(member, StructuredFieldItem) and member.value is True:
                out.append(StructuredFieldSerializer.serialize_key(key) + StructuredFieldSerializer.serialize_params(member.params))
            else:
                out.append(StructuredFieldSerializer.serialize_key(key) + "=" + StructuredFieldSerializer.serialize_member(member))

        return ", ".join(out)

    @staticmethod
    def serialize_item(item) -> str:
        return StructuredFieldSerializer.serialize_member(StructuredFieldSerializer.as_item_or_list(item))

    @staticmethod
    def serialize_key(key: str) -> str:
        if not key or (key[0] not in Characters.LOWER and key[0] != "*"):
            raise StructuredFieldError("invalid key")
        if any(ch not in CHARS_KEY for ch in key):
            raise StructuredFieldError("invalid key character")
        return key

    @staticmethod
    def serialize_params(params: dict) -> str:
        out: list[str] = []
        for key, val in params.items():
            out.append(";" + StructuredFieldSerializer.serialize_key(key))
            if val is not True:
                out.append("=" + StructuredFieldSerializer.serialize_bare_item(val))
        return "".join(out)

    @staticmethod
    def serialize_member(member) -> str:
        member = StructuredFieldSerializer.as_item_or_list(member)
        if isinstance(member, StructuredFieldList):
            return StructuredFieldSerializer.serialize_list(member)
        return StructuredFieldSerializer.serialize_item(member)

    @staticmethod
    def serialize_list(inner: StructuredFieldList) -> str:
        parts = [StructuredFieldSerializer.serialize_item(StructuredFieldSerializer.as_item_or_list(it)) for it in inner.items]
        return "(" + " ".join(parts) + ")" + StructuredFieldSerializer.serialize_params(inner.params)

    @staticmethod
    def serialize_item(item: StructuredFieldItem) -> str:
        return StructuredFieldSerializer.serialize_bare_item(item.value) + StructuredFieldSerializer.serialize_params(item.params)

    @staticmethod
    def serialize_bare_item(value) -> str:
        if isinstance(value, bool):
            return "?1" if value else "?0"
        if isinstance(value, StructuredFieldToken):
            return StructuredFieldSerializer.serialize_token(value)
        if isinstance(value, int):
            return StructuredFieldSerializer.serialize_integer(value)
        if isinstance(value, Decimal) or isinstance(value, float):
            return StructuredFieldSerializer.serialize_decimal(value)
        if isinstance(value, str):
            return StructuredFieldSerializer.serialize_string(value)
        if isinstance(value, (bytes, bytearray)):
            return StructuredFieldSerializer.serialize_bytes(bytes(value))
        raise StructuredFieldError(f"cannot serialize bare item of type {type(value).__name__}")

    @staticmethod
    def serialize_bytes(value: bytes) -> str:
        return ":" + base64.b64encode(value).decode("ascii") + ":"

    @staticmethod
    def serialize_integer(value: int) -> str:
        if not (-999_999_999_999_999 <= value <= 999_999_999_999_999):
            raise StructuredFieldError("integer out of range")
        return str(value)

    @staticmethod
    def serialize_decimal(value: Decimal | float) -> str:
        d = value if isinstance(value, Decimal) else Decimal(str(value))
        d = d.quantize(Decimal("0.001"), rounding=ROUND_HALF_EVEN)
        neg = d < 0
        text = format(abs(d), "f")
        if "." not in text:
            text += ".0"
        int_part, frac = text.split(".")
        if len(int_part) > 12:
            raise StructuredFieldError("decimal integer part too long")
        frac = frac.rstrip("0") or "0"
        return ("-" if neg else "") + int_part + "." + frac

    @staticmethod
    def serialize_string(value: str) -> str:
        out = ['"']
        for ch in value:
            if ord(ch) < 0x20 or ord(ch) > 0x7E:
                raise StructuredFieldError("invalid character in string")
            if ch in ('"', "\\"):
                out.append("\\")
            out.append(ch)
        out.append('"')
        return "".join(out)

    @staticmethod
    def serialize_token(value: str) -> str:
        if not value or ((not value[0].isascii() or not value[0].isalpha()) and value[0] != "*"):
            raise StructuredFieldError("invalid token")
        if any(ch not in CHARS_TOKEN and ch not in ":/" for ch in value[1:]):
            raise StructuredFieldError("invalid token character")
        return value

    @staticmethod
    def as_item_or_list(member):
        if isinstance(member, (StructuredFieldItem, StructuredFieldList)):
            return member
        return StructuredFieldItem(member, {})

class FieldValue:
    @staticmethod
    def is_token(value: str) -> bool:
        return bool(value) and all(ch in CHARS_TOKEN for ch in value)

    @staticmethod
    def parse_parameters(value: str) -> tuple[str, dict[str, str]]:
        from ..common import unquote, split_semicolons

        segments = split_semicolons(value)
        head = segments[0].strip()
        params: dict[str, str] = {}

        for seg in segments[1:]:
            seg = seg.strip()
            if not seg:
                continue

            name, eq, raw = seg.partition("=")
            name = name.strip().lower()
            if not name:
                continue

            params[name] = unquote(raw.strip()) if eq else ""

        return head, params

    @staticmethod
    def parse_qvalue(value: str) -> float:
        try:
            return max(0.0, min(1.0, float(value)))
        except (ValueError, TypeError):
            return 0.0

    @staticmethod
    def parse_qlist(value: str) -> list[tuple[str, float, dict]]:
        from ..common import split_list

        result: list[tuple[str, float, dict]] = []

        for element in split_list(value):
            head, params = FieldValue.parse_parameters(element)
            if not head:
                continue

            q = FieldValue.parse_qvalue(params.pop("q", "1"))

            result.append((head, q, params))

        return result
