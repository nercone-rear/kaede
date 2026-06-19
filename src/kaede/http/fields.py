from __future__ import annotations

TCHAR = set("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

def split_list(value: str) -> list[str]:
    if not value:
        return []

    elements: list[str] = []
    buf: list[str] = []
    in_quote = False
    escaped = False

    for ch in value:
        if in_quote:
            buf.append(ch)

            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_quote = False

        elif ch == '"':
            in_quote = True
            buf.append(ch)

        elif ch == ",":
            element = "".join(buf).strip()
            if element:
                elements.append(element)
            buf = []

        else:
            buf.append(ch)

    element = "".join(buf).strip()
    if element:
        elements.append(element)

    return elements

def unquote(value: str) -> str:
    if len(value) < 2 or value[0] != '"' or value[-1] != '"':
        return value

    out: list[str] = []
    i = 1
    end = len(value) - 1

    while i < end:
        ch = value[i]
        if ch == "\\" and i + 1 < end:
            out.append(value[i + 1])
            i += 2
        else:
            out.append(ch)
            i += 1

    return "".join(out)

def split_semicolons(value: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    in_quote = False
    escaped = False

    for ch in value:
        if in_quote:
            buf.append(ch)

            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_quote = False

        elif ch == '"':
            in_quote = True
            buf.append(ch)

        elif ch == ";":
            parts.append("".join(buf))
            buf = []

        else:
            buf.append(ch)

    parts.append("".join(buf))
    return parts

def parse_parameters(value: str) -> tuple[str, dict[str, str]]:
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

def parse_qvalue(raw: str) -> float:
    try:
        return max(0.0, min(1.0, float(raw)))
    except (ValueError, TypeError):
        return 0.0

def parse_qlist(value: str) -> list[tuple[str, float, dict[str, str]]]:
    out: list[tuple[str, float, dict[str, str]]] = []

    for element in split_list(value):
        head, params = parse_parameters(element)
        head = head.lower()
        if not head:
            continue

        q = parse_qvalue(params["q"]) if "q" in params else 1.0
        params.pop("q", None)
        out.append((head, q, params))

    return out

def is_token(value: str) -> bool:
    return bool(value) and all(ch in TCHAR for ch in value)

def parse_entity_tag(value: str) -> tuple[bool, str] | None:
    value = value.strip()
    weak = False

    if value.startswith("W/"):
        weak = True
        value = value[2:]

    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return weak, value

    return None

def etag_strong_match(a: str, b: str) -> bool:
    pa, pb = parse_entity_tag(a), parse_entity_tag(b)
    if pa is None or pb is None:
        return False
    return (not pa[0]) and (not pb[0]) and pa[1] == pb[1]

def etag_weak_match(a: str, b: str) -> bool:
    pa, pb = parse_entity_tag(a), parse_entity_tag(b)
    if pa is None or pb is None:
        return False
    return pa[1] == pb[1]
