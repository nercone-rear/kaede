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
