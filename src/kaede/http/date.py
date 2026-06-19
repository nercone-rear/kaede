from __future__ import annotations

from datetime import datetime, timezone

DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
DAY_NAMES_LONG = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
MONTH_NAMES = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

MONTHS: dict[str, int] = {name: i + 1 for i, name in enumerate(MONTH_NAMES)}

def parse_time(token: str) -> tuple[int, int, int] | None:
    parts = token.split(":")
    if len(parts) != 3:
        return None
    if not all(len(p) == 2 and p.isdigit() for p in parts):
        return None

    hour, minute, second = int(parts[0]), int(parts[1]), int(parts[2])
    if hour > 23 or minute > 59 or second > 60:
        return None

    return hour, minute, second

def build(year: int, month: int, day: int, hour: int, minute: int, second: int) -> datetime | None:
    if second == 60:
        second = 59
    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        return None

def expand_two_digit_year(two: int) -> int:
    now = datetime.now(timezone.utc).year
    year = now - (now % 100) + two
    while year > now + 50:
        year -= 100
    return year

def parse_imf_fixdate(rest: str) -> datetime | None:
    parts = rest.split(" ")
    if len(parts) != 5 or parts[4] != "GMT":
        return None

    day_s, month_s, year_s, time_s, _ = parts
    if len(day_s) != 2 or not day_s.isdigit() or len(year_s) != 4 or not year_s.isdigit():
        return None

    month = MONTHS.get(month_s)
    tod = parse_time(time_s)
    if month is None or tod is None:
        return None

    return build(int(year_s), month, int(day_s), *tod)

def parse_rfc850(rest: str) -> datetime | None:
    parts = rest.split(" ")
    if len(parts) != 3 or parts[2] != "GMT":
        return None

    date2, time_s, _ = parts
    date_parts = date2.split("-")
    if len(date_parts) != 3:
        return None

    day_s, month_s, year_s = date_parts
    if len(day_s) != 2 or not day_s.isdigit() or len(year_s) != 2 or not year_s.isdigit():
        return None

    month = MONTHS.get(month_s)
    tod = parse_time(time_s)
    if month is None or tod is None:
        return None

    return build(expand_two_digit_year(int(year_s)), month, int(day_s), *tod)

def parse_asctime(value: str) -> datetime | None:
    parts = value.split()
    if len(parts) != 5:
        return None

    day_name, month_s, day_s, time_s, year_s = parts
    if day_name not in DAY_NAMES:
        return None
    if not (1 <= len(day_s) <= 2) or not day_s.isdigit():
        return None
    if len(year_s) != 4 or not year_s.isdigit():
        return None

    month = MONTHS.get(month_s)
    tod = parse_time(time_s)
    if month is None or tod is None:
        return None

    return build(int(year_s), month, int(day_s), *tod)

def parse_http_date(value: str) -> datetime | None:
    if not value:
        return None
    value = value.strip()

    comma = value.find(",")
    if comma == -1:
        return parse_asctime(value)

    day_name = value[:comma]

    rest = value[comma + 1:]
    if not rest.startswith(" "):
        return None

    rest = rest[1:]

    if day_name in DAY_NAMES_LONG:
        return parse_rfc850(rest)

    if day_name in DAY_NAMES:
        head = rest.split(" ", 1)[0]
        if "-" in head:
            return parse_rfc850(rest)

        return parse_imf_fixdate(rest)

    return None

def format_http_date(when: datetime | float | int | None = None) -> str:
    if when is None:
        dt = datetime.now(timezone.utc)
    elif isinstance(when, (int, float)):
        dt = datetime.fromtimestamp(when, tz=timezone.utc)
    else:
        dt = when.astimezone(timezone.utc)

    return "%s, %02d %s %04d %02d:%02d:%02d GMT" % (DAY_NAMES[dt.weekday()], dt.day, MONTH_NAMES[dt.month - 1], dt.year, dt.hour, dt.minute, dt.second)

def http_date_to_timestamp(value: str) -> float | None:
    dt = parse_http_date(value)
    return dt.timestamp() if dt is not None else None
