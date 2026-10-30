"""Step 5: parse record times and find nearby line numbers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from elpa.models import Record

_SSHD_PREFIX = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")


@dataclass(frozen=True)
class TimePoint:
    source: str  # "log" | "packet"
    number: int
    when: datetime | None


@dataclass(frozen=True)
class TimeSettings:
    log_tz: str = "Asia/Seoul"
    sshd_year: int | None = None
    window_seconds: int = 5


def _zone(name: str) -> ZoneInfo | None:
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError:
        return None


def record_time(
    record: Record, kind_group: str, settings: TimeSettings
) -> datetime | None:
    """Parse a record's timestamp. Returns None on failure (never raises)."""
    try:
        if kind_group == "pcap":
            value = record.fields.get("time")
            if not value:
                return None
            return datetime.fromtimestamp(float(value), timezone.utc)

        if kind_group == "access":
            value = record.fields.get("time")
            if not value:
                return None
            return datetime.strptime(str(value), "%d/%b/%Y:%H:%M:%S %z")

        if kind_group == "evtx":
            value = record.fields.get("time")
            if not value:
                return None
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))

        if kind_group == "sshd":
            if settings.sshd_year is None:
                return None
            match = _SSHD_PREFIX.match(record.raw)
            if not match:
                return None
            tz = _zone(settings.log_tz)
            if tz is None:
                return None
            naive = datetime.strptime(
                f"{settings.sshd_year} {match.group(1)}", "%Y %b %d %H:%M:%S"
            )
            return naive.replace(tzinfo=tz)

        return None
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def build_timeline(
    records: list[Record], kind_group: str, settings: TimeSettings
) -> list[TimePoint]:
    source = "packet" if kind_group == "pcap" else "log"
    return [
        TimePoint(
            source=source,
            number=record.line_number,
            when=record_time(record, kind_group, settings),
        )
        for record in records
    ]


def numbers_near(
    points: list[TimePoint], center: datetime, window_seconds: int
) -> set[int]:
    delta = timedelta(seconds=window_seconds)
    low = center - delta
    high = center + delta
    return {
        point.number
        for point in points
        if point.when is not None and low <= point.when <= high
    }
