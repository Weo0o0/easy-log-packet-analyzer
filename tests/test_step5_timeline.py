"""Step 5 acceptance: record_time / build_timeline / numbers_near (docs/design.md)."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from elpa.pcap_reader import read_pcap
from elpa.text_reader import read_text_log
from elpa.timeline import (
    TimePoint,
    TimeSettings,
    build_timeline,
    numbers_near,
    record_time,
)

EXPECTED_FIRST_TS = 1112172466.496046
_SSHD_PREFIX = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")


def test_dns_cap_packet1_utc_epoch(dns_cap: Path) -> None:
    first = read_pcap(str(dns_cap)).records[0]
    when = record_time(first, "pcap", TimeSettings())
    assert when is not None
    assert when.tzinfo is not None
    assert when.utcoffset() == timedelta(0)
    assert when.timestamp() == pytest.approx(EXPECTED_FIRST_TS, abs=1e-6)


def test_openssh_line1_utc_vs_plus9_differs_by_9h(openssh_log: Path) -> None:
    first = read_text_log(str(openssh_log), "sshd").records[0]
    utc = record_time(first, "sshd", TimeSettings(log_tz="UTC", sshd_year=2023))
    plus9 = record_time(
        first, "sshd", TimeSettings(log_tz="Asia/Seoul", sshd_year=2023)
    )
    assert utc is not None and plus9 is not None
    assert abs((utc.astimezone(timezone.utc) - plus9.astimezone(timezone.utc)).total_seconds()) == 9 * 3600


def test_window_includes_all_lines_with_same_time_string(openssh_log: Path) -> None:
    result = read_text_log(str(openssh_log), "sshd")
    first_raw = result.records[0].raw
    match = _SSHD_PREFIX.match(first_raw)
    assert match is not None
    time_string = match.group(1)
    expected = {
        record.line_number
        for record in result.records
        if record.raw.startswith(time_string)
    }
    assert expected  # counted in-test from the same time string
    settings = TimeSettings(log_tz="Asia/Seoul", sshd_year=2023, window_seconds=5)
    points = build_timeline(result.records, "sshd", settings)
    center = points[0].when
    assert center is not None
    assert expected <= numbers_near(points, center, settings.window_seconds)


def test_when_none_excluded_without_error() -> None:
    center = datetime(2023, 12, 10, 6, 55, 46, tzinfo=ZoneInfo("Asia/Seoul"))
    points = [
        TimePoint("log", 1, None),
        TimePoint("log", 2, center),
        TimePoint("log", 3, center + timedelta(seconds=30)),
    ]
    assert numbers_near(points, center, 5) == {2}


def test_sshd_without_year_is_none(openssh_log: Path) -> None:
    first = read_text_log(str(openssh_log), "sshd").records[0]
    assert record_time(first, "sshd", TimeSettings(sshd_year=None)) is None


def test_build_timeline_preserves_line_order(dns_cap: Path) -> None:
    records = read_pcap(str(dns_cap)).records
    points = build_timeline(records, "pcap", TimeSettings())
    assert [point.number for point in points] == [record.line_number for record in records]
    assert all(point.source == "packet" for point in points)
