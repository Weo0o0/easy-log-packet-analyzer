"""Step 8 acceptance tests: ColumnChoice, table_rows, to_csv, and export command translation."""

from __future__ import annotations

import csv
import dataclasses
import io
from pathlib import Path

import pytest

from elpa.conversations import build_conversations
from elpa.export import (
    CONVERSATION_COLUMNS,
    LOG_COLUMNS,
    PACKET_COLUMNS,
    ColumnChoice,
    table_rows,
    to_awk_columns,
    to_csv,
    to_export_command,
    to_tshark_fields,
    to_zeek_cut,
    untranslated_columns,
)
from elpa.filters import FilterCond, apply_filters, load_filters
from elpa.models import Record
from elpa.pcap_reader import read_pcap
from elpa.text_reader import read_text_log
from elpa.timeline import TimeSettings

ROOT = Path(__file__).resolve().parents[1]
FILTERS_YAML = ROOT / "filters.yaml"


def test_column_choice_is_frozen_dataclass() -> None:
    choice = ColumnChoice("로그", ["출발지", "상태"])
    assert choice.tab == "로그"
    assert choice.columns == ("출발지", "상태")
    with pytest.raises(dataclasses.FrozenInstanceError):
        choice.tab = "패킷"  # type: ignore[misc]


def test_apache_logs_csv_srcip_and_status_matches_awk_line_by_line(
    apache_log: Path,
) -> None:
    records = read_text_log(str(apache_log), "access").records
    assert len(records) == 10_000

    choice = ColumnChoice("로그", ("출발지", "상태"))
    rows = table_rows(records, choice, TimeSettings())
    csv_bytes = to_csv(rows, choice)
    assert csv_bytes.startswith(b"\xef\xbb\xbf")

    lines = csv_bytes.decode("utf-8-sig").splitlines()
    assert lines[0] == "출발지,상태"
    body_lines = lines[1:]
    assert len(body_lines) == 10_000

    with apache_log.open(encoding="utf-8") as f:
        awk_lines = [
            f"{parts[0]},{parts[8]}"
            for line in f
            if (parts := line.split())
        ]

    assert len(awk_lines) == 10_000
    diffs = [
        (idx, got, expected)
        for idx, (got, expected) in enumerate(zip(body_lines, awk_lines), start=1)
        if got != expected
    ]
    assert diffs == []
    assert body_lines == awk_lines


def test_dns_cap_packet_csv_has_38_rows(dns_cap: Path) -> None:
    records = read_pcap(str(dns_cap)).records
    choice = ColumnChoice("패킷", PACKET_COLUMNS)
    rows = table_rows(records, choice, TimeSettings())
    assert len(rows) == 38
    assert list(rows[0].keys()) == list(PACKET_COLUMNS)

    csv_bytes = to_csv(rows, choice)
    assert csv_bytes.startswith(b"\xef\xbb\xbf")
    parsed_rows = list(csv.reader(io.StringIO(csv_bytes.decode("utf-8-sig"))))
    assert parsed_rows[0] == list(PACKET_COLUMNS)
    assert len(parsed_rows) - 1 == 38


def test_table_rows_reuses_step5_time_display_and_conversations(
    openssh_log: Path, dns_cap: Path
) -> None:
    sshd_record = read_text_log(str(openssh_log), "sshd").records[0]
    rows_utc = table_rows(
        [sshd_record],
        ("시간", "출발지", "상태"),
        TimeSettings(log_tz="UTC", sshd_year=2026),
    )
    rows_seoul = table_rows(
        [sshd_record],
        ("시간", "출발지", "상태"),
        TimeSettings(log_tz="Asia/Seoul", sshd_year=2026),
    )
    assert rows_utc[0]["시간"] == "2026-12-10 15:55:46"
    assert rows_seoul[0]["시간"] == "2026-12-10 06:55:46"
    assert list(rows_utc[0].keys()) == ["시간", "출발지", "상태"]

    conversations = build_conversations(read_pcap(str(dns_cap)).records)
    conv_rows = table_rows(conversations, ("대화", "출발지:포트", "상태"), TimeSettings())
    assert len(conv_rows) == 8
    assert conv_rows[0]["대화"] == "udp-0"
    assert list(conv_rows[0].keys()) == ["대화", "출발지:포트", "상태"]

    assert len(LOG_COLUMNS) == 8
    assert len(CONVERSATION_COLUMNS) == 9


def test_csv_preserves_screen_row_order_after_step6_filter() -> None:
    records = [
        Record(1, "access.log", {"srcip": "10.0.0.1", "status": "200"}, ""),
        Record(2, "access.log", {"srcip": "10.0.0.2", "status": "404"}, ""),
        Record(3, "access.log", {"srcip": "10.0.0.3", "status": "404"}, ""),
    ]
    filtered = apply_filters(records, [FilterCond("status", "==", "404")])
    rows = table_rows(filtered, ("번호", "출발지", "상태"), TimeSettings())
    csv_text = to_csv(rows, ("번호", "출발지", "상태")).decode("utf-8-sig")
    assert csv_text.splitlines() == [
        "번호,출발지,상태",
        "2,10.0.0.2,404",
        "3,10.0.0.3,404",
    ]


@pytest.mark.parametrize(
    ("raw_value", "expected"),
    [
        ("=1+1", "'=1+1"),
        ("+SUM(A1:A2)", "'+SUM(A1:A2)"),
        ("-10+20", "'-10+20"),
        ("@cmd|'/c calc'!A0", "'@cmd|'/c calc'!A0"),
        ("normal_value", "normal_value"),
    ],
)
def test_formula_injection_guard_and_utf8_bom(raw_value: str, expected: str) -> None:
    csv_bytes = to_csv([{"요약": raw_value}], ("요약",))
    assert csv_bytes.startswith(b"\xef\xbb\xbf")
    parsed = list(csv.reader(io.StringIO(csv_bytes.decode("utf-8-sig"))))
    assert parsed == [["요약"], [expected]]


def test_command_translations_and_untranslated_columns() -> None:
    table = load_filters(FILTERS_YAML)

    assert (
        to_tshark_fields(("출발지", "목적지"), table, "dns.cap")
        == "tshark -r dns.cap -T fields -E separator=, -e ip.src -e ip.dst"
    )
    assert (
        to_zeek_cut(("출발지", "목적지", "종류"), table)
        == "zeek-cut id.orig_h id.resp_h service"
    )
    assert (
        to_awk_columns(("출발지", "상태"), table, "apache_logs")
        == "awk '{print $1\",\"$9}' apache_logs"
    )

    assert untranslated_columns(("출발지", "포트", "요약"), table, "tshark") == (
        "포트",
        "요약",
    )
    tshark_with_missing = to_export_command(
        "tshark", ("출발지", "포트", "요약"), table, "dns.cap"
    )
    assert (
        tshark_with_missing
        == "tshark -r dns.cap -T fields -E separator=, -e ip.src"
    )

    awk_with_missing = to_export_command(
        "awk", ("출발지", "시간", "상태"), table, "apache_logs"
    )
    assert (
        awk_with_missing
        == "awk '{print $1\",\"$9}' apache_logs"
    )

    zeek_with_missing = to_export_command(
        "zeek-cut", ("출발지:포트", "목적지:포트", "종류", "흐름"), table
    )
    assert zeek_with_missing == "zeek-cut service"
    assert untranslated_columns(
        ("출발지:포트", "목적지:포트", "흐름"), table, "zeek-cut"
    ) == ("출발지:포트", "목적지:포트", "흐름")

    assert to_export_command("tshark", ("요약",), table, "dns.cap") is None
    assert to_export_command("awk", ("요약",), table, "apache_logs") is None
    assert to_export_command("zeek-cut", ("요약",), table) is None


def test_export_command_shell_quoting_and_unsafe_yaml_rejection() -> None:
    table = load_filters(FILTERS_YAML)
    assert (
        to_tshark_fields(("출발지",), table, "my capture; id.pcap")
        == "tshark -r 'my capture; id.pcap' -T fields -E separator=, -e ip.src"
    )
    assert (
        to_awk_columns(("출발지", "상태"), table, "access log; rm -rf /")
        == "awk '{print $1\",\"$9}' 'access log; rm -rf /'"
    )

    unsafe_table = {
        "src": {"tshark_e": "ip.src; id", "zeek_cut": "id.orig_h && id"},
        "srcip": {"awk": '$1; system("id")'},
    }
    assert to_tshark_fields(("출발지",), unsafe_table, "dns.cap") is None
    assert to_zeek_cut(("출발지",), unsafe_table) is None
    assert to_awk_columns(("출발지",), unsafe_table, "apache_logs") is None
