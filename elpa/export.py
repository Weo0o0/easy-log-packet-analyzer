"""Step 8: column selection, CSV export with formula-injection guard, and CLI command translation."""

from __future__ import annotations

import csv
import io
import re
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml

from elpa.conversations import Conversation
from elpa.limits import open_checked, read_bounded
from elpa.models import Record
from elpa.timeline import TimeSettings, record_time

_HELP_PATH = Path(__file__).resolve().parents[1] / "help.yaml"
_SEOUL = ZoneInfo("Asia/Seoul")
_SSHD_PREFIX = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
_SAFE_FIELD_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
_SAFE_AWK_COL = re.compile(r"^\$[1-9]\d*$")
_FORMULA_PREFIXES = ("=", "+", "-", "@")

LOG_COLUMNS: tuple[str, ...] = (
    "번호",
    "표시",
    "시간",
    "출발지",
    "사용자",
    "종류",
    "상태",
    "요약",
)
PACKET_COLUMNS: tuple[str, ...] = (
    "번호",
    "표시",
    "시간",
    "출발지",
    "목적지",
    "포트",
    "종류",
    "요약",
)
CONVERSATION_COLUMNS: tuple[str, ...] = (
    "대화",
    "출발지:포트",
    "목적지:포트",
    "종류",
    "상태",
    "지속 시간",
    "패킷 수",
    "바이트 합계",
    "흐름",
)

_FIELD_TO_HEADER: dict[str, str] = {
    "srcip": "출발지",
    "status": "상태",
    "src": "출발지",
    "dst": "목적지",
    "port": "포트",
    "protocol": "종류",
    "time": "시간",
    "user": "사용자",
    "summary": "요약",
}

_PACKET_COL_TO_FILTER: dict[str, str] = {
    "출발지": "src",
    "출발지:포트": "src",
    "목적지": "dst",
    "목적지:포트": "dst",
    "포트": "port",
    "종류": "protocol",
}

_ACCESS_COL_TO_FILTER: dict[str, str] = {
    "출발지": "srcip",
    "상태": "status",
}


@dataclass(frozen=True)
class ColumnChoice:
    tab: str
    columns: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.columns, tuple):
            object.__setattr__(self, "columns", tuple(self.columns))


def _load_help(path: str | Path = _HELP_PATH) -> dict:
    try:
        with open_checked(str(path)) as f:
            raw = read_bounded(f).decode("utf-8")
        data = yaml.safe_load(raw)
    except (OSError, ValueError, UnicodeDecodeError, yaml.YAMLError):
        return {}
    return data if isinstance(data, dict) else {}


def _help_text(help_data: dict, group: str, key: str) -> str:
    group_map = help_data.get(group)
    if isinstance(group_map, dict) and group_map.get(key):
        return str(group_map[key])
    return f"{key}: 설명 없음"


def _format_when(when: datetime | None, *, subsecond: bool = False) -> str:
    if when is None:
        return ""
    local = when.astimezone(_SEOUL)
    if subsecond:
        return local.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    return local.strftime("%Y-%m-%d %H:%M:%S")


def _log_time_display(record: Record, kind_group: str, settings: TimeSettings) -> str:
    when = record_time(record, kind_group, settings)
    if when is not None:
        return _format_when(when)
    if kind_group == "sshd":
        match = _SSHD_PREFIX.match(record.raw)
        return match.group(1) if match else ""
    value = record.fields.get("time")
    return str(value) if value else ""


def build_log_table(
    records: Sequence[Record],
    kind_group: str,
    settings: TimeSettings,
    highlighted: set[int] | None = None,
) -> list[dict[str, str | int]]:
    highlighted = highlighted or set()
    rows: list[dict[str, str | int]] = []
    for record in records:
        fields = record.fields
        state = (
            "실패"
            if "실패" in record.kind
            else "성공"
            if "성공" in record.kind
            else ""
        )
        if fields.get("status"):
            state = str(fields["status"])
        summary = fields.get("message") or record.kind
        if fields.get("method") and fields.get("path"):
            summary = f"{fields['method']} {fields['path']} · {fields.get('status') or ''}"
        elif fields.get("EventID"):
            summary = f"EventID {fields['EventID']}"
        rows.append(
            {
                "번호": record.line_number,
                "표시": "[!] 강조" if record.line_number in highlighted else "",
                "시간": _log_time_display(record, kind_group, settings),
                "출발지": fields.get("srcip") or "",
                "사용자": fields.get("user") or fields.get("TargetUserName") or "",
                "종류": record.kind,
                "상태": state,
                "요약": summary,
            }
        )
    return rows


def _local_packet_time(value: str | None) -> str:
    if not value:
        return ""
    return _format_when(
        datetime.fromtimestamp(float(value), timezone.utc), subsecond=True
    )


def build_packet_table(
    records: Sequence[Record], highlighted: set[int] | None = None
) -> list[dict[str, str | int]]:
    highlighted = highlighted or set()
    return [
        {
            "번호": record.line_number,
            "표시": "[!] 강조" if record.line_number in highlighted else "",
            "시간": _local_packet_time(record.fields.get("time")),
            "출발지": record.fields.get("src") or "",
            "목적지": record.fields.get("dst") or "",
            "포트": ":".join(
                part
                for part in (record.fields.get("sport"), record.fields.get("dport"))
                if part
            ),
            "종류": record.fields.get("protocol") or record.kind,
            "요약": record.fields.get("summary") or "",
        }
        for record in records
    ]


def build_conversation_table(
    conversations: Sequence[Conversation], help_data: dict | None = None
) -> list[dict[str, str | int | float]]:
    resolved_help = _load_help() if help_data is None else help_data
    return [
        {
            "대화": conversation.uid,
            "출발지:포트": conversation.a,
            "목적지:포트": conversation.b,
            "종류": f"{conversation.protocol} ({conversation.service})",
            "상태": f"{conversation.state} ({_help_text(resolved_help, '상태', conversation.state)})",
            "지속 시간": round(conversation.duration, 3),
            "패킷 수": conversation.packets,
            "바이트 합계": conversation.bytes,
            "흐름": " ".join(conversation.history),
        }
        for conversation in conversations
    ]


def _infer_kind_group(record: Record, tab: str | None = None) -> str:
    if tab in ("packet", "pcap", "패킷", "패킷 탭"):
        return "pcap"
    if "transport" in record.fields or "dst" in record.fields:
        return "pcap"
    if record.kind == "access.log" or "method" in record.fields or "status" in record.fields:
        return "access"
    if record.kind == "evtx" or "EventID" in record.fields:
        return "evtx"
    return "sshd"


def _unwrap_columns(columns: ColumnChoice | Sequence[str]) -> tuple[str | None, tuple[str, ...]]:
    if isinstance(columns, ColumnChoice):
        return columns.tab, columns.columns
    return None, tuple(columns)


def table_rows(
    records: Sequence[Record | Conversation | Mapping[str, object]],
    columns: ColumnChoice | Sequence[str],
    settings: TimeSettings | None = None,
    *,
    kind_group: str | None = None,
    highlighted: set[int] | None = None,
) -> list[dict[str, str]]:
    """Build step 4 table rows (with step 5 time settings) and keep only chosen columns."""
    tab, col_names = _unwrap_columns(columns)
    if not records:
        return []
    resolved_settings = settings or TimeSettings()

    first = records[0]
    if isinstance(first, Mapping):
        base_rows: list[Mapping[str, object]] = list(records)  # type: ignore[arg-type]
    elif isinstance(first, Conversation):
        base_rows = build_conversation_table(records)  # type: ignore[arg-type]
    elif isinstance(first, Record):
        group = kind_group or _infer_kind_group(first, tab)
        if group == "pcap":
            base_rows = build_packet_table(records, highlighted=highlighted)  # type: ignore[arg-type]
        else:
            base_rows = build_log_table(
                records, group, resolved_settings, highlighted=highlighted  # type: ignore[arg-type]
            )
    else:
        return []

    out: list[dict[str, str]] = []
    for item, row in zip(records, base_rows):
        filtered_row: dict[str, str] = {}
        for col in col_names:
            if col in row:
                val = row[col]
            elif _FIELD_TO_HEADER.get(col) in row:
                val = row[_FIELD_TO_HEADER[col]]
            elif isinstance(item, Record) and col in item.fields:
                val = item.fields.get(col)
            else:
                val = ""
            filtered_row[col] = "" if val is None else str(val)
        out.append(filtered_row)
    return out


def _sanitize_cell(value: object) -> str:
    text = "" if value is None else str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return f"'{text}"
    return text


def to_csv(
    rows: Sequence[Mapping[str, object]],
    columns: ColumnChoice | Sequence[str],
) -> bytes:
    """Serialize rows and columns to UTF-8 with BOM CSV bytes and formula-injection guard."""
    _, col_names = _unwrap_columns(columns)
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow([_sanitize_cell(col) for col in col_names])
    for row in rows:
        csv_row: list[str] = []
        for col in col_names:
            if col in row:
                val = row[col]
            elif _FIELD_TO_HEADER.get(col) in row:
                val = row[_FIELD_TO_HEADER[col]]
            else:
                val = ""
            csv_row.append(_sanitize_cell(val))
        writer.writerow(csv_row)
    return buf.getvalue().encode("utf-8-sig")


def _resolve_filter_entry(col: str, table: dict, tool: str) -> str | None:
    if not isinstance(table, dict):
        return None
    if tool == "awk":
        field_key = _ACCESS_COL_TO_FILTER.get(col, col)
        entry = table.get(field_key)
        if not isinstance(entry, dict):
            return None
        awk_col = entry.get("awk")
        if isinstance(awk_col, str) and _SAFE_AWK_COL.match(awk_col):
            return awk_col
        return None

    field_key = _PACKET_COL_TO_FILTER.get(col, col)
    entry = table.get(field_key)
    if not isinstance(entry, dict):
        return None
    yaml_key = "tshark_e" if tool == "tshark" else "zeek_cut"
    val = entry.get(yaml_key)
    if isinstance(val, str) and _SAFE_FIELD_NAME.match(val):
        return val
    return None


def _partition_columns(
    columns: ColumnChoice | Sequence[str], table: dict, tool: str
) -> tuple[list[str], list[str]]:
    _, col_names = _unwrap_columns(columns)
    translated: list[str] = []
    missing: list[str] = []
    for col in col_names:
        resolved = _resolve_filter_entry(col, table, tool)
        if resolved is not None:
            translated.append(resolved)
        else:
            missing.append(col)
    return translated, missing


def untranslated_columns(
    columns: ColumnChoice | Sequence[str], table: dict, tool: str
) -> tuple[str, ...]:
    """Return columns that have no translation for tool ('tshark', 'zeek-cut', 'awk')."""
    _, missing = _partition_columns(columns, table, tool)
    return tuple(missing)


def to_tshark_fields(
    columns: ColumnChoice | Sequence[str], table: dict, filename: str
) -> str | None:
    """Build tshark -T fields command for chosen columns, omitting untranslated ones."""
    if not filename or "\x00" in filename:
        return None
    translated, _ = _partition_columns(columns, table, "tshark")
    if not translated:
        return None
    flags = " ".join(f"-e {field}" for field in translated)
    return f"tshark -r {shlex.quote(filename)} -T fields -E separator=, {flags}"


def to_zeek_cut(
    columns: ColumnChoice | Sequence[str], table: dict
) -> str | None:
    """Build zeek-cut command for chosen columns, omitting untranslated ones."""
    translated, _ = _partition_columns(columns, table, "zeek-cut")
    if not translated:
        return None
    return f"zeek-cut {' '.join(translated)}"


def to_awk_columns(
    columns: ColumnChoice | Sequence[str], table: dict, filename: str
) -> str | None:
    """Build awk column print command for access.log, omitting untranslated columns."""
    if not filename or "\x00" in filename:
        return None
    translated, _ = _partition_columns(columns, table, "awk")
    if not translated:
        return None
    joined = '","'.join(translated)
    return f"awk '{{print {joined}}}' {shlex.quote(filename)}"


to_awk_fields = to_awk_columns


def to_export_command(
    tool: str,
    columns: ColumnChoice | Sequence[str],
    table: dict,
    filename: str = "",
) -> str:
    """Build export CLI command string and mark untranslated columns as '번역 없음'."""
    normalized = "zeek-cut" if tool in ("zeek", "zeek-cut", "zeek_cut") else tool
    _, missing = _partition_columns(columns, table, normalized)
    if normalized == "tshark":
        cmd = to_tshark_fields(columns, table, filename)
    elif normalized == "zeek-cut":
        cmd = to_zeek_cut(columns, table)
    elif normalized == "awk":
        cmd = to_awk_columns(columns, table, filename)
    else:
        cmd = None

    if cmd is None:
        return "번역 없음"
    if missing:
        return f"{cmd} (번역 없음: {', '.join(missing)})"
    return cmd


format_export_command = to_export_command
