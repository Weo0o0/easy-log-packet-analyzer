"""Step 6: record filtering and Wireshark/tshark/awk command translation."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path

import yaml

from elpa.limits import open_checked, read_bounded
from elpa.models import Record

_FILTERS_PATH = Path(__file__).resolve().parents[1] / "filters.yaml"
_SAFE_VALUE = re.compile(r"^[A-Za-z0-9._:-]+$")
_SAFE_AWK_COL = re.compile(r"^\$[1-9]\d*$")


@dataclass(frozen=True)
class FilterCond:
    field: str
    op: str
    value: str


def load_filters(
    path: str | Path = _FILTERS_PATH, notices: list[str] | None = None
) -> dict:
    """Load filters.yaml via yaml.safe_load; return {} on missing or invalid file."""
    try:
        with open_checked(str(path)) as f:
            raw = read_bounded(f).decode("utf-8")
        data = yaml.safe_load(raw)
    except (OSError, ValueError, UnicodeDecodeError, yaml.YAMLError):
        if notices is not None:
            notices.append("filters.yaml을 읽지 못해 번역 표를 비웠습니다")
        return {}

    if not isinstance(data, dict) or not all(
        isinstance(k, str) and isinstance(v, dict) for k, v in data.items()
    ):
        if notices is not None:
            notices.append("filters.yaml 형식이 올바르지 않아 번역 표를 비웠습니다")
        return {}
    return data


def _matches_cond(record: Record, cond: FilterCond) -> bool:
    if cond.op != "==":
        return False
    if cond.field == "port":
        return (
            record.fields.get("sport") == cond.value
            or record.fields.get("dport") == cond.value
        )
    if cond.field == "kind":
        return (record.fields.get("kind") or record.kind) == cond.value
    if cond.field == "protocol":
        val = record.fields.get("protocol")
        return val is not None and val.lower() == cond.value.lower()
    return record.fields.get(cond.field) == cond.value


def apply_filters(
    records: list[Record], conds: list[FilterCond]
) -> list[Record]:
    """Filter records by AND-combining conditions, preserving original order."""
    if not conds:
        return list(records)
    return [
        record
        for record in records
        if all(_matches_cond(record, cond) for cond in conds)
    ]


def to_wireshark(conds: list[FilterCond], table: dict) -> str | None:
    """Translate conditions into a Wireshark display filter string, or None."""
    if not conds or not isinstance(table, dict):
        return None
    parts: list[str] = []
    for cond in conds:
        if cond.op != "==" or not _SAFE_VALUE.match(cond.value):
            return None
        entry = table.get(cond.field)
        if not isinstance(entry, dict):
            return None
        template = entry.get("wireshark")
        if not isinstance(template, str) or not template:
            return None
        val = cond.value.lower() if cond.field == "protocol" else cond.value
        if ":" in val:
            template = template.replace("ip.src", "ipv6.src").replace(
                "ip.dst", "ipv6.dst"
            )
        part = template.replace("{v}", val)
        parts.append(f"({part})" if len(conds) > 1 and "||" in part else part)
    return " && ".join(parts)


def to_tshark(
    conds: list[FilterCond], table: dict, filename: str
) -> str | None:
    """Build a display-only tshark command string, or None if untranslatable."""
    if not filename or "\x00" in filename:
        return None
    ws = to_wireshark(conds, table)
    if ws is None:
        return None
    return f'tshark -r {shlex.quote(filename)} -Y "{ws}"'


def to_awk(
    conds: list[FilterCond], table: dict, filename: str
) -> str | None:
    """Build a display-only awk command string for access.log, or None."""
    if not conds or not isinstance(table, dict) or not filename or "\x00" in filename:
        return None
    parts: list[str] = []
    for cond in conds:
        if cond.op != "==" or not _SAFE_VALUE.match(cond.value):
            return None
        entry = table.get(cond.field)
        if not isinstance(entry, dict):
            return None
        col = entry.get("awk")
        if not isinstance(col, str) or not _SAFE_AWK_COL.match(col):
            return None
        parts.append(f'{col} == "{cond.value}"')
    expr = " && ".join(parts)
    return f"awk '{expr}' {shlex.quote(filename)}"
