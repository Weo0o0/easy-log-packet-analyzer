from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

import yaml

from elpa.limits import iter_bounded_lines, open_checked
from elpa.models import ParseResult, Record

_DECODERS_PATH = Path(__file__).resolve().parents[1] / "decoders.yaml"
_MAX_LINE_BYTES = 8192


@lru_cache(maxsize=1)
def _load_config() -> dict:
    with _DECODERS_PATH.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("decoders.yaml 형식이 올바르지 않습니다")
    return data


def _compile_section(section: dict) -> tuple[re.Pattern[str] | None, list[tuple[str, re.Pattern[str] | None, re.Pattern[str], list[str]]]]:
    prefix_s = section.get("prefix") or ""
    prefix = re.compile(prefix_s) if prefix_s else None
    compiled: list[tuple[str, re.Pattern[str] | None, re.Pattern[str], list[str]]] = []
    for dec in section["decoders"]:
        pre_s = dec.get("prematch") or ""
        pre = re.compile(pre_s) if pre_s else None
        compiled.append(
            (
                dec["name"],
                pre,
                re.compile(dec["regex"]),
                list(dec["fields"]),
            )
        )
    return prefix, compiled


def read_text_log(path: str, log_type: str) -> ParseResult:
    """Parse sshd auth.log or Apache access.log via decoders.yaml.

    log_type: \"sshd\" | \"access\"
    """
    section = _load_config().get(log_type)
    if section is None:
        raise ValueError(f"알 수 없는 log_type: {log_type}")
    prefix, decoders = _compile_section(section)

    records: list[Record] = []
    unparsed = 0
    with open_checked(path) as f:
        lines = iter_bounded_lines(f)
        for line_number, line in enumerate(lines, start=1):
            if len(line) > _MAX_LINE_BYTES:
                unparsed += 1
                continue
            raw = line.decode("utf-8", errors="replace").rstrip("\n\r")
            body = raw
            if prefix is not None:
                m = prefix.match(raw)
                if not m:
                    unparsed += 1
                    continue
                body = raw[m.end() :]

            matched = False
            for name, pre, rx, fields in decoders:
                if pre is not None and pre.search(body) is None:
                    continue
                m = rx.search(body)
                if not m:
                    continue
                values = m.groups()
                field_map = {
                    fields[i]: values[i] if i < len(values) else None
                    for i in range(len(fields))
                }
                records.append(
                    Record(line_number=line_number, kind=name, fields=field_map, raw=raw)
                )
                matched = True
                break
            if not matched:
                unparsed += 1

    return ParseResult(records=records, unparsed=unparsed)
