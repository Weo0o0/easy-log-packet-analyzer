"""Study note markdown export."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from html import escape
from pathlib import Path
import re

import yaml

from elpa.rules import Alert

_HELP_PATH = Path(__file__).resolve().parents[1] / "help.yaml"
_MARKDOWN = re.compile(r"([\\`*_{}\[\]()#+.!|>~-])")


@dataclass
class StudyNote:
    file_names: list[str]
    alerts: list[Alert]
    filters: list[str]
    terms: list[str]
    created_at: datetime


def _safe(value: str) -> str:
    return _MARKDOWN.sub(r"\\\1", escape(str(value), quote=True))


def render_note(note: StudyNote) -> str:
    try:
        help_data = yaml.safe_load(_HELP_PATH.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        help_data = {}
    lines = ["# 오늘의 분석 노트", "", "## 파일"]
    lines.extend(f"- {_safe(name)}" for name in note.file_names)
    lines.extend(["", "## 경고"])
    for alert in note.alerts:
        evidence = ", ".join(str(number) for number in alert.evidence)
        lines.append(
            f"- {_safe(alert.msg)} (근거: {evidence}; 신뢰도: {_safe(alert.confidence)})"
        )
    lines.extend(["", "## 쓴 필터"])
    lines.extend(f"- {_safe(value)}" for value in note.filters)
    lines.extend(["", "## 배운 용어"])
    for term in note.terms:
        group, _, key = term.partition(".")
        meaning = help_data.get(group, {}).get(key, "설명 없음")
        lines.append(f"- {_safe(key)}: {_safe(meaning)}")
    lines.extend(["", f"만든 시각: {_safe(note.created_at.isoformat())}"])
    return "\n".join(lines) + "\n"
