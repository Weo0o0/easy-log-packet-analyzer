from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Record:
    """One parsed log line / event. line_number is 1-based source order."""

    line_number: int
    kind: str
    fields: dict[str, str | None] = field(default_factory=dict)
    raw: str = ""


@dataclass(frozen=True)
class ParseResult:
    records: list[Record]
    unparsed: int  # 읽지 못한 줄
    notices: list[str] = field(default_factory=list)  # 안내 메시지
    unparsed_lines: list[int] = field(default_factory=list)
