"""Step 7: beginner misconception hints (hints.yaml)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import yaml

from elpa.conversations import Conversation
from elpa.filters import FilterCond, apply_filters
from elpa.limits import open_checked, read_bounded
from elpa.models import Record
from elpa.rules import parse_conditions

_HINTS_PATH = Path(__file__).resolve().parents[1] / "hints.yaml"
_VALID_TARGETS = frozenset({"sshd", "access", "evtx", "pcap", "conversation"})
_ALLOWED_KEYS = frozenset({"id", "대상", "target", "조건", "conditions", "text"})


@dataclass(frozen=True)
class HintRule:
    id: str
    target: str
    conditions: tuple[FilterCond, ...]
    text: str

    @property
    def 대상(self) -> str:
        return self.target

    @property
    def 조건(self) -> tuple[FilterCond, ...]:
        return self.conditions


@dataclass(frozen=True)
class Hint:
    hint_id: str
    target: str
    text: str
    evidence: tuple[int, ...]

    @property
    def id(self) -> str:
        return self.hint_id

    @property
    def 대상(self) -> str:
        return self.target


def _parse_hint_rule(entry: object, index: int) -> tuple[HintRule | None, str | None]:
    if not isinstance(entry, dict):
        return None, f"hints.yaml {index}번째 항목이 사전 형식이 아니라 건너뛰었습니다"
    unknown = set(entry.keys()) - _ALLOWED_KEYS
    if unknown:
        names = ", ".join(sorted(map(str, unknown)))
        return None, f"hints.yaml {index}번째 힌트에 알 수 없는 칸({names})이 있어 건너뛰었습니다"

    hint_id = entry.get("id")
    target = entry.get("대상") if "대상" in entry else entry.get("target")
    raw_conds = entry.get("조건") if "조건" in entry else entry.get("conditions")
    text = entry.get("text")
    conds = parse_conditions(raw_conds)

    if (
        not isinstance(hint_id, str)
        or not hint_id.strip()
        or not isinstance(target, str)
        or target not in _VALID_TARGETS
        or conds is None
        or not isinstance(text, str)
        or not text.strip()
    ):
        return None, f"hints.yaml {index}번째 힌트({hint_id or '?'})의 필수 칸이 빠졌거나 잘못되어 건너뛰었습니다"

    return (
        HintRule(
            id=hint_id,
            target=target,
            conditions=conds,
            text=text,
        ),
        None,
    )


def load_hints(
    path: str | Path = _HINTS_PATH, notices: list[str] | None = None
) -> tuple[list[HintRule], list[str]]:
    """Load hints.yaml via yaml.safe_load; skip invalid entries with notices."""
    out_notices: list[str] = []
    try:
        with open_checked(str(path)) as f:
            raw = read_bounded(f).decode("utf-8")
        data = yaml.safe_load(raw)
    except (OSError, ValueError, UnicodeDecodeError, yaml.YAMLError):
        out_notices.append("hints.yaml을 읽지 못해 힌트 목록을 비웠습니다")
        if notices is not None:
            notices.extend(out_notices)
        return [], out_notices

    if not isinstance(data, list):
        out_notices.append("hints.yaml 형식이 올바르지 않아 힌트 목록을 비웠습니다")
        if notices is not None:
            notices.extend(out_notices)
        return [], out_notices

    hints: list[HintRule] = []
    for idx, entry in enumerate(data, start=1):
        rule, err = _parse_hint_rule(entry, idx)
        if err is not None:
            out_notices.append(err)
        elif rule is not None:
            hints.append(rule)

    if notices is not None:
        notices.extend(out_notices)
    return hints, out_notices


def _conversation_to_record(conv: Conversation, index: int) -> Record:
    return Record(
        line_number=index,
        kind=conv.service,
        fields={
            "uid": conv.uid,
            "protocol": conv.protocol,
            "service": conv.service,
            "stream": str(conv.stream),
            "a": conv.a,
            "b": conv.b,
            "state": conv.state,
            "history": conv.history,
        },
        raw=conv.uid,
    )


def _infer_target(items: Sequence[Record | Conversation]) -> str | None:
    for item in items:
        if isinstance(item, Conversation):
            return "conversation"
        if "transport" in item.fields:
            return "pcap"
        if item.kind == "evtx":
            return "evtx"
        if item.kind == "access.log":
            return "access"
        if "sshd" in item.kind:
            return "sshd"
    return None


def compute_hints(
    items: Sequence[Record | Conversation],
    hint_rules: Sequence[HintRule] | None = None,
    target: str | None = None,
) -> list[Hint]:
    """Compute matching hints for records or conversations using apply_filters."""
    if not items:
        return []
    if hint_rules is None:
        hint_rules, _ = load_hints()

    active_target = target or _infer_target(items)
    is_conv = isinstance(items[0], Conversation)
    if is_conv:
        conv_list: list[Conversation] = list(items)  # type: ignore[arg-type]
        records = [_conversation_to_record(c, i) for i, c in enumerate(conv_list)]
    else:
        conv_list = []
        records = list(items)  # type: ignore[arg-type]

    results: list[Hint] = []
    for rule in hint_rules:
        if active_target is not None and rule.target != active_target:
            continue
        matched = apply_filters(records, list(rule.conditions))
        if not matched:
            continue
        if is_conv:
            ev_nums = sorted({
                pkt_num
                for r in matched
                for pkt_num in (conv_list[r.line_number].packet_numbers or (conv_list[r.line_number].stream + 1,))
            })
            evidence = tuple(ev_nums)
        else:
            evidence = tuple(r.line_number for r in matched)
        results.append(
            Hint(
                hint_id=rule.id,
                target=rule.target,
                text=rule.text,
                evidence=evidence,
            )
        )
    return results


evaluate_hints = compute_hints
