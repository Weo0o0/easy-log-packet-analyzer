"""Step 7: rule-based alert cards with sliding window and confidence checks."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import yaml

from elpa.filters import FilterCond, apply_filters
from elpa.limits import open_checked, read_bounded
from elpa.models import ParseResult, Record
from elpa.timeline import TimeSettings, record_time

_RULES_PATH = Path(__file__).resolve().parents[1] / "rules.yaml"
_VALID_TARGETS = frozenset({"sshd", "access", "evtx", "pcap"})
_VALID_LEVELS = frozenset({"높음", "중간", "낮음"})
_ALLOWED_KEYS = frozenset({
    "id",
    "version",
    "대상",
    "target",
    "조건",
    "conditions",
    "count",
    "seconds",
    "track",
    "unique",
    "중복 억제",
    "suppress",
    "level",
    "category",
    "msg",
    "왜 이상한가",
    "why",
    "다음 단계",
    "next_steps",
    "wireshark_filter",
    "오해 주의",
    "caution",
    "suricata_example",
})


@dataclass(frozen=True)
class Rule:
    id: str
    version: int
    target: str
    conditions: tuple[FilterCond, ...]
    count: int
    seconds: int
    track: str
    unique: str | None = None
    suppress: int = 0
    level: str = "중간"
    category: str = ""
    msg: str = ""
    why: str = ""
    next_steps: str = ""
    wireshark_filter: str = ""
    caution: str = ""
    suricata_example: str = ""

    @property
    def 대상(self) -> str:
        return self.target

    @property
    def 조건(self) -> tuple[FilterCond, ...]:
        return self.conditions

    @property
    def 중복_억제(self) -> int:
        return self.suppress

    @property
    def 왜_이상한가(self) -> str:
        return self.why

    @property
    def 다음_단계(self) -> str:
        return self.next_steps

    @property
    def 오해_주의(self) -> str:
        return self.caution


@dataclass(frozen=True)
class Alert:
    rule_id: str
    track_value: str
    level: str
    category: str
    msg: str
    evidence: tuple[int, ...]
    confidence: str
    confidence_reason: str
    why: str = ""
    next_steps: str = ""
    wireshark_filter: str = ""
    caution: str = ""
    suricata_example: str = ""

    @property
    def 왜_이상한가(self) -> str:
        return self.why

    @property
    def 다음_단계(self) -> str:
        return self.next_steps

    @property
    def 오해_주의(self) -> str:
        return self.caution


def parse_conditions(raw: object) -> tuple[FilterCond, ...] | None:
    if isinstance(raw, dict) and raw:
        out: list[FilterCond] = []
        for k, v in raw.items():
            if not isinstance(k, str) or not k or v is None or isinstance(v, (dict, list)):
                return None
            out.append(FilterCond(k, "==", str(v)))
        return tuple(out)
    if isinstance(raw, list) and raw:
        out = []
        for item in raw:
            if not isinstance(item, dict):
                return None
            if "field" in item and "value" in item:
                op = item.get("op", "==")
                field = item.get("field")
                val = item.get("value")
                if (
                    op != "=="
                    or not isinstance(field, str)
                    or not field
                    or val is None
                    or isinstance(val, (dict, list))
                ):
                    return None
                out.append(FilterCond(field, "==", str(val)))
            elif len(item) == 1:
                (k, v), = item.items()
                if not isinstance(k, str) or not k or v is None or isinstance(v, (dict, list)):
                    return None
                out.append(FilterCond(k, "==", str(v)))
            else:
                return None
        return tuple(out)
    return None


def _is_int(val: object) -> bool:
    return isinstance(val, int) and not isinstance(val, bool)


def _parse_rule(entry: object, index: int) -> tuple[Rule | None, str | None]:
    if not isinstance(entry, dict):
        return None, f"rules.yaml {index}번째 항목이 사전 형식이 아니라 건너뛰었습니다"
    unknown = set(entry.keys()) - _ALLOWED_KEYS
    if unknown:
        names = ", ".join(sorted(map(str, unknown)))
        return None, f"rules.yaml {index}번째 규칙에 알 수 없는 칸({names})이 있어 건너뛰었습니다"

    rule_id = entry.get("id")
    version = entry.get("version", 1)
    target = entry.get("대상") if "대상" in entry else entry.get("target")
    raw_conds = entry.get("조건") if "조건" in entry else entry.get("conditions")
    count = entry.get("count")
    seconds = entry.get("seconds")
    track = entry.get("track")
    unique = entry.get("unique")
    suppress = entry.get("중복 억제", entry.get("suppress", 0))
    if suppress is None:
        suppress = 0
    level = entry.get("level")
    category = entry.get("category")
    msg = entry.get("msg")
    why = entry.get("왜 이상한가") if "왜 이상한가" in entry else entry.get("why")
    next_steps = entry.get("다음 단계") if "다음 단계" in entry else entry.get("next_steps")
    wireshark_filter = entry.get("wireshark_filter") or ""
    caution = entry.get("오해 주의") if "오해 주의" in entry else entry.get("caution")
    suricata_example = entry.get("suricata_example") or ""

    if isinstance(next_steps, list) and all(isinstance(x, str) for x in next_steps):
        next_steps = " / ".join(next_steps)

    conds = parse_conditions(raw_conds)
    if (
        not isinstance(rule_id, str)
        or not rule_id.strip()
        or not _is_int(version)
        or version < 1
        or not isinstance(target, str)
        or target not in _VALID_TARGETS
        or conds is None
        or not _is_int(count)
        or count < 1
        or not _is_int(seconds)
        or seconds < 0
        or not isinstance(track, str)
        or not track.strip()
        or (unique is not None and (not isinstance(unique, str) or not unique.strip()))
        or not _is_int(suppress)
        or suppress < 0
        or not isinstance(level, str)
        or level not in _VALID_LEVELS
        or not isinstance(category, str)
        or not category.strip()
        or not isinstance(msg, str)
        or not msg.strip()
        or not isinstance(why, str)
        or not why.strip()
        or not isinstance(next_steps, str)
        or not next_steps.strip()
        or not isinstance(wireshark_filter, str)
        or not isinstance(caution, str)
        or not caution.strip()
        or not isinstance(suricata_example, str)
    ):
        return None, f"rules.yaml {index}번째 규칙({rule_id or '?'})의 필수 칸이 빠졌거나 잘못되어 건너뛰었습니다"

    return (
        Rule(
            id=rule_id,
            version=version,
            target=target,
            conditions=conds,
            count=count,
            seconds=seconds,
            track=track,
            unique=unique,
            suppress=suppress,
            level=level,
            category=category,
            msg=msg,
            why=why,
            next_steps=next_steps,
            wireshark_filter=wireshark_filter,
            caution=caution,
            suricata_example=suricata_example,
        ),
        None,
    )


def load_rules(
    path: str | Path = _RULES_PATH, notices: list[str] | None = None
) -> tuple[list[Rule], list[str]]:
    """Load rules.yaml via yaml.safe_load; skip invalid rules with notices."""
    out_notices: list[str] = []
    try:
        with open_checked(str(path)) as f:
            raw = read_bounded(f).decode("utf-8")
        data = yaml.safe_load(raw)
    except (OSError, ValueError, UnicodeDecodeError, yaml.YAMLError):
        out_notices.append("rules.yaml을 읽지 못해 규칙 목록을 비웠습니다")
        if notices is not None:
            notices.extend(out_notices)
        return [], out_notices

    if not isinstance(data, list):
        out_notices.append("rules.yaml 형식이 올바르지 않아 규칙 목록을 비웠습니다")
        if notices is not None:
            notices.extend(out_notices)
        return [], out_notices

    rules: list[Rule] = []
    for idx, entry in enumerate(data, start=1):
        rule, err = _parse_rule(entry, idx)
        if err is not None:
            out_notices.append(err)
        elif rule is not None:
            rules.append(rule)

    if notices is not None:
        notices.extend(out_notices)
    return rules, out_notices


def _infer_target(records: Sequence[Record]) -> str | None:
    for r in records:
        if "transport" in r.fields:
            return "pcap"
        if r.kind == "evtx":
            return "evtx"
        if r.kind == "access.log":
            return "access"
        if "sshd" in r.kind:
            return "sshd"
    return None


def _track_value(record: Record, field: str) -> str | None:
    val = record.kind if field == "kind" else record.fields.get(field)
    return val if val else None


def _has_empty_field(record: Record, rule: Rule) -> bool:
    if not record.fields:
        return True
    for k, v in record.fields.items():
        if k == "invalid":
            continue
        if k == "flags" and record.fields.get("transport") != "TCP":
            continue
        if v is None or v == "":
            return True
    if rule.unique and not record.fields.get(rule.unique):
        return True
    return False


def _verify_raw(record: Record, rule: Rule, track_val: str) -> bool:
    if not apply_filters([record], list(rule.conditions)):
        return False
    if _track_value(record, rule.track) != track_val:
        return False
    if rule.target in ("sshd", "access"):
        if not record.raw or track_val not in record.raw:
            return False
        for cond in rule.conditions:
            if cond.field not in ("kind", "port", "protocol") and cond.value not in record.raw:
                return False
    return True


def _window_meets_count(
    window: Sequence[tuple[datetime, Record]], rule: Rule
) -> tuple[bool, int]:
    if rule.unique is None:
        n = len(window)
        return n >= rule.count, n
    uniq = {
        r.fields.get(rule.unique)
        for _, r in window
        if r.fields.get(rule.unique)
    }
    return len(uniq) >= rule.count, len(uniq)


def evaluate_rules(
    records: Sequence[Record] | ParseResult,
    rules: Sequence[Rule] | None = None,
    target: str | TimeSettings | int | None = None,
    settings: TimeSettings | None = None,
    unparsed: int = 0,
) -> list[Alert]:
    """Evaluate rules against records using a two-pointer sliding window."""
    if isinstance(target, TimeSettings) and settings is None:
        settings, target = target, None
    elif _is_int(target) and unparsed == 0:
        unparsed, target = int(target), None
    if isinstance(records, ParseResult):
        unparsed = unparsed or records.unparsed
        rec_list = list(records.records)
    else:
        rec_list = list(records)

    if rules is None:
        rules, _ = load_rules()

    active_settings = (
        settings
        if settings is not None
        else TimeSettings(log_tz="Asia/Seoul", sshd_year=2023)
    )
    active_target = target if isinstance(target, str) else _infer_target(rec_list)
    by_number = {r.line_number: r for r in rec_list}
    alerts: list[Alert] = []

    for rule in rules:
        if active_target is not None and rule.target != active_target:
            continue

        matched = apply_filters(rec_list, list(rule.conditions))
        if not matched:
            continue

        grouped: dict[str, list[tuple[datetime, Record]]] = defaultdict(list)
        untimed_tracks: set[str] = set()
        any_untimed = False
        any_missing_track = False

        for rec in matched:
            tv = _track_value(rec, rule.track)
            if tv is None:
                any_missing_track = True
                continue
            when = record_time(rec, rule.target, active_settings)
            if when is None:
                any_untimed = True
                untimed_tracks.add(tv)
                continue
            grouped[tv].append((when, rec))

        for tv, items in grouped.items():
            items.sort(key=lambda pair: (pair[0], pair[1].line_number))
            windows: list[tuple[int, int]] = []
            left = 0
            for right in range(len(items)):
                while (items[right][0] - items[left][0]).total_seconds() > rule.seconds:
                    left += 1
                ok, _ = _window_meets_count(items[left : right + 1], rule)
                if ok:
                    windows.append((left, right))

            if not windows:
                continue

            clusters: list[list[tuple[int, int]]] = [[windows[0]]]
            for l_idx, r_idx in windows[1:]:
                prev_r = clusters[-1][-1][1]
                gap = (items[l_idx][0] - items[prev_r][0]).total_seconds()
                if l_idx <= prev_r or gap <= rule.suppress:
                    clusters[-1].append((l_idx, r_idx))
                else:
                    clusters.append([(l_idx, r_idx)])

            for cluster in clusters:
                ev_indices = sorted({
                    i for l_idx, r_idx in cluster for i in range(l_idx, r_idx + 1)
                })
                evidence = tuple(items[i][1].line_number for i in ev_indices)
                ev_records = [by_number[num] for num in evidence if num in by_number]

                if rule.unique is None:
                    measured = len(evidence)
                else:
                    measured = len({
                        r.fields.get(rule.unique)
                        for r in ev_records
                        if r.fields.get(rule.unique)
                    })

                reasons: list[str] = []
                if len(ev_records) != len(evidence) or not all(
                    _verify_raw(r, rule, tv) for r in ev_records
                ):
                    reasons.append("원본 레코드 재확인에 실패한 근거가 있습니다")
                if any_missing_track or any(_has_empty_field(r, rule) for r in ev_records):
                    reasons.append("일부 필드가 비어 있습니다")
                if unparsed > 0:
                    reasons.append(f"읽지 못한 줄 {unparsed}개가 있습니다")
                if tv in untimed_tracks or any_untimed:
                    reasons.append("시간을 읽지 못한 레코드가 있습니다")
                if measured <= rule.count:
                    reasons.append(f"근거 수가 기준({rule.count}개)과 딱 같습니다")

                if reasons:
                    confidence = "더 확인 필요"
                    confidence_reason = " · ".join(reasons)
                else:
                    confidence = "근거 충분"
                    confidence_reason = f"조건 모두 일치 · 근거 {len(evidence)}개 · 원본에서 재확인됨"

                ws_filter = rule.wireshark_filter.replace("{track}", tv)
                alerts.append(
                    Alert(
                        rule_id=rule.id,
                        track_value=tv,
                        level=rule.level,
                        category=rule.category,
                        msg=rule.msg,
                        evidence=evidence,
                        confidence=confidence,
                        confidence_reason=confidence_reason,
                        why=rule.why,
                        next_steps=rule.next_steps,
                        wireshark_filter=ws_filter,
                        caution=rule.caution,
                        suricata_example=rule.suricata_example,
                    )
                )

    return alerts
