"""Step 8.5: scenario learning cards."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from elpa.limits import open_checked, read_bounded

_LEARNING_PATH = Path(__file__).resolve().parents[1] / "learning.yaml"
_KINDS = ("cause", "evidence", "result")


@dataclass(frozen=True)
class LearningStage:
    kind: str
    title: str
    text: str
    lines: tuple[str, ...] = ()


@dataclass(frozen=True)
class LearningScenario:
    id: str
    title: str
    sample: str
    example_only: bool
    stages: tuple[LearningStage, ...]


def load_learning(path: str | Path = _LEARNING_PATH) -> tuple[tuple[LearningScenario, ...], list[str]]:
    notices: list[str] = []
    try:
        with open_checked(str(path)) as file:
            data = yaml.safe_load(read_bounded(file).decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError, yaml.YAMLError):
        return (), ["시나리오 없음"]
    raw = data.get("scenarios") if isinstance(data, dict) else None
    if not isinstance(raw, list):
        return (), ["시나리오 없음"]
    scenarios: list[LearningScenario] = []
    for index, item in enumerate(raw, 1):
        stages = item.get("stages") if isinstance(item, dict) else None
        valid = (
            isinstance(item, dict)
            and isinstance(item.get("id"), str) and bool(item["id"].strip())
            and isinstance(item.get("title"), str) and bool(item["title"].strip())
            and isinstance(item.get("sample"), str)
            and isinstance(item.get("example_only"), bool)
            and isinstance(stages, list) and len(stages) == 3
            and all(
                isinstance(stage, dict)
                and stage.get("kind") == kind
                and isinstance(stage.get("title"), str)
                and isinstance(stage.get("text"), str)
                and isinstance(stage.get("lines", []), list)
                and all(isinstance(line, str) for line in stage.get("lines", []))
                for stage, kind in zip(stages, _KINDS)
            )
        )
        if not valid:
            notices.append(f"learning.yaml {index}번째 시나리오를 건너뛰었습니다")
            continue
        scenarios.append(LearningScenario(
            item["id"], item["title"], item["sample"], item["example_only"],
            tuple(LearningStage(s["kind"], s["title"], s["text"], tuple(s.get("lines", []))) for s in stages),
        ))
    if not scenarios:
        notices.append("시나리오 없음")
    return tuple(scenarios), notices
