from pathlib import Path

import yaml
from streamlit.testing.v1 import AppTest

from elpa.learning import load_learning

ROOT = Path(__file__).resolve().parents[1]


def test_learning_yaml_has_four_ordered_three_stage_scenarios():
    scenarios, notices = load_learning(ROOT / "learning.yaml")

    assert notices == []
    assert len(scenarios) == 4
    for scenario in scenarios:
        assert [stage.kind for stage in scenario.stages] == ["cause", "evidence", "result"]
    example = next(item for item in scenarios if item.id == "udp_one_side")
    assert example.example_only
    assert example.sample == "교육용 예시"


def test_invalid_scenario_is_skipped_with_notice(tmp_path):
    path = tmp_path / "learning.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "scenarios": [
                    {
                        "id": "valid",
                        "title": "정상",
                        "sample": "샘플",
                        "example_only": False,
                        "stages": [
                            {"kind": kind, "title": kind, "text": "내용"}
                            for kind in ("cause", "evidence", "result")
                        ],
                    },
                    {
                        "id": "invalid",
                        "title": "잘못된 항목",
                        "sample": "샘플",
                        "example_only": False,
                        "stages": [{"kind": "cause", "title": "원인", "text": "내용"}],
                    },
                ]
            },
            allow_unicode=True,
        ),
        encoding="utf-8",
    )

    scenarios, notices = load_learning(path)

    assert [item.id for item in scenarios] == ["valid"]
    assert len(notices) == 1


def test_missing_or_malformed_learning_file_returns_empty_and_notice(tmp_path):
    missing, missing_notices = load_learning(tmp_path / "missing.yaml")
    malformed_path = tmp_path / "broken.yaml"
    malformed_path.write_text("scenarios: [", encoding="utf-8")
    malformed, malformed_notices = load_learning(malformed_path)

    assert missing == malformed == ()
    assert missing_notices and malformed_notices


def test_scenario_home_renders_without_uploads():
    app = AppTest.from_file(str(ROOT / "app.py")).run(timeout=30)
    visible = "\n".join(
        item.value
        for item in list(app.text) + list(app.caption) + list(app.markdown)
    )

    assert not app.exception
    assert [tab.label for tab in app.tabs][:2] == ["시나리오 학습", "분석"]
    assert app.title[0].value == "easy-log-packet-analyzer"
    assert "SSH 로그인 실패 반복" in visible
    assert "1 / 4" in visible
    assert any(button.label == "열기" for button in app.button)


def test_open_shows_only_one_stage_and_restart_returns_home():
    app = AppTest.from_file(str(ROOT / "app.py")).run(timeout=30)
    app.button(key="learning_open_button").click().run(timeout=30)

    visible = "\n".join(
        item.value
        for item in list(app.text) + list(app.markdown) + list(app.caption)
    )
    assert "단계 1 / 3" in visible
    assert "원인" in visible
    assert sum(
        "단계 " in item.value
        for item in list(app.text) + list(app.markdown) + list(app.caption)
    ) == 1
    assert any(button.label == "처음으로" for button in app.button)

