"""Step 8.5: scenario learning data, cards, stages, and escaping."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from streamlit.testing.v1 import AppTest

from elpa.learning import LearningScenario, LearningStage, load_learning

ROOT = Path(__file__).resolve().parents[1]
APP = str(ROOT / "app.py")
LEARNING_YAML = ROOT / "learning.yaml"
SAMPLES = Path.home() / "orca/easy-log-packet-analyzer/.samples"


def _strings(app: AppTest) -> list[str]:
    values: list[str] = []
    for name in (
        "title",
        "header",
        "subheader",
        "markdown",
        "caption",
        "text",
        "code",
        "info",
        "warning",
        "error",
        "success",
    ):
        values.extend(str(element.value) for element in getattr(app, name))
    values.extend(element.label for element in app.expander)
    return values


def _click(app: AppTest, label: str) -> AppTest:
    button = next(
        item for item in app.button if item.label == label and not item.disabled
    )
    return button.click().run(timeout=30)


def _scenario(scenario_id: str, kinds: tuple[str, ...] = ("cause", "evidence", "result")):
    return {
        "id": scenario_id,
        "title": f"{scenario_id} 제목",
        "sample": "샘플",
        "example_only": False,
        "stages": [
            {"kind": kind, "title": kind, "text": f"{kind} 내용"} for kind in kinds
        ],
    }


def _write_learning(tmp_path: Path, scenarios: list[dict]) -> Path:
    path = tmp_path / "learning.yaml"
    path.write_text(
        yaml.safe_dump({"scenarios": scenarios}, allow_unicode=True), encoding="utf-8"
    )
    return path


def test_learning_data_classes_match_design():
    stage = LearningStage("cause", "원인", "설명", ("줄",))
    scenario = LearningScenario("id", "제목", "샘플", False, (stage,))

    assert (stage.kind, stage.title, stage.text, stage.lines) == (
        "cause",
        "원인",
        "설명",
        ("줄",),
    )
    assert (scenario.id, scenario.title, scenario.sample, scenario.example_only) == (
        "id",
        "제목",
        "샘플",
        False,
    )
    assert scenario.stages == (stage,)


def test_learning_yaml_has_four_ordered_three_stage_scenarios():
    scenarios, notices = load_learning(LEARNING_YAML)

    assert notices == []
    assert [scenario.id for scenario in scenarios] == [
        "ssh_repeated_fail",
        "dns_query_answer",
        "web_404",
        "udp_one_side",
    ]
    for scenario in scenarios:
        assert isinstance(scenario, LearningScenario)
        assert [stage.kind for stage in scenario.stages] == [
            "cause",
            "evidence",
            "result",
        ]
        assert all(isinstance(stage, LearningStage) for stage in scenario.stages)

    example = next(item for item in scenarios if item.id == "udp_one_side")
    assert example.example_only is True
    assert example.sample == "교육용 예시"
    assert all(not item.example_only for item in scenarios if item.id != "udp_one_side")


def test_invalid_scenario_is_skipped_with_one_notice(tmp_path):
    path = _write_learning(
        tmp_path,
        [
            _scenario("one"),
            _scenario("two"),
            _scenario("three"),
            _scenario("bad", kinds=("cause", "evidence")),
        ],
    )

    scenarios, notices = load_learning(path)

    assert [item.id for item in scenarios] == ["one", "two", "three"]
    assert len(notices) == 1


@pytest.mark.parametrize(
    "stages",
    [
        (
            {"kind": "evidence", "title": "생기는 패킷", "text": "내용"},
            {"kind": "cause", "title": "원인", "text": "내용"},
            {"kind": "result", "title": "결과", "text": "내용"},
        ),
        (
            {"kind": "cause", "title": "원인", "text": "내용"},
            {"kind": "evidence", "title": "생기는 패킷", "text": "내용"},
        ),
    ],
)
def test_wrong_stage_order_or_count_is_skipped(tmp_path, stages):
    good = _scenario("good")
    bad = {**_scenario("bad"), "stages": list(stages)}

    scenarios, notices = load_learning(_write_learning(tmp_path, [good, bad]))

    assert [item.id for item in scenarios] == ["good"]
    assert len(notices) == 1


def test_missing_or_malformed_learning_file_shows_no_scenarios(tmp_path):
    missing_scenarios, missing_notices = load_learning(tmp_path / "missing.yaml")

    broken = tmp_path / "broken.yaml"
    broken.write_text("scenarios: [", encoding="utf-8")
    broken_scenarios, broken_notices = load_learning(broken)

    assert missing_scenarios == broken_scenarios == ()
    assert "시나리오 없음" in missing_notices
    assert "시나리오 없음" in broken_notices


def test_home_shows_four_cards_without_uploaded_files():
    app = AppTest.from_file(APP).run(timeout=30)

    assert not app.exception
    assert {"시나리오 학습", "분석"} <= {tab.label for tab in app.tabs}
    values = _strings(app)
    assert any("SSH 로그인 실패 반복" in value for value in values)
    assert any("1 / 4" in value for value in values)
    assert any(button.label == "열기" for button in app.button)
    empty_states = {item.value for item in app.info}
    assert len(empty_states) >= 3
    assert all("파일" in value for value in empty_states)


def test_example_only_card_has_text_badge():
    app = AppTest.from_file(APP).run(timeout=30)
    app.session_state["learning_index"] = 3
    app.run(timeout=30)

    values = _strings(app)
    assert any("한쪽 방향만 보이는 UDP" in value for value in values)
    assert any("교육용 예시" in value for value in values)


def test_next_previous_clamp_and_persist():
    app = AppTest.from_file(APP).run(timeout=30)

    assert next(item for item in app.button if item.label == "이전").disabled
    app = _click(app, "다음")
    assert app.session_state["learning_index"] == 1
    assert any("2 / 4" in value for value in _strings(app))

    app.session_state["learning_index"] = 3
    app.run(timeout=30)
    assert next(item for item in app.button if item.label == "다음").disabled
    app.text_input[0].set_value("UTC").run(timeout=30)
    assert app.session_state["learning_index"] == 3
    assert any("4 / 4" in value for value in _strings(app))


def test_card_swiper_return_value_updates_learning_index():
    app = AppTest.from_file(APP).run(timeout=30)
    key = next(
        (name for name in app.session_state if "card" in name and "index" not in name),
        None,
    )
    if key is None:
        pytest.skip("card_swiper value is not exposed through session_state")

    app.session_state[key] = 1
    app.run(timeout=30)

    assert app.session_state["learning_index"] == 1
    assert any("2 / 4" in value for value in _strings(app))

    app.session_state[key] = 2
    app.run(timeout=30)
    assert app.session_state["learning_index"] == 2
    app = _click(app, "이전")
    assert app.session_state["learning_index"] == 1
    assert any("2 / 4" in value for value in _strings(app))


def test_scenario_page_shows_one_stage_at_a_time():
    scenarios, _ = load_learning(LEARNING_YAML)
    scenario = scenarios[0]
    cause, evidence, result = scenario.stages
    app = AppTest.from_file(APP).run(timeout=30)
    app = _click(app, "열기")

    assert app.session_state["learning_open"] == scenario.id
    assert app.session_state["learning_stage"] == 0
    values = _strings(app)
    assert sum("단계 " in value for value in values) == 1
    assert any("단계 1 / 3" in value for value in values)
    assert any(cause.text in value for value in values)
    assert not any(evidence.text in value for value in values)
    assert not any(result.text in value for value in values)
    assert next(item for item in app.button if item.label == "이전").disabled

    app = _click(app, "다음")
    assert app.session_state["learning_stage"] == 1
    values = _strings(app)
    assert any("단계 2 / 3" in value for value in values)
    assert any(evidence.text in value for value in values)
    assert not any(cause.text in value for value in values)

    app = _click(app, "다음")
    assert app.session_state["learning_stage"] == 2
    values = _strings(app)
    assert any("단계 3 / 3" in value for value in values)
    assert any(result.text in value for value in values)
    assert next(item for item in app.button if item.label == "다음").disabled


def test_restart_returns_to_card_home():
    app = AppTest.from_file(APP).run(timeout=30)
    app = _click(app, "열기")
    app = _click(app, "처음으로")

    assert app.session_state["learning_open"] is None
    assert app.session_state["learning_stage"] == 0
    assert any("1 / 4" in value for value in _strings(app))


def test_missing_scenarios_keeps_analysis_tabs_working(monkeypatch):
    import elpa.learning as learning

    monkeypatch.setattr(
        learning, "load_learning", lambda *args, **kwargs: ((), ["시나리오 없음"])
    )
    app = AppTest.from_file(APP).run(timeout=30)

    assert not app.exception
    assert any("시나리오 없음" in value for value in _strings(app))
    assert any("로그 파일을 올리면" in value for value in _strings(app))
    assert any("패킷 파일을 올리면" in value for value in _strings(app))


def test_learning_text_is_html_escaped(monkeypatch):
    import elpa.learning as learning

    def fake_load_learning(*args, **kwargs):
        malicious = LearningStage(
            "cause", "<script>c</script>", "<script>t</script>", ("<script>l</script>",)
        )
        scenario = LearningScenario(
            "x",
            "<script>x</script>",
            "샘플",
            False,
            (
                malicious,
                LearningStage("evidence", "e", "e", ()),
                LearningStage("result", "r", "r", ()),
            ),
        )
        return (scenario,), []

    monkeypatch.setattr(learning, "load_learning", fake_load_learning)
    app = AppTest.from_file(APP).run(timeout=30)

    assert not app.exception
    values = _strings(app)
    assert any("&lt;script&gt;x&lt;/script&gt;" in value for value in values)
    assert not any("<script>" in value for value in values)

    app = _click(app, "열기")
    values = _strings(app)
    assert any("&lt;script&gt;t&lt;/script&gt;" in value for value in values)
    assert any("&lt;script&gt;l&lt;/script&gt;" in value for value in values)
    assert not any("<script>" in value for value in values)


@pytest.mark.skipif(not SAMPLES.is_dir(), reason="public samples are unavailable")
def test_learning_numbers_match_public_samples():
    openssh = (SAMPLES / "OpenSSH_2k.log").read_text(
        encoding="utf-8", errors="replace"
    )
    failed_for_ip = [
        line
        for line in openssh.splitlines()
        if "Failed password for" in line and "183.62.140.253" in line
    ]
    apache = (SAMPLES / "apache_logs").read_text(encoding="utf-8", errors="replace")
    not_found = [
        line
        for line in apache.splitlines()
        if len(parts := line.split()) > 8 and parts[8] == "404"
    ]
    text = LEARNING_YAML.read_text(encoding="utf-8")

    assert len(failed_for_ip) == 286
    assert len(not_found) == 213
    assert "286" in text
    assert "213" in text
