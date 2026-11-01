"""Step 8.5 UI review checks: layout, sub-tabs, alerts, and file-link state."""

from __future__ import annotations

import re
from pathlib import Path

from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]
APP = str(ROOT / "app.py")


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


def _expander_strings(app: AppTest) -> list[str]:
    values: list[str] = []

    def walk(block) -> None:
        if hasattr(block, "value"):
            values.append(str(block.value))
        children = getattr(block, "children", None)
        if isinstance(children, dict):
            for child in children.values():
                walk(child)

    for expander in app.expander:
        walk(expander)
    return values


def _set_subtab(app: AppTest, label: str) -> AppTest:
    for key in list(app.session_state.keys()):
        if key.startswith("sub_"):
            app.session_state[key] = label
    for control in (*app.segmented_control, *app.radio):
        options = list(getattr(control, "options", []) or [])
        if label in options:
            control.set_value(label)
    return app.run(timeout=30)


def _table_key(app: AppTest, table: str) -> str:
    version = app.session_state.get(f"{table}_version", 0)
    return table if version == 0 else f"{table}_{version}"


def _select_row(app: AppTest, table: str, row: int | None = 0) -> AppTest:
    rows = [] if row is None else [row]
    app.session_state[_table_key(app, table)] = {
        "selection": {"rows": rows, "columns": [], "cells": []}
    }
    return app.run(timeout=30)


def _upload(app: AppTest, index: int, name: str, path: Path) -> AppTest:
    app.file_uploader[index].set_value(
        (name, path.read_bytes(), "application/octet-stream")
    )
    return app.run(timeout=30)


def test_upload_widgets_are_not_at_the_top_of_the_body():
    app = AppTest.from_file(APP).run(timeout=30)

    assert not app.exception
    upload_labels = {item.label for item in app.sidebar.file_uploader}
    in_sidebar = {"로그 파일 올리기", "패킷 파일 올리기"} <= upload_labels
    in_expander = any(item.label == "파일 올리기" for item in app.expander)
    assert in_sidebar or in_expander


def test_analysis_tabs_have_three_subtabs():
    app = AppTest.from_file(APP).run(timeout=30)

    labels = [tab.label for tab in app.tabs]
    assert labels.count("요약") == 3
    assert labels.count("표") == 3
    assert labels.count("내보내기·명령어") == 3


def test_only_the_selected_subtab_is_drawn(dns_cap):
    app = AppTest.from_file(APP).run(timeout=30)
    app = _upload(app, 1, "dns.cap", dns_cap)

    assert len(app.dataframe) == 0
    app = _set_subtab(app, "표")
    assert len(app.dataframe) >= 1
    app = _set_subtab(app, "요약")
    assert len(app.dataframe) == 0


def test_warning_list_is_a_summary_with_confidence_labels(openssh_log):
    app = AppTest.from_file(APP).run(timeout=30)
    app = _upload(app, 0, "OpenSSH_2k.log", openssh_log)
    app.number_input[0].set_value(2023).run(timeout=30)

    values = _strings(app)
    summary = next(
        value for value in values if re.search(r"경고 \d+건 · 높음", value)
    )
    numbers = [int(number) for number in re.findall(r"(\d+)", summary)]
    total, high, medium, low, enough, needs_check = numbers
    assert high + medium + low == total
    assert enough + needs_check == total

    cards = [
        item.label
        for item in app.expander
        if re.match(r"^\[(높음|중간|낮음)\]", item.label)
    ]
    assert len(cards) == total
    assert any("[근거 충분]" in label for label in cards)
    assert any("[더 확인 필요]" in label for label in cards)


def test_alert_evidence_stays_inside_expanders(openssh_log):
    app = AppTest.from_file(APP).run(timeout=30)
    app = _upload(app, 0, "OpenSSH_2k.log", openssh_log)
    app.number_input[0].set_value(2023).run(timeout=30)

    evidence = [value for value in _strings(app) if value.startswith("근거:")]
    inside = _expander_strings(app)
    assert all(value in inside for value in evidence)


def test_packet_only_does_not_claim_log_highlight(dns_cap):
    app = AppTest.from_file(APP).run(timeout=30)
    app = _upload(app, 1, "dns.cap", dns_cap)
    app = _set_subtab(app, "표")
    app = _select_row(app, "packet_table")

    assert app.session_state["time_link_from"] == "packet"
    assert "time_center" in app.session_state
    assert not any("로그 탭에서 강조" in item.value for item in app.info)


def test_log_only_does_not_claim_packet_highlight(openssh_log):
    app = AppTest.from_file(APP).run(timeout=30)
    app = _upload(app, 0, "OpenSSH_2k.log", openssh_log)
    app.number_input[0].set_value(2023).run(timeout=30)
    app = _set_subtab(app, "표")
    app = _select_row(app, "log_table")

    assert app.session_state["time_link_from"] == "log"
    assert not any("패킷 탭에서 강조" in item.value for item in app.info)


def test_upload_ids_are_name_and_size(openssh_log, dns_cap):
    app = AppTest.from_file(APP).run(timeout=30)
    app = _upload(app, 0, "OpenSSH_2k.log", openssh_log)
    app = _upload(app, 1, "dns.cap", dns_cap)

    assert "OpenSSH_2k.log" in app.session_state["log_file_id"]
    assert str(openssh_log.stat().st_size) in app.session_state["log_file_id"]
    assert "dns.cap" in app.session_state["packet_file_id"]
    assert str(dns_cap.stat().st_size) in app.session_state["packet_file_id"]


def test_removing_a_file_clears_time_link(openssh_log, dns_cap):
    app = AppTest.from_file(APP).run(timeout=30)
    app = _upload(app, 0, "OpenSSH_2k.log", openssh_log)
    app = _upload(app, 1, "dns.cap", dns_cap)
    app.number_input[0].set_value(2023).run(timeout=30)
    app = _set_subtab(app, "표")
    app = _select_row(app, "log_table")
    assert "time_center" in app.session_state

    app.file_uploader[0].set_value(None).run(timeout=30)

    assert app.session_state["log_file_id"] is None
    assert "time_center" not in app.session_state
    assert "time_link_from" not in app.session_state
    assert not any("강조해 두었습니다" in item.value for item in app.info)


def test_replacing_a_file_clears_time_link(openssh_log, apache_log, dns_cap):
    app = AppTest.from_file(APP).run(timeout=30)
    app = _upload(app, 0, "OpenSSH_2k.log", openssh_log)
    app = _upload(app, 1, "dns.cap", dns_cap)
    app.number_input[0].set_value(2023).run(timeout=30)
    app = _set_subtab(app, "표")
    app = _select_row(app, "packet_table")
    assert "time_center" in app.session_state

    app.file_uploader[0].set_value(
        ("apache_logs", apache_log.read_bytes(), "application/octet-stream")
    ).run(timeout=30)

    assert "apache_logs" in app.session_state["log_file_id"]
    assert "time_center" not in app.session_state
    assert "time_link_from" not in app.session_state
