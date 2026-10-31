from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / ".samples"


def uploaded(name: str, index: int) -> AppTest:
    path = SAMPLES / name
    if not path.is_file():
        pytest.skip(f"sample unavailable: {name}")
    app = AppTest.from_file(str(ROOT / "app.py")).run()
    app.file_uploader[index].set_value((name, path.read_bytes(), "application/octet-stream"))
    return app.run(timeout=30)


def select_row(app: AppTest, key: str, row: int) -> AppTest:
    app.session_state[key] = {"selection": {"rows": [row], "columns": [], "cells": []}}
    return app.run(timeout=30)


def test_packet_layer_help_appears_for_selected_dns_packet():
    app = uploaded("dns.cap", 1)
    app = select_row(app, "packet_table", 0)

    box = next(item.value for item in app.markdown if "elpa-layer-help" in item.value)
    assert "지금 고른 것" in box
    assert box.count("들어 있음") == 4
    for layer_name, token in (
        ("응용 계층", "DNS"),
        ("전송 계층", "UDP"),
        ("IP 계층", "IP"),
        ("링크 계층", "Ethernet"),
    ):
        assert f"[{layer_name}] {token}" in box


def test_conversation_layer_help_shows_app_and_transport_for_dns():
    app = uploaded("dns.cap", 1)
    app = select_row(app, "conversation_table", 0)

    box = next(item.value for item in app.markdown if "elpa-layer-help" in item.value)
    assert "[전송 계층] UDP" in box and "지금 고른 것 (들어 있음)" in box
    assert "[응용 계층] DNS <span>들어 있음</span>" in box


def test_packet_layer_help_is_absent_without_selection():
    app = uploaded("dns.cap", 1)

    assert not any("elpa-layer-help" in item.value for item in app.markdown)


def test_selected_openssh_failure_shows_scenario():
    app = uploaded("OpenSSH_2k.log", 0)
    df = app.dataframe(key="log_table").value
    failed_row = df.index[df["종류"].str.contains("실패")][0]
    app = select_row(app, "log_table", int(failed_row))

    assert any("SSH 로그인 실패 기록" in item.value for item in app.markdown)

    other_row = df.index[df["종류"] == "sshd"][0]
    app = select_row(app, "log_table", int(other_row))
    box = next(item.value for item in app.markdown if "elpa-layer-help" in item.value)
    assert box.count("이 기록에 맞는 예시 상황: 설명 없음") == 1
