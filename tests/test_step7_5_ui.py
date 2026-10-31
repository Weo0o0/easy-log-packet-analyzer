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

    assert any("elpa-layer-help" in item.value and "지금 고른 것" in item.value for item in app.markdown)
    assert any('data-layer="app"' in item.value and "[응용 계층]" in item.value and "지금 고른 것 (들어 있음)" in item.value for item in app.markdown)


def test_packet_layer_help_is_absent_without_selection():
    app = uploaded("dns.cap", 1)

    assert not any("elpa-layer-help" in item.value for item in app.markdown)


def test_selected_openssh_failure_shows_scenario():
    app = uploaded("OpenSSH_2k.log", 0)
    failed_row = app.dataframe(key="log_table").value.index[
        app.dataframe(key="log_table").value["종류"].str.contains("실패")
    ][0]
    app = select_row(app, "log_table", int(failed_row))

    assert any("SSH 로그인 실패 기록" in item.value for item in app.markdown)
