from pathlib import Path

from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]


def test_log_selection_updates_link_and_highlights_in_same_run(openssh_log, dns_cap):
    app = AppTest.from_file(str(ROOT / "app.py")).run()
    app.file_uploader[0].set_value(
        ("OpenSSH_2k.log", openssh_log.read_bytes(), "application/octet-stream")
    )
    app.file_uploader[1].set_value(
        ("dns.cap", dns_cap.read_bytes(), "application/octet-stream")
    )
    app.run(timeout=30)
    app.number_input[0].set_value(2023).run(timeout=30)

    app.session_state["log_table"] = {"selection": {"rows": [0], "columns": [], "cells": []}}
    app.run(timeout=30)

    assert app.session_state["prev_log_rows"] == [0]
    assert app.session_state["time_link_from"] == "log"
    assert any("로그 탭에서 고른 시각 앞뒤" in item.value for item in app.info)


def test_clearing_log_selection_clears_its_time_link_without_rerun_loop(openssh_log, dns_cap):
    app = AppTest.from_file(str(ROOT / "app.py")).run()
    app.file_uploader[0].set_value(
        ("OpenSSH_2k.log", openssh_log.read_bytes(), "application/octet-stream")
    )
    app.file_uploader[1].set_value(
        ("dns.cap", dns_cap.read_bytes(), "application/octet-stream")
    )
    app.run(timeout=30)
    app.number_input[0].set_value(2023).run(timeout=30)
    app.session_state["log_table"] = {"selection": {"rows": [0], "columns": [], "cells": []}}
    app.run(timeout=30)

    app.session_state["log_table"] = {"selection": {"rows": [], "columns": [], "cells": []}}
    app.run(timeout=30)

    assert app.session_state["prev_log_rows"] == []
    assert "time_center" not in app.session_state
    assert "time_link_from" not in app.session_state
    assert not any("로그 탭에서 고른 시각 앞뒤" in item.value for item in app.info)
