from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app.py"
SAMPLES = ROOT / ".samples"


def run_upload(filename: str, content: bytes, *, log: bool, timeout: float = 3) -> AppTest:
    app = AppTest.from_file(str(APP)).run()
    app.file_uploader[0 if log else 1].set_value(
        (filename, content, "application/octet-stream")
    )
    app.run(timeout=timeout)
    if log and Path(filename).name.startswith("apache"):
        app.selectbox[0].select("access").run(timeout=timeout)
    return app


def sample(name: str) -> Path:
    path = SAMPLES / name
    if not path.is_file():
        pytest.skip(f"sample unavailable: {name}")
    return path


def metric(app: AppTest, label: str) -> str:
    return next(item.value for item in app.metric if item.label == label)


def test_empty_state():
    app = AppTest.from_file(str(APP)).run()

    assert any(item.value == "아직 파일이 없습니다" for item in app.info)
    assert any("로그나 pcap 파일을 올리면" in item.value for item in app.markdown)


@pytest.mark.parametrize(
    ("filename", "expected"),
    [("OpenSSH_2k.log", "520"), ("apache_logs", "213"), ("security.evtx", "583")],
)
def test_log_sample_counts(filename: str, expected: str):
    path = sample(filename)
    app = run_upload(filename, path.read_bytes(), log=True, timeout=20)
    if filename == "OpenSSH_2k.log":
        assert app.dataframe[0].value["종류"].str.contains("실패").sum() == int(expected)
    elif filename == "apache_logs":
        assert (app.dataframe[0].value["상태"] == "404").sum() == int(expected)
    else:
        assert app.dataframe[0].value["요약"].str.contains("EventID 4624").sum() == int(expected)


def test_dns_sample_counts():
    path = sample("dns.cap")
    app = run_upload("dns.cap", path.read_bytes(), log=False, timeout=20)

    assert metric(app, "패킷") == "38"
    assert metric(app, "대화") == "8"
    assert any(item.value == "원본 값: 확인 못 함" for item in app.text)


def test_unparsed_line_numbers_and_truncation():
    content = ("not a supported log line\n" * 1001).encode()
    app = run_upload("bad.log", content, log=True)
    text = [item.value for item in app.text]

    assert any(item.value.startswith("1001줄을 읽지 못했습니다") for item in app.warning)
    assert any(value.startswith("1, 2, 3,") for value in text)
    assert any("처음 1,000개까지만 표시했습니다." in value for value in text)


def test_raw_text_is_html_escaped():
    content = b"<script>alert(1)</script>\n"
    app = run_upload("bad.log", content, log=True)

    assert not app.exception
    assert not app.markdown or all("<script>" not in item.value for item in app.markdown)


def test_help_yaml_loads_safely():
    data = yaml.safe_load((ROOT / "help.yaml").read_text(encoding="utf-8"))

    assert isinstance(data, dict)


def test_streamlit_upload_config():
    config = (ROOT / ".streamlit/config.toml").read_text(encoding="utf-8")

    assert "maxUploadSize = 10" in config
    assert 'address = "127.0.0.1"' in config
    assert "gatherUsageStats = false" in config


def test_elpa_exports_step4_helpers():
    import elpa

    assert callable(elpa.read_pcap)
    assert callable(elpa.build_conversations)


def test_most_recent_selection_wins_across_tabs(dns_cap: Path):
    def table_key(table):
        version = app.session_state.get(f"{table}_version", 0)
        return table if version == 0 else f"{table}_{version}"

    log_line = b'127.0.0.1 - - [30/Mar/2005:17:47:48 +0900] "GET / HTTP/1.0" 200 123\n'
    app = AppTest.from_file(str(APP)).run()
    app.file_uploader[0].set_value(("apache_logs", log_line, "application/octet-stream"))
    app.file_uploader[1].set_value(("dns.cap", dns_cap.read_bytes(), "application/octet-stream"))
    app.run(timeout=20)
    app.selectbox[0].select("access").run(timeout=20)

    # 1. Select packet row 0 -> packet wins
    app.session_state[table_key("packet_table")] = {"selection": {"rows": [0], "columns": [], "cells": []}}
    app.run(timeout=20)
    assert app.session_state["time_link_from"] == "packet"

    # 2. While packet row 0 remains selected, select log row 0 -> log wins
    app.session_state[table_key("log_table")] = {"selection": {"rows": [0], "columns": [], "cells": []}}
    app.run(timeout=20)
    assert app.session_state["time_link_from"] == "log"
    assert any(item.value == "패킷 탭에서 강조해 두었습니다" for item in app.info)
    assert any(item.value == "로그 탭에서 고른 시각 앞뒤 몇 초를 강조해 두었습니다" for item in app.info)

    # 3. While log row 0 remains selected, select packet row 1 -> packet wins and log tab updates
    app.session_state[table_key("packet_table")] = {"selection": {"rows": [1], "columns": [], "cells": []}}
    app.run(timeout=20)
    assert app.session_state["time_link_from"] == "packet"
    assert any(item.value == "패킷 탭에서 고른 시각 앞뒤 몇 초를 강조해 두었습니다" for item in app.info)
    assert any(item.value == "로그 탭에서 강조해 두었습니다" for item in app.info)
