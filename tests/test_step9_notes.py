from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re

import streamlit as st
from streamlit.testing.v1 import AppTest

from elpa.filters import FilterCond
from elpa.notes import StudyNote, render_note
from elpa.rules import Alert

ROOT = Path(__file__).resolve().parents[1]


def _upload(app: AppTest, index: int, name: str, path: Path) -> AppTest:
    app.file_uploader[index].set_value(
        (name, path.read_bytes(), "application/octet-stream")
    )
    return app.run(timeout=30)


def test_note_download_has_alert_filter_term_and_evidence(openssh_log, dns_cap, monkeypatch):
    downloads = {}
    download_button = st.download_button

    def capture_download(label, data, *args, **kwargs):
        downloads[label] = data
        return download_button(label, data, *args, **kwargs)

    monkeypatch.setattr(st, "download_button", capture_download)
    app = AppTest.from_file(str(ROOT / "app.py")).run(timeout=30)
    app = _upload(app, 0, "OpenSSH_2k.log", openssh_log)
    app = _upload(app, 1, "dns.cap", dns_cap)
    app.number_input[0].set_value(2023)
    app.session_state["step6_패킷"] = [
        FilterCond("port", "==", "53")
    ]
    app.session_state["sub_packet"] = "표"
    app.run(timeout=30)
    app.run(timeout=30)

    term = next(item for item in app.button if item.label == "? S0")
    term.click().run(timeout=30)
    term = next(item for item in app.button if item.label == "? S0")
    term.click().run(timeout=30)
    app.run(timeout=30)
    note = downloads["공부 노트 내보내기"]
    assert "같은 IP의 SSH 로그인 실패 반복" in note
    assert r"udp\.port == 53 \|\| tcp\.port == 53" in note
    assert note.count("S0:") == 1
    assert "SF:" not in note
    evidence = re.search(r"근거: ([\d, ]+);", note)
    assert evidence and evidence.group(1).strip()
    assert openssh_log.read_text(encoding="utf-8").splitlines()[0] not in note
    assert all(expander.proto.expanded is False for expander in app.expander)


def test_render_note_escapes_untrusted_markdown_and_html():
    raw_line = "distinctive raw log line that must stay private"
    alert = Alert(
        "test", "", "낮음", "test", "<script>alert(1)</script> [link](x)",
        (7,), "근거 충분", "",
    )
    note = render_note(
        StudyNote(
            ["<script> [file](x).log"], [alert], [], [],
            datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
    )
    assert "&lt;script&gt;" in note
    assert r"\[link\]\(x\)" in note
    assert raw_line not in note
