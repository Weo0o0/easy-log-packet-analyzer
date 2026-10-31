from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from elpa.filters import FilterCond

ROOT = Path(__file__).resolve().parents[1]


def packet_app() -> AppTest:
    sample = ROOT / ".samples/dns.cap"
    if not sample.is_file():
        pytest.skip("dns.cap sample unavailable")
    app = AppTest.from_file(str(ROOT / "app.py")).run()
    app.file_uploader[1].set_value(("dns.pcap", sample.read_bytes(), "application/octet-stream"))
    return app.run(timeout=20)


def test_filter_chips_and_command_boxes():
    app = packet_app()
    app.session_state["step6_패킷"] = [FilterCond("port", "==", "53")]
    app.run(timeout=20)

    assert any(item.value == "port == 53" for item in app.text)
    code = [item.value for item in app.code]
    assert 'udp.port == 53 || tcp.port == 53' in code
    assert any('tshark -r dns.pcap -Y "udp.port == 53 || tcp.port == 53"' == value for value in code)
    assert code.count("번역 없음") == 1


def test_zero_result_uses_ui_copy():
    app = packet_app()
    app.session_state["step6_패킷"] = [FilterCond("port", "==", "not-present")]
    app.run(timeout=20)

    assert any(item.value == "조건에 맞는 줄이 없습니다" for item in app.error)
    assert any(
        item.value == "지금 필터에 맞는 로그/패킷이 0건입니다.\n\n"
        "필터를 지우거나, 시간 범위를 넓히거나, 다른 열을 골라 보세요."
        for item in app.markdown
    )
    assert any(item.label == "필터 지우기" for item in app.button)


def test_clear_filters_button_restores_rows():
    app = packet_app()
    app.session_state["step6_패킷"] = [FilterCond("port", "==", "not-present")]
    app.run(timeout=20)

    next(item for item in app.button if item.label == "필터 지우기").click().run(timeout=20)

    assert app.session_state["step6_패킷"] == []
    assert len(app.dataframe(key="packet_table").value) == 38


def test_both_tabs_empty_at_once_does_not_duplicate_button_id():
    log_sample = ROOT / ".samples/OpenSSH_2k.log"
    packet_sample = ROOT / ".samples/dns.cap"
    if not log_sample.is_file() or not packet_sample.is_file():
        pytest.skip("samples unavailable")
    app = AppTest.from_file(str(ROOT / "app.py")).run()
    app.file_uploader[0].set_value(("auth.log", log_sample.read_bytes(), "text/plain"))
    app.file_uploader[1].set_value(("dns.pcap", packet_sample.read_bytes(), "application/octet-stream"))
    app.session_state["step6_로그"] = [FilterCond("srcip", "==", "not-present")]
    app.session_state["step6_패킷"] = [FilterCond("port", "==", "not-present")]
    app.run(timeout=20)

    assert not app.exception
    assert sum(item.label == "필터 지우기" for item in app.button) == 2
