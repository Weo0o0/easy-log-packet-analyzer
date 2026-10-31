from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / ".samples"


def upload_sample(name: str, index: int) -> AppTest:
    path = SAMPLES / name
    if not path.is_file():
        pytest.skip(f"sample unavailable: {name}")
    app = AppTest.from_file(str(ROOT / "app.py")).run()
    app.file_uploader[index].set_value((name, path.read_bytes(), "application/octet-stream"))
    return app.run(timeout=30)


def test_openssh_alert_card_matches_step7_layout():
    app = upload_sample("OpenSSH_2k.log", 0)
    app.number_input[0].set_value(2023).run(timeout=30)

    text = [item.value for item in app.text]
    assert any("[!] [분류:" in value and "[level: 중간]" in value for value in text)
    assert any(value.startswith("제목:") for value in text)
    assert any(value.startswith("근거:") and "[원본 보기]" in value for value in text)
    assert any(value.startswith("Wireshark에서는:") for value in text)
    assert any(value.startswith("더 확인 필요:") for value in text) or any(
        value.startswith("신뢰도 판단:") for value in text
    )
    assert any("오해 주의:" in item.value for item in app.text)
    assert any("[신뢰도: 근거 충분]" in value or "[신뢰도: 더 확인 필요]" in value for value in text)
    assert any(item.value == "Suricata 룰 예시 (참고용, 실행 안 함)" for item in app.caption)


def test_alert_empty_state_copy():
    app = upload_sample("dns.cap", 1)

    assert any(
        item.value == "규칙에 걸린 경고가 없습니다. 이것은 안전하다는 뜻이 아닙니다."
        for item in app.text
    )


def test_dns_has_separate_misconception_hint_expander():
    app = upload_sample("dns.cap", 1)

    assert any(item.label == "오해 힌트" for item in app.expander)
    assert any("정상 UDP 대화" in item.value for item in app.text)
