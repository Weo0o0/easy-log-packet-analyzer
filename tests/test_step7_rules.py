"""Step 7 acceptance and unit tests: rules.py, hints.py, rules.yaml, hints.yaml."""

from __future__ import annotations

import subprocess
from pathlib import Path

from elpa.conversations import Conversation, build_conversations
from elpa.hints import Hint, HintRule, compute_hints, load_hints
from elpa.models import Record
from elpa.pcap_reader import read_pcap
from elpa.rules import Alert, Rule, evaluate_rules, load_rules
from elpa.text_reader import read_text_log
from elpa.timeline import TimeSettings

ROOT = Path(__file__).resolve().parents[1]
RULES_YAML = ROOT / "rules.yaml"
HINTS_YAML = ROOT / "hints.yaml"


def test_openssh_sshd_failure_rule_counts_and_top_ip(openssh_log: Path) -> None:
    rules, notices = load_rules(RULES_YAML)
    assert notices == []
    assert len(rules) >= 1

    result = read_text_log(str(openssh_log), "sshd")
    settings = TimeSettings(log_tz="Asia/Seoul", sshd_year=2023)
    alerts = evaluate_rules(
        result.records,
        rules,
        target="sshd",
        settings=settings,
        unparsed=result.unparsed,
    )

    alert_ips = {a.track_value for a in alerts}
    assert len(alert_ips) == 9
    assert alert_ips == {
        "183.62.140.253",
        "187.141.143.180",
        "103.99.0.122",
        "112.95.230.3",
        "5.188.10.180",
        "185.190.58.151",
        "119.4.203.64",
        "123.235.32.19",
        "60.2.12.12",
    }
    assert len(alerts) == 10

    top = max(alerts, key=lambda a: len(a.evidence))
    assert top.track_value == "183.62.140.253"
    assert len(top.evidence) == 286


def test_openssh_card_evidence_matches_grep_line_numbers(openssh_log: Path) -> None:
    rules, _ = load_rules(RULES_YAML)
    result = read_text_log(str(openssh_log), "sshd")
    alerts = evaluate_rules(
        result.records,
        rules,
        target="sshd",
        settings=TimeSettings(log_tz="Asia/Seoul", sshd_year=2023),
    )
    by_ip: dict[str, list[int]] = {}
    for alert in alerts:
        by_ip.setdefault(alert.track_value, []).extend(alert.evidence)

    for ip in ("183.62.140.253", "187.141.143.180", "112.95.230.3", "103.99.0.122"):
        proc = subprocess.run(
            ["grep", "-n", f"Failed password for.*from {ip} ", str(openssh_log)],
            capture_output=True,
            text=True,
            check=True,
        )
        grep_numbers = tuple(
            int(line.split(":", 1)[0])
            for line in proc.stdout.splitlines()
            if line
        )
        assert tuple(by_ip[ip]) == grep_numbers


def test_cards_have_level_caution_and_confidence(openssh_log: Path) -> None:
    rules, _ = load_rules(RULES_YAML)
    result = read_text_log(str(openssh_log), "sshd")
    alerts = evaluate_rules(result, rules, target="sshd")
    assert alerts

    for alert in alerts:
        assert isinstance(alert, Alert)
        assert alert.level in {"높음", "중간", "낮음"}
        assert alert.caution and alert.오해_주의 == alert.caution
        assert alert.confidence in {"근거 충분", "더 확인 필요"}
        assert alert.confidence_reason and "\n" not in alert.confidence_reason

    top = max(alerts, key=lambda a: len(a.evidence))
    assert top.confidence == "근거 충분"
    assert "원본에서 재확인됨" in top.confidence_reason

    exact_five = [a for a in alerts if len(a.evidence) == 5]
    assert {a.track_value for a in exact_five} == {"123.235.32.19", "60.2.12.12"}
    for alert in exact_five:
        assert alert.confidence == "더 확인 필요"
        assert "기준(5개)과 딱 같습니다" in alert.confidence_reason


def test_dns_cap_conversation_hints(dns_cap: Path) -> None:
    hint_rules, notices = load_hints(HINTS_YAML)
    assert notices == []
    assert len(hint_rules) >= 1

    packets = read_pcap(str(dns_cap)).records
    conversations = build_conversations(packets)
    assert len(conversations) == 8
    assert all(c.protocol == "UDP" and c.state == "SF" for c in conversations)

    hints = compute_hints(conversations, hint_rules)
    assert len(hints) == 1
    hint = hints[0]
    assert isinstance(hint, Hint)
    assert hint.hint_id == "H-002"
    assert hint.target == "conversation"
    assert "SF" in hint.text
    assert hint.evidence == tuple(range(1, 39))

    s0_conv = Conversation(
        uid="udp-99",
        protocol="UDP",
        service="DNS",
        stream=99,
        a="10.0.0.1:55555",
        b="10.0.0.2:53",
        start="2023-01-01T00:00:00.000Z",
        duration=0.0,
        packets=1,
        bytes=60,
        state="S0",
        history="D",
        packet_numbers=(100,),
    )
    mixed_hints = compute_hints([*conversations, s0_conv], hint_rules)
    assert [h.hint_id for h in mixed_hints] == ["H-001", "H-002"]
    assert mixed_hints[0].evidence == (100,)


def test_broken_rule_skipped_with_notice_and_others_work(
    tmp_path: Path, openssh_log: Path
) -> None:
    broken_yaml = tmp_path / "rules_with_broken.yaml"
    broken_yaml.write_text(
        RULES_YAML.read_text(encoding="utf-8")
        + "\n- id: R-BROKEN-1\n  대상: sshd\n  unknown_field: 123\n"
        + "\n- id: R-BROKEN-2\n  대상: sshd\n  count: 5\n",
        encoding="utf-8",
    )

    rules, notices = load_rules(broken_yaml)
    assert len(notices) == 2
    assert any("unknown_field" in n for n in notices)
    assert [r.id for r in rules] == ["R-001", "R-002", "R-003"]

    result = read_text_log(str(openssh_log), "sshd")
    alerts = evaluate_rules(result, rules, target="sshd")
    assert len({a.track_value for a in alerts}) == 9


def test_broken_hint_and_missing_files_do_not_crash(tmp_path: Path) -> None:
    rules, r_notices = load_rules(tmp_path / "missing_rules.yaml")
    assert rules == []
    assert len(r_notices) == 1

    bad_hints_path = tmp_path / "bad_hints.yaml"
    bad_hints_path.write_text(
        "- id: H-OK\n  대상: conversation\n  조건:\n    protocol: UDP\n    state: S0\n  text: 설명\n"
        "- id: H-BAD\n  대상: conversation\n  extra_key: nope\n  text: 설명\n",
        encoding="utf-8",
    )
    hints, h_notices = load_hints(bad_hints_path)
    assert [h.id for h in hints] == ["H-OK"]
    assert len(h_notices) == 1


def test_unique_dport_and_confidence_degradation_reasons() -> None:
    rules, _ = load_rules(RULES_YAML)
    scan_rule = next(r for r in rules if r.id == "R-002")
    assert isinstance(scan_rule, Rule)
    assert scan_rule.unique == "dport"

    base_ts = 1700000000.0
    records = [
        Record(
            line_number=i,
            kind="TCP",
            fields={
                "time": f"{base_ts + i:.6f}",
                "src": "10.0.0.9",
                "dst": "10.0.0.1",
                "sport": "50000",
                "dport": str(1000 + i),
                "transport": "TCP",
                "protocol": "TCP",
                "flags": "S",
                "length": "60",
                "summary": "Ethernet / IP / TCP",
            },
            raw=str(i),
        )
        for i in range(1, 12)
    ]
    alerts = evaluate_rules(records, [scan_rule], target="pcap")
    assert len(alerts) == 1
    assert alerts[0].confidence == "근거 충분"
    assert alerts[0].evidence == tuple(range(1, 12))

    # Add an untimed record and unparsed > 0 -> confidence becomes 더 확인 필요
    untimed = Record(
        line_number=99,
        kind="TCP",
        fields={
            "time": None,
            "src": "10.0.0.9",
            "dst": "10.0.0.1",
            "sport": "50000",
            "dport": "2000",
            "transport": "TCP",
            "protocol": "TCP",
            "flags": "S",
            "length": "60",
            "summary": "Ethernet / IP / TCP",
        },
        raw="99",
    )
    degraded = evaluate_rules(
        [*records, untimed], [scan_rule], target="pcap", unparsed=2
    )
    assert len(degraded) == 1
    assert degraded[0].confidence == "더 확인 필요"
    assert "읽지 못한 줄 2개" in degraded[0].confidence_reason
    assert "시간을 읽지 못한 레코드" in degraded[0].confidence_reason
    assert 99 not in degraded[0].evidence


def test_dense_same_time_records_are_linear_and_unique_window_expires() -> None:
    import time

    rules, _ = load_rules(RULES_YAML)
    scan = next(r for r in rules if r.id == "R-002")

    def rec(i: int, t: float, dport: str) -> Record:
        f = {"time": f"{t:.6f}", "src": "10.0.0.9", "dst": "10.0.0.1", "sport": "1",
             "dport": dport, "transport": "TCP", "protocol": "TCP", "flags": "S",
             "length": "60", "summary": "x"}
        return Record(line_number=i, kind="TCP", fields=f, raw=str(i))

    dense = [rec(i, 1.7e9, "80") for i in range(1, 30001)]  # one port: never unique enough
    start = time.perf_counter()
    assert evaluate_rules(dense, [scan], target="pcap") == []
    assert time.perf_counter() - start < 5
