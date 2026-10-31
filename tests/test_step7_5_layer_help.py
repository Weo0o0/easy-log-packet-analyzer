"""Step 7.5 acceptance and unit tests: layer_help.py, layers.yaml, scenarios.yaml."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from elpa.conversations import Conversation, build_conversations
from elpa.evtx_reader import read_evtx
from elpa.layer_help import (
    LayerHelp,
    LayerInfo,
    Scenario,
    build_layer_help,
    layer_of,
    load_layers,
    load_scenarios,
    render_layer_help,
    scenarios_for,
)
from elpa.models import Record
from elpa.pcap_reader import read_pcap
from elpa.text_reader import read_text_log

ROOT = Path(__file__).resolve().parents[1]
LAYERS_YAML = ROOT / "layers.yaml"
SCENARIOS_YAML = ROOT / "scenarios.yaml"


def test_load_layers_and_scenarios_defaults() -> None:
    layers, l_notices = load_layers(LAYERS_YAML)
    scenarios, s_notices = load_scenarios(SCENARIOS_YAML)

    assert isinstance(layers, tuple)
    assert isinstance(scenarios, tuple)
    assert l_notices == []
    assert s_notices == []
    assert len(layers) == 6
    assert {l.id for l in layers} == {
        "link",
        "ip",
        "transport",
        "app",
        "log_auth",
        "log_web",
    }
    assert "DNS" in getattr(layers, "app_names", ())
    assert all(isinstance(l, LayerInfo) for l in layers)
    assert all(isinstance(s, Scenario) for s in scenarios)


def test_dns_cap_packet_1_is_app_and_all_4_layers_present(dns_cap: Path) -> None:
    layers, _ = load_layers(LAYERS_YAML)
    scenarios, _ = load_scenarios(SCENARIOS_YAML)

    packets = read_pcap(str(dns_cap)).records
    pkt1 = packets[0]
    assert pkt1.kind == "DNS"
    assert pkt1.fields["summary"] == "Ethernet / IP / UDP / DNS"

    assert layer_of(pkt1, "packet", layers) == "app"

    lh = build_layer_help(pkt1, "packet", layers, scenarios)
    assert isinstance(lh, LayerHelp)
    assert lh.current == "app"
    assert [l.id for l in lh.layers] == ["app", "transport", "ip", "link"]
    assert set(lh.present) == {"app", "transport", "ip", "link"}
    assert any(s.id == "dns_query_answer" for s in lh.scenarios)

    lh_replaced = replace(lh, notes=lh.notes)
    rendered = render_layer_help(lh_replaced)
    assert "▶" in rendered
    assert "지금 고른 것" in rendered
    assert "border: 2px solid currentColor" in rendered
    assert 'data-raw="' not in rendered
    # All 4 layers in the summary are marked "들어 있음"
    assert rendered.count("들어 있음") == 4
    for layer_name, token in (
        ("응용 계층", "DNS"),
        ("전송 계층", "UDP"),
        ("IP 계층", "IP"),
        ("링크 계층", "Ethernet"),
    ):
        assert f"[{layer_name}] {token}" in rendered


def test_dns_cap_conversations_are_transport_and_no_udp_one_side_only(
    dns_cap: Path,
) -> None:
    layers, _ = load_layers(LAYERS_YAML)
    scenarios, _ = load_scenarios(SCENARIOS_YAML)

    packets = read_pcap(str(dns_cap)).records
    conversations = build_conversations(packets)
    assert len(conversations) == 8

    for conv in conversations:
        assert conv.protocol == "UDP"
        assert conv.state == "SF"
        assert conv.history == "Dd"
        assert layer_of(conv, "conversation", layers) == "transport"

        lh = replace(build_layer_help(conv, "conversation", layers, scenarios), notes=())
        assert lh.current == "transport"
        assert "udp_one_side_only" not in {s.id for s in lh.scenarios}
        assert "transport" in lh.present
        assert "app" in lh.present
        rendered = render_layer_help(lh)
        assert "[응용 계층] DNS" in rendered
        assert "[전송 계층] UDP" in rendered
        assert rendered.count("들어 있음") == 2


def test_openssh_failed_password_line_maps_to_log_auth_and_ssh_login_failed(
    openssh_log: Path,
) -> None:
    layers, _ = load_layers(LAYERS_YAML)
    scenarios, _ = load_scenarios(SCENARIOS_YAML)

    records = read_text_log(str(openssh_log), "sshd").records
    failed = next(r for r in records if "Failed password for" in r.raw)
    assert failed.kind == "sshd 실패"

    assert layer_of(failed, "log", layers) == "log_auth"
    lh = build_layer_help(failed, "log", layers, scenarios)
    assert lh.current == "log_auth"
    assert [l.id for l in lh.layers] == ["log_auth"]
    assert "ssh_login_failed" in [s.id for s in lh.scenarios]

    other = next(r for r in records if r.kind == "sshd")
    lh_other = replace(build_layer_help(other, "log", layers, scenarios), notes=build_layer_help(other, "log", layers, scenarios).notes)
    rendered_other = render_layer_help(lh_other)
    assert rendered_other.count("이 기록에 맞는 예시 상황: 설명 없음") == 1


def test_apache_and_evtx_records_map_to_log_layers(
    apache_log: Path, security_evtx: Path
) -> None:
    layers, _ = load_layers(LAYERS_YAML)
    scenarios, _ = load_scenarios(SCENARIOS_YAML)

    apache_rec = read_text_log(str(apache_log), "access").records[0]
    assert layer_of(apache_rec, "log", layers) == "log_web"
    lh_web = build_layer_help(apache_rec, "log", layers, scenarios)
    assert lh_web.current == "log_web"
    assert [l.id for l in lh_web.layers] == ["log_web"]

    evtx_rec = read_evtx(str(security_evtx)).records[0]
    assert layer_of(evtx_rec, "log", layers) == "log_auth"
    lh_auth = build_layer_help(evtx_rec, "log", layers, scenarios)
    assert lh_auth.current == "log_auth"
    assert [l.id for l in lh_auth.layers] == ["log_auth"]


def test_kind_raw_gives_no_description_without_error() -> None:
    layers, _ = load_layers(LAYERS_YAML)
    scenarios, _ = load_scenarios(SCENARIOS_YAML)

    raw_rec = Record(
        line_number=1,
        kind="Raw",
        fields={"summary": "Raw", "transport": "other", "protocol": "Raw"},
        raw="1",
    )
    assert layer_of(raw_rec, "packet", layers) is None

    lh = build_layer_help(raw_rec, "packet", layers, scenarios)
    assert lh.current is None
    assert lh.scenarios == ()
    assert "설명 없음" in lh.notes

    rendered = render_layer_help(lh)
    assert rendered.count("설명 없음") == 2  # once for layer, once for scenario
    assert rendered.count("이 기록에 맞는 예시 상황: 설명 없음") == 1


def test_script_value_is_html_escaped_in_rendered_string() -> None:
    layers, _ = load_layers(LAYERS_YAML)
    scenarios, _ = load_scenarios(SCENARIOS_YAML)

    # 1. <script> in Record kind / layer_labels (visible escaped text)
    pkt_xss = Record(
        line_number=1,
        kind="<script>alert(1)</script>",
        fields={"summary": "Ethernet / IP / UDP / <script>alert(1)</script>"},
        raw="<script>alert(1)</script>",
    )
    xss_layers = LayerHelp(
        layers=tuple(l for l in layers if l.id == "app"),
        current="app",
        scenarios=(),
        present=("app",),
        layer_labels={"app": pkt_xss.kind},
    )
    rendered_pkt = render_layer_help(xss_layers)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered_pkt
    assert "<script>" not in rendered_pkt
    assert 'data-raw="' not in rendered_pkt

    # 2. <script> in YAML text (LayerInfo and Scenario)
    xss_layer = LayerInfo(
        id="app",
        name="응용 <script>",
        order=4,
        text="설명 <script>",
    )
    xss_scenario = Scenario(
        id="xss_sc",
        layer="app",
        match={"source": "packet", "kind": "DNS"},
        title="제목 <script>",
        why="이유 <script>",
        check_next=("확인 <script>",),
        caution="주의 <script>",
    )
    lh_yaml = LayerHelp(
        layers=(xss_layer,),
        current="app",
        scenarios=(xss_scenario,),
        notes=("노트 <script>",),
    )
    rendered_yaml = render_layer_help(lh_yaml, pkt_xss, "packet")
    assert "&lt;script&gt;" in rendered_yaml
    assert "<script>" not in rendered_yaml


def test_missing_and_malformed_yaml_files_do_not_crash(tmp_path: Path) -> None:
    missing_layers, l_notices = load_layers(tmp_path / "no_layers.yaml")
    missing_scenarios, s_notices = load_scenarios(tmp_path / "no_scenarios.yaml")

    assert missing_layers == ()
    assert len(l_notices) == 1
    assert missing_scenarios == ()
    assert len(s_notices) == 1

    rec = Record(
        line_number=1,
        kind="DNS",
        fields={"summary": "Ethernet / IP / UDP / DNS"},
        raw="1",
    )
    lh = build_layer_help(rec, "packet", missing_layers, missing_scenarios)
    assert lh.current is None
    assert "설명 없음" in lh.notes
    rendered = render_layer_help(lh)
    assert "설명 없음" in rendered

    # Broken item in layers.yaml / scenarios.yaml is skipped with notice while valid ones load
    partial_layers_path = tmp_path / "layers_partial.yaml"
    partial_layers_path.write_text(
        "app_names: [DNS]\n"
        "layers:\n"
        "  - id: app\n"
        "    name: 응용 계층\n"
        "    order: 4\n"
        "    text: 설명\n"
        "  - id: transport\n"
        "    name: 전송 계층\n",
        encoding="utf-8",
    )
    loaded_l, notices_l = load_layers(partial_layers_path)
    assert [l.id for l in loaded_l] == ["app"]
    assert len(notices_l) == 1

    partial_scenarios_path = tmp_path / "scenarios_partial.yaml"
    partial_scenarios_path.write_text(
        "- id: s1\n"
        "  layer: app\n"
        "  match: {source: packet, kind: DNS}\n"
        "  title: t1\n"
        "  why: w1\n"
        "  check_next: [c1]\n"
        "  caution: ca1\n"
        "- id: s_broken\n"
        "  layer: app\n"
        "  title: missing_fields\n",
        encoding="utf-8",
    )
    loaded_s, notices_s = load_scenarios(partial_scenarios_path)
    assert [s.id for s in loaded_s] == ["s1"]
    assert len(notices_s) == 1


def test_scenarios_for_equality_only_file_order_and_max_3() -> None:
    custom_scenarios = tuple(
        Scenario(
            id=f"sc-{i}",
            layer="app",
            match={"source": "packet", "kind": "DNS"},
            title=f"title {i}",
            why="why",
            check_next=("check",),
            caution="caution",
        )
        for i in range(1, 6)
    )
    non_matching = Scenario(
        id="sc-extra-key",
        layer="app",
        match={"source": "packet", "kind": "DNS", "sport": "9999"},
        title="nope",
        why="why",
        check_next=("check",),
        caution="caution",
    )
    rec = Record(
        line_number=1,
        kind="DNS",
        fields={"sport": "53", "summary": "Ethernet / IP / UDP / DNS"},
        raw="1",
    )
    matched = scenarios_for(rec, "packet", (non_matching, *custom_scenarios))
    assert [s.id for s in matched] == ["sc-1", "sc-2", "sc-3"]
