from __future__ import annotations

from dataclasses import replace
from html import escape
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import pandas as pd
import streamlit as st
import yaml
import streamlit.components.v1 as components

from elpa import build_conversations, read_evtx, read_pcap, read_text_log
from elpa.export import (
    CONVERSATION_COLUMNS,
    LOG_COLUMNS,
    PACKET_COLUMNS,
    ColumnChoice,
    table_rows,
    to_csv,
    to_export_command,
)
from elpa.filters import (
    FilterCond,
    apply_filters,
    load_filters,
    to_awk,
    to_tshark,
    to_wireshark,
)
from elpa.models import ParseResult, Record
from elpa.hints import compute_hints, load_hints
from elpa.rules import evaluate_rules, load_rules
from elpa.timeline import (
    TimeSettings,
    build_timeline,
    numbers_near,
    record_time,
)
from elpa.layer_help import (
    build_layer_help,
    load_layers,
    load_scenarios,
    render_layer_help,
)
from elpa.learning import load_learning

HELP_PATH = Path(__file__).resolve().with_name("help.yaml")
SEOUL = ZoneInfo("Asia/Seoul")
_SSHD_PREFIX = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")


def load_help() -> dict:
    if not HELP_PATH.exists():
        return {}
    with HELP_PATH.open(encoding="utf-8") as file:
        return yaml.safe_load(file) or {}


def help_text(help_data: dict, group: str, key: str) -> str:
    return help_data.get(group, {}).get(key) or f"{key}: 설명 없음"


def read_upload(upload, reader) -> ParseResult:
    path = None
    try:
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=Path(upload.name).suffix
        ) as temporary:
            path = temporary.name
            temporary.write(upload.getvalue())
        return reader(path)
    finally:
        if path is not None:
            Path(path).unlink(missing_ok=True)


def _format_when(when: datetime | None, *, subsecond: bool = False) -> str:
    if when is None:
        return ""
    local = when.astimezone(SEOUL)
    if subsecond:
        return local.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    return local.strftime("%Y-%m-%d %H:%M:%S")


def _log_time_display(record: Record, kind_group: str, settings: TimeSettings) -> str:
    when = record_time(record, kind_group, settings)
    if when is not None:
        return _format_when(when)
    if kind_group == "sshd":
        match = _SSHD_PREFIX.match(record.raw)
        return match.group(1) if match else ""
    value = record.fields.get("time")
    return str(value) if value else ""


HELP = load_help()


@st.cache_data(show_spinner=False)
def _load_layer_help_data():
    layers, layer_notices = load_layers()
    scenarios, scenario_notices = load_scenarios()
    return layers, scenarios, (*layer_notices, *scenario_notices)


def _show_layer_help(item, source: str) -> None:
    layers, scenarios, notices = _load_layer_help_data()
    layer_help = build_layer_help(item, source, layers, scenarios)
    layer_help = replace(layer_help, notes=(*layer_help.notes, *notices))
    with st.container(border=True):
        st.markdown(render_layer_help(layer_help), unsafe_allow_html=True)


def _show_parse_notices(result: ParseResult, *, packets: bool = False) -> None:
    for notice in result.notices:
        if notice == "pcap 파일이 아닙니다":
            st.error("pcap 파일이 아닙니다")
            st.write(
                "이 파일은 패킷을 저장한 pcap/pcapng 형식이 아닙니다.\n\n"
                "Wireshark에서 저장할 때 형식을 pcap 또는 pcapng로 고르거나,\n"
                "다른 파일을 올려 주세요."
            )
            st.caption("다른 파일 올리기")
        elif "제한을 초과" in notice:
            st.error("파일이 너무 큽니다 (10MB 제한)")
            st.write(
                "이 도구는 공부용이라 10MB까지만 읽습니다.\n\n"
                "Wireshark로 열어 일부만 저장하거나, 더 작은 공개 샘플을 올려 주세요."
            )
            st.caption("다른 파일 올리기")
        elif "잘려" in notice and packets:
            count = re.search(r"(\d+)개", notice)
            number = count.group(1) if count else str(len(result.records))
            st.warning(f"파일 끝이 잘려 {number}개까지만 읽었습니다")
            st.write(
                f"파일을 끝까지 읽지 못했습니다. 읽은 {number}개 패킷만 보여 줍니다.\n\n"
                "마지막 패킷은 일부가 빠져 있을 수 있습니다.\n\n"
                "다시 받은 파일이면 새로 올려 주세요."
            )
            st.caption("다시 올리기")
            st.caption(f"읽은 {number}개 보기")
        else:
            st.info(notice)


def _show_unparsed(result: ParseResult) -> None:
    if not result.unparsed:
        return
    st.warning(
        f"{result.unparsed}줄을 읽지 못했습니다. 원본 줄 번호와 함께 보여 줍니다."
    )
    if result.unparsed_lines:
        st.text(", ".join(map(str, result.unparsed_lines)))
    if result.unparsed_lines_truncated:
        st.text("원본 줄 번호는 처음 1,000개까지만 표시했습니다.")


def _show_empty_records(key: str) -> None:
    st.error("조건에 맞는 줄이 없습니다")
    st.write(
        "지금 필터에 맞는 로그/패킷이 0건입니다.\n\n"
        "필터를 지우거나, 시간 범위를 넓히거나, 다른 열을 골라 보세요."
    )
    if st.button("필터 지우기", key=key):
        st.session_state["step6_로그"] = []
        st.session_state["step6_패킷"] = []
        st.rerun()


def _show_file_error(error: ValueError) -> None:
    message = str(error)
    if "제한을 초과" in message:
        st.error("파일이 너무 큽니다 (10MB 제한)")
        st.write(
            "이 도구는 공부용이라 10MB까지만 읽습니다.\n\n"
            "Wireshark로 열어 일부만 저장하거나, 더 작은 공개 샘플을 올려 주세요."
        )
        st.caption("다른 파일 올리기")
    else:
        st.error(message)


def _columns(help_data: dict, names: list[str]) -> dict:
    return {
        name: (
            st.column_config.NumberColumn(name, help=help_text(help_data, "열", name))
            if name in {"번호", "지속 시간", "패킷 수", "바이트 합계"}
            else st.column_config.TextColumn(name, help=help_text(help_data, "열", name))
        )
        for name in names
    }


def _style_highlights(frame: pd.DataFrame):
    return frame.style.apply(
        lambda row: [
            "background-color: #dbeafe; color: #102a43"
            if "강조" in str(row["표시"])
            else ""
        ]
        * len(row),
        axis=1,
    )


def _render_selectable_table(rows: list[dict], help_data: dict, *, key: str):
    if not rows:
        _show_empty_records(f"{key}_empty")
        return None
    frame = pd.DataFrame(rows)
    has_highlight = "표시" in frame.columns and frame["표시"].astype(str).str.contains(
        "강조"
    ).any()
    version = st.session_state.get(f"{key}_version", 0)
    return st.dataframe(
        _style_highlights(frame) if has_highlight else frame,
        width="stretch",
        height=320,
        hide_index=True,
        column_config=_columns(help_data, list(rows[0])),
        on_select="rerun",
        selection_mode="single-row",
        key=key if version == 0 else f"{key}_{version}",
    )


def _select_columns(tab, columns, records, *, kind_group=None, highlighted=None):
    key = f"columns_{tab}"
    st.session_state.setdefault(key, list(columns))
    selected = st.multiselect(
        "열 고르기", columns, key=key
    )
    choice = ColumnChoice(tab, tuple(selected))
    rows = table_rows(
        records, choice, time_settings, kind_group=kind_group, highlighted=highlighted
    )
    return choice, rows


def _filtered_records(records: list[Record], kind: str) -> list[Record]:
    fields = {
        "로그": ["srcip", "status", "time"],
        "패킷": ["src", "dst", "port", "protocol", "time"],
    }[kind]
    key = f"step6_{kind}"
    conds = st.session_state.setdefault(key, [])
    options = {
        field: sorted(
            {
                str(record.fields[field])
                for record in records
                if record.fields.get(field) is not None
            }
            | (
                {
                    str(value)
                    for record in records
                    for value in (record.fields.get("sport"), record.fields.get("dport"))
                    if value is not None
                }
                if field == "port"
                else set()
            )
        )
        for field in fields
    }
    st.subheader("필터")
    if fields and any(options.values()):
        field = st.selectbox(
            "필터 열", [name for name in fields if options[name]], key=f"{key}_field"
        )
        value = st.selectbox("필터 값", options[field], key=f"{key}_value")
        if st.button("필터 추가", key=f"{key}_add"):
            condition = FilterCond(field, "==", value)
            if condition not in conds:
                conds.append(condition)
                st.session_state[key] = conds
                st.rerun()
    for index, cond in enumerate(conds):
        button_col, chip_col = st.columns([1, 5])
        chip_col.text(f"{cond.field} == {cond.value}")
        if button_col.button("지우기", key=f"{key}_remove_{index}"):
            conds.pop(index)
            st.session_state[key] = conds
            st.rerun()
    filtered = apply_filters(records, conds)
    if not filtered and conds:
        _show_empty_records(f"{key}_empty")
    return filtered


def _render_filter_commands(
    conds: list[FilterCond], filename: str, awk_ok: bool = False
) -> None:
    st.subheader("명령 번역")
    table = load_filters()
    for label, command in (
        ("Wireshark", to_wireshark(conds, table)),
        ("tshark", to_tshark(conds, table, filename)),
        ("awk", to_awk(conds, table, filename) if awk_ok else None),
    ):
        st.caption(label)
        st.code(command or "번역 없음")


def _render_alerts(
    records,
    target: str,
    settings: TimeSettings,
    *,
    scope: str,
    unparsed: int = 0,
    hint_items=None,
    hint_target: str | None = None,
) -> set[int]:
    rules, rule_notices = load_rules()
    hints, hint_notices = load_hints()
    alerts = evaluate_rules(records, rules, target, settings, unparsed)
    selected: set[int] = set()
    enough = sum(alert.confidence == "근거 충분" for alert in alerts)
    levels = {level: sum(alert.level == level for alert in alerts) for level in ("높음", "중간", "낮음")}
    st.caption(
        f"경고 {len(alerts)}건 · 높음 {levels['높음']} · 중간 {levels['중간']} · 낮음 {levels['낮음']} · "
        f"근거 충분 {enough} · 더 확인 필요 {len(alerts) - enough}"
    )
    if not alerts:
        st.text("규칙에 걸린 경고가 없습니다. 이것은 안전하다는 뜻이 아닙니다.")
    rule_by_id = {rule.id: rule for rule in rules}
    for index, alert in enumerate(alerts):
        rule = rule_by_id[alert.rule_id]
        trust = f"[{alert.confidence}]"
        with st.expander(f"[{alert.level}] {trust} {alert.msg}", expanded=False) as alert_expander:
            if alert_expander.open:
                color = "#22c55e" if alert.confidence == "근거 충분" else "#f59e0b"
                st.markdown(
                    f'<div style="border:1px solid {color};padding:.5rem;border-radius:.5rem">'
                    f'<b>{escape(trust)}</b></div>', unsafe_allow_html=True
                )
                st.text(f"[!] [분류: {alert.category}] [level: {alert.level}]")
                st.text(f"제목: {alert.msg}")
                st.text(f"왜 이상한가: {rule.why}")
                st.text("근거: " + ", ".join(map(str, alert.evidence)) + "  [원본 보기]")
                if alert.confidence == "더 확인 필요":
                    st.text(f"더 확인 필요: {alert.confidence_reason}")
                else:
                    st.text(f"신뢰도 판단: {alert.confidence_reason}")
                st.text(f"다음 확인 단계: {rule.next_steps}")
                st.text("Wireshark에서는: " + rule.wireshark_filter.replace("{track}", alert.track_value))
                st.text(f"오해 주의: {rule.caution}")
                choice = st.selectbox(
                    "[원본 보기] 근거 줄/패킷 강조", [None, *alert.evidence],
                    format_func=lambda value: "선택 안 함" if value is None else str(value),
                    key=f"{scope}_alert_evidence_{index}",
                )
                if choice is not None:
                    selected.add(choice)
                if rule.suricata_example:
                    with st.expander("Suricata 룰 예시 (참고용, 실행 안 함)", expanded=False):
                        st.code(rule.suricata_example)
    matched_hints = compute_hints(
        hint_items if hint_items is not None else records, hints, hint_target or target
    )
    with st.expander("오해 힌트", expanded=False) as hint_expander:
        if hint_expander.open:
            for hint in matched_hints:
                st.text(f"{hint.text} (근거: {', '.join(map(str, hint.evidence))})")
            if not matched_hints:
                st.text("해당하는 오해 힌트가 없습니다.")
    for notice in (*rule_notices, *hint_notices):
        st.warning(escape(notice))
    return selected


def _summary_time(
    log_records: list[Record],
    packet_records: list[Record],
    log_kind: str,
    settings: TimeSettings,
) -> str:
    values = []
    for record in packet_records:
        when = record_time(record, "pcap", settings)
        text = _format_when(when, subsecond=True)
        if text:
            values.append(text)
    for record in log_records:
        text = _log_time_display(record, log_kind, settings)
        if text and re.match(r"\d{4}-\d\d-\d\d ", text):
            values.append(text)
    if not values:
        return "시간 범위를 확인할 수 없습니다."
    return f"시간 범위 {min(values)} ~ {max(values)} (Asia/Seoul)"


_card_swiper = components.declare_component(
    "card_swiper", path=str(Path(__file__).resolve().parent / "elpa/components/card_swiper")
)


def card_swiper(cards: list[str], index: int, key: str) -> int | None:
    return _card_swiper(cards=cards, index=index, key=key, default=None)


def _learning_view() -> None:
    scenarios, notices = load_learning()
    for notice in notices:
        st.warning(escape(notice))
    if not scenarios:
        st.info("시나리오 없음")
        return
    opened = st.session_state.get("learning_open")
    if opened:
        scenario = next((item for item in scenarios if item.id == opened), None)
        if scenario is None:
            st.session_state["learning_open"] = None
            st.session_state["learning_stage"] = 0
        else:
            stage_index = max(0, min(2, int(st.session_state.get("learning_stage", 0))))
            st.session_state["learning_stage"] = stage_index
            stage = scenario.stages[stage_index]
            st.subheader(escape(scenario.title))
            if scenario.example_only:
                st.caption("교육용 예시")
            with st.container(border=True):
                st.markdown(f"**[{escape(stage.title)}]** {escape(stage.text)}")
                for line in stage.lines:
                    st.markdown(f"`{escape(line)}`")
            st.caption(f"단계 {'●' * (stage_index + 1)}{'○' * (2 - stage_index)} · 단계 {stage_index + 1} / 3")
            previous, following, home = st.columns(3)
            if previous.button("이전", disabled=stage_index == 0, key="learning_stage_previous"):
                st.session_state["learning_stage"] = stage_index - 1
                st.rerun()
            if following.button("다음", disabled=stage_index == 2, key="learning_stage_next"):
                st.session_state["learning_stage"] = stage_index + 1
                st.rerun()
            if home.button("처음으로", key="learning_home"):
                st.session_state["learning_open"] = None
                st.session_state["learning_stage"] = 0
                st.rerun()
            return
    index = max(0, min(len(scenarios) - 1, int(st.session_state.get("learning_index", 0))))
    st.session_state["learning_index"] = index
    updated = card_swiper([item.title for item in scenarios], index, "learning_cards")
    if isinstance(updated, int) and not isinstance(updated, bool):
        st.session_state["learning_index"] = max(0, min(len(scenarios) - 1, updated))
        index = st.session_state["learning_index"]
    scenario = scenarios[index]
    with st.container(border=True):
        st.markdown(f"### {escape(scenario.title)}")
        st.markdown(f"근거 샘플: {escape(scenario.sample)}")
        if scenario.example_only:
            st.markdown("`교육용 예시` 배지")
        if st.button("열기", key="learning_open_button"):
            st.session_state["learning_open"] = scenario.id
            st.session_state["learning_stage"] = 0
            st.rerun()
    previous, count, following = st.columns([1, 2, 1])
    if previous.button("이전", key="learning_previous", disabled=index == 0):
        st.session_state["learning_index"] = index - 1
        st.rerun()
    count.markdown(f"<p style='text-align:center'>{escape(str(index + 1))} / {escape(str(len(scenarios)))}</p>", unsafe_allow_html=True)
    if following.button("다음", key="learning_next", disabled=index == len(scenarios) - 1):
        st.session_state["learning_index"] = index + 1
        st.rerun()


def _subtab(name: str, labels: list[str]):
    tabs = st.tabs(labels, key=f"sub_{name}", on_change="rerun")
    selected = next((index for index, tab in enumerate(tabs) if tab.open), 0)
    return tabs, selected


def _clear_upload_links():
    for key in ("time_center", "time_link_from", "prev_log_rows", "prev_packet_rows", "step7_conversation_highlights", "step7_log_highlights", "step7_packet_highlights"):
        st.session_state.pop(key, None)
    for key in ("log_table_version", "packet_table_version", "conversation_table_version"):
        st.session_state[key] = st.session_state.get(key, 0) + 1


def _file_id(upload):
    return f"{upload.name}:{len(upload.getvalue())}" if upload else None


def _render_export_view(tab: str, columns: tuple[str, ...], records, filename: str,
                        tool: str | None, *, kind_group: str | None = None,
                        highlighted: set[int] | None = None, conds=None, awk_ok=False):
    choice = ColumnChoice(tab, tuple(st.session_state.get(f"columns_{tab}", list(columns))))
    rows = table_rows(records, choice, time_settings, kind_group=kind_group, highlighted=highlighted)
    st.download_button("CSV", to_csv(rows, choice), file_name=f"{Path(filename).stem}.csv", mime="text/csv", key=f"{tab}_csv")
    filters = load_filters()
    command = to_export_command(tool, choice, filters, filename) if tool else None
    if command:
        st.code(command)
    with st.expander("명령 번역", expanded=False) as commands:
        if commands.open:
            _render_filter_commands(conds or [], filename, awk_ok)
    return rows


st.set_page_config(page_title="easy-log-packet-analyzer", layout="wide")
st.title("easy-log-packet-analyzer")
st.write("로그와 패킷을 한곳에서, 쉬운 한국어로")
st.caption("지원: auth.log(sshd) · access.log · .evtx · .pcap/.pcapng · 최대 10MB")

with st.sidebar:
    st.subheader("파일 올리기")
    log_upload = st.file_uploader("로그 파일 올리기", key="log_upload")
    log_type = "sshd"
    if log_upload and Path(log_upload.name).suffix.lower() != ".evtx":
        log_type = st.selectbox("로그 형식", ["sshd", "access"], format_func=lambda value: "auth.log (sshd)" if value == "sshd" else "access.log", key="log_type")
    packet_upload = st.file_uploader("패킷 파일 올리기", key="packet_upload")
    st.subheader("시간 연결")
    log_tz = st.text_input("로그 시간대 (log_tz)", value="Asia/Seoul")
    sshd_year = st.number_input("sshd 연도", min_value=1970, max_value=2100, value=None, step=1)
    st.caption("연도는 직접 고른 값")
    window_seconds = int(st.number_input("앞뒤 초 (window_seconds)", min_value=0, max_value=86400, value=5, step=1))

for key, upload in (("log_file_id", log_upload), ("packet_file_id", packet_upload)):
    identity = _file_id(upload)
    if key in st.session_state and st.session_state[key] != identity:
        _clear_upload_links()
    st.session_state[key] = identity

time_settings = TimeSettings(log_tz=log_tz or "Asia/Seoul", sshd_year=int(sshd_year) if sshd_year is not None else None, window_seconds=window_seconds)
log_result = packet_result = None
with st.spinner("파일을 읽는 중입니다…"):
    if log_upload:
        try:
            extension = Path(log_upload.name).suffix.lower()
            log_result = read_upload(log_upload, read_evtx if extension == ".evtx" else lambda path: read_text_log(path, log_type))
        except ValueError as error:
            _show_file_error(error)
    if packet_upload:
        try:
            packet_result = read_upload(packet_upload, read_pcap)
        except ValueError as error:
            _show_file_error(error)

log_records = log_result.records if log_result else []
packet_records = packet_result.records if packet_result else []
conversations = build_conversations(packet_records)
log_kind = "evtx" if log_upload and Path(log_upload.name).suffix.lower() == ".evtx" else log_type
log_points = build_timeline(log_records, log_kind, time_settings)
packet_points = build_timeline(packet_records, "pcap", time_settings)

learning_tab, analysis_tab = st.tabs(["시나리오 학습", "분석"])
with learning_tab:
    _learning_view()

with analysis_tab:
    st.subheader("요약")
    metrics = st.columns(4)
    metrics[0].metric("로그", len(log_records))
    metrics[1].metric("패킷", len(packet_records))
    metrics[2].metric("대화", len(conversations))
    metrics[3].metric("읽지 못한 줄", log_result.unparsed if log_result else 0)
    st.caption("로그·패킷·대화의 전체 건수입니다.")
    st.write(_summary_time(log_records, packet_records, log_kind, time_settings))
    if not log_upload and not packet_upload:
        st.info("아직 파일이 없습니다")
        st.write("로그나 pcap 파일을 올리면 여기에 요약이 나옵니다.")
    log_tab, packet_tab, conversation_tab = st.tabs(["로그 탭", "패킷 탭", "대화 요약 탭"])

    with log_tab:
        subtabs, active = _subtab("log", ["요약", "표", "내보내기·명령어"])
        with subtabs[active]:
            if active == 0:
                if log_result:
                    st.session_state["step7_log_highlights"] = _render_alerts(log_records, log_kind, time_settings, scope="log", unparsed=log_result.unparsed)
                    _show_parse_notices(log_result)
                    _show_unparsed(log_result)
                    if not log_records and log_result.unparsed:
                        st.error("읽을 수 없는 로그 형식입니다")
                        st.write("지금은 auth.log(sshd), Apache/Nginx access.log,\nWindows .evtx만 읽습니다. 이 파일에서 읽은 줄은 0줄입니다.\n\n지원 목록과 샘플 링크를 확인해 주세요.")
                        st.caption("지원 형식 보기 · 다른 파일 올리기")
                else:
                    st.info("로그 파일을 올리면 여기에 요약이 나옵니다")
            elif active == 1:
                if log_result:
                    visible = _filtered_records(log_records, "로그")
                    time_center, time_from = st.session_state.get("time_center"), st.session_state.get("time_link_from")
                    linked = (numbers_near(log_points, time_center, time_settings.window_seconds) if time_center is not None and time_from == "packet" else set()) | st.session_state.get("step7_log_highlights", set())
                    choice, rows = _select_columns("logs", LOG_COLUMNS, visible, kind_group=log_kind, highlighted=linked)
                    event = _render_selectable_table(rows, HELP, key="log_table") if visible else None
                    selected = event.selection.rows if event is not None else []
                    if len(selected) == 1:
                        _show_layer_help(visible[selected[0]], "log")
                    previous = st.session_state.get("prev_log_rows", [])
                    st.session_state["prev_log_rows"] = list(selected)
                    if selected != previous:
                        if selected:
                            st.session_state["packet_table_version"] = st.session_state.get("packet_table_version", 0) + 1
                            st.session_state["prev_packet_rows"] = []
                            when = record_time(visible[selected[0]], log_kind, time_settings)
                            if when is not None:
                                st.session_state["time_center"], st.session_state["time_link_from"] = when, "log"
                        elif st.session_state.get("time_link_from") == "log":
                            st.session_state.pop("time_center", None)
                            st.session_state.pop("time_link_from", None)
                        st.rerun()
                    if packet_upload and time_from == "log" and linked:
                        st.info("패킷 탭에서 강조해 두었습니다")
                    elif packet_upload and time_from == "packet" and linked:
                        st.info("패킷 탭에서 고른 시각 앞뒤 몇 초를 강조해 두었습니다")
                else:
                    st.info("로그 파일을 올리면 여기에 표가 나옵니다")
            else:
                if log_result:
                    _render_export_view("logs", LOG_COLUMNS, log_records, log_upload.name, "awk" if log_kind == "access" else None, kind_group=log_kind, conds=st.session_state.get("step6_로그", []), awk_ok=log_kind == "access")
                else:
                    st.info("로그 파일을 올리면 여기에 내보내기 명령이 나옵니다")

    with packet_tab:
        subtabs, active = _subtab("packet", ["요약", "표", "내보내기·명령어"])
        with subtabs[active]:
            if active == 0:
                if packet_result:
                    st.session_state["step7_packet_highlights"] = _render_alerts(packet_records, "pcap", time_settings, scope="packet", unparsed=packet_result.unparsed)
                    _show_parse_notices(packet_result, packets=True)
                    _show_unparsed(packet_result)
                else:
                    st.info("패킷 파일을 올리면 여기에 요약이 나옵니다")
            elif active == 1:
                if packet_result:
                    time_center, time_from = st.session_state.get("time_center"), st.session_state.get("time_link_from")
                    linked = numbers_near(packet_points, time_center, time_settings.window_seconds) if time_center is not None and time_from == "log" else set()
                    highlighted = linked | st.session_state.get("step7_conversation_highlights", set()) | st.session_state.get("step7_packet_highlights", set())
                    visible = _filtered_records(packet_records, "패킷")
                    choice, rows = _select_columns("packets", PACKET_COLUMNS, visible, kind_group="pcap", highlighted=highlighted)
                    event = _render_selectable_table(rows, HELP, key="packet_table") if visible else None
                    selected = event.selection.rows if event is not None else []
                    if len(selected) == 1:
                        _show_layer_help(visible[selected[0]], "packet")
                    previous = st.session_state.get("prev_packet_rows", [])
                    st.session_state["prev_packet_rows"] = list(selected)
                    if selected != previous:
                        if selected:
                            st.session_state["log_table_version"] = st.session_state.get("log_table_version", 0) + 1
                            st.session_state["prev_log_rows"] = []
                            when = record_time(visible[selected[0]], "pcap", time_settings)
                            if when is not None:
                                st.session_state["time_center"], st.session_state["time_link_from"] = when, "packet"
                        elif st.session_state.get("time_link_from") == "packet":
                            st.session_state.pop("time_center", None)
                            st.session_state.pop("time_link_from", None)
                        st.rerun()
                    if log_upload and time_from == "packet" and linked:
                        st.info("로그 탭에서 강조해 두었습니다")
                    elif log_upload and time_from == "log" and linked:
                        st.info("로그 탭에서 고른 시각 앞뒤 몇 초를 강조해 두었습니다")
                    if visible:
                        selected_packet = st.selectbox("패킷 상세", range(len(visible)), format_func=lambda i: f"패킷 #{visible[i].line_number}")
                        record = visible[selected_packet]
                        with st.expander(f"#{record.line_number} {record.fields.get('summary') or record.kind}", expanded=False) as detail:
                            if detail.open:
                                st.write({key: value for key, value in record.fields.items() if value is not None})
                                st.text(f"Wireshark에서는: frame.number == {record.line_number}")
                                st.text("원본 값: 확인 못 함")
                else:
                    st.info("패킷 파일을 올리면 여기에 표가 나옵니다")
            else:
                if packet_result:
                    _render_export_view("packets", PACKET_COLUMNS, packet_records, packet_upload.name, "tshark", kind_group="pcap", conds=st.session_state.get("step6_패킷", []))
                else:
                    st.info("패킷 파일을 올리면 여기에 내보내기 명령이 나옵니다")

    with conversation_tab:
        subtabs, active = _subtab("conversation", ["요약", "표", "내보내기·명령어"])
        with subtabs[active]:
            if active == 0:
                st.write("대화를 먼저 보고, 필요하면 패킷으로 내려갑니다")
                if packet_result:
                    st.session_state["step7_conversation_highlights"] = _render_alerts(packet_records, "pcap", time_settings, scope="conversation", unparsed=packet_result.unparsed, hint_items=conversations, hint_target="conversation")
                else:
                    st.info("패킷 파일을 올리면 대화 요약이 나옵니다")
            elif active == 1:
                if packet_result:
                    choice, rows = _select_columns("conversations", CONVERSATION_COLUMNS, conversations, kind_group="pcap")
                    if rows:
                        version = st.session_state.get("conversation_table_version", 0)
                        event = st.dataframe(pd.DataFrame(rows), width="stretch", height=320, hide_index=True, column_config=_columns(HELP, list(rows[0])), on_select="rerun", selection_mode="single-row", key="conversation_table" if version == 0 else f"conversation_table_{version}")
                        if len(event.selection.rows) == 1:
                            _show_layer_help(conversations[event.selection.rows[0]], "conversation")
                    else:
                        _show_empty_records("conversation_empty")
                else:
                    st.info("패킷 파일을 올리면 여기에 대화 표가 나옵니다")
            else:
                if packet_result:
                    choice = ColumnChoice("conversations", tuple(st.session_state.get("columns_conversations", list(CONVERSATION_COLUMNS))))
                    rows = table_rows(conversations, choice, time_settings, kind_group="pcap")
                    st.download_button("CSV", to_csv(rows, choice), file_name=f"{Path(packet_upload.name).stem}.csv", mime="text/csv", key="conversations_csv")
                else:
                    st.info("패킷 파일을 올리면 대화를 내보낼 수 있습니다")
