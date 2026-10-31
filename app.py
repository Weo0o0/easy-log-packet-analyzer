from __future__ import annotations

from html import escape
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import pandas as pd
import streamlit as st
import yaml

from elpa import build_conversations, read_evtx, read_pcap, read_text_log
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


def build_log_table(
    records: list[Record],
    kind_group: str,
    settings: TimeSettings,
    highlighted: set[int] | None = None,
) -> list[dict[str, str | int]]:
    highlighted = highlighted or set()
    rows = []
    for record in records:
        fields = record.fields
        state = "실패" if "실패" in record.kind else "성공" if "성공" in record.kind else ""
        if fields.get("status"):
            state = str(fields["status"])
        summary = fields.get("message") or record.kind
        if fields.get("method") and fields.get("path"):
            summary = f"{fields['method']} {fields['path']} · {fields.get('status') or ''}"
        elif fields.get("EventID"):
            summary = f"EventID {fields['EventID']}"
        rows.append(
            {
                "번호": record.line_number,
                "표시": "[!] 강조" if record.line_number in highlighted else "",
                "시간": _log_time_display(record, kind_group, settings),
                "출발지": fields.get("srcip") or "",
                "사용자": fields.get("user") or fields.get("TargetUserName") or "",
                "종류": record.kind,
                "상태": state,
                "요약": summary,
            }
        )
    return rows


def _local_packet_time(value: str | None) -> str:
    if not value:
        return ""
    return _format_when(
        datetime.fromtimestamp(float(value), timezone.utc), subsecond=True
    )


def build_packet_table(
    records: list[Record], highlighted: set[int] | None = None
) -> list[dict[str, str | int]]:
    highlighted = highlighted or set()
    return [
        {
            "번호": record.line_number,
            "표시": "[!] 강조" if record.line_number in highlighted else "",
            "시간": _local_packet_time(record.fields.get("time")),
            "출발지": record.fields.get("src") or "",
            "목적지": record.fields.get("dst") or "",
            "포트": ":".join(
                part
                for part in (record.fields.get("sport"), record.fields.get("dport"))
                if part
            ),
            "종류": record.fields.get("protocol") or record.kind,
            "요약": record.fields.get("summary") or "",
        }
        for record in records
    ]


def build_conversation_table(conversations) -> list[dict[str, str | int | float]]:
    return [
        {
            "대화": conversation.uid,
            "출발지:포트": conversation.a,
            "목적지:포트": conversation.b,
            "종류": f"{conversation.protocol} ({conversation.service})",
            "상태": f"{conversation.state} ({help_text(HELP, '상태', conversation.state)})",
            "지속 시간": round(conversation.duration, 3),
            "패킷 수": conversation.packets,
            "바이트 합계": conversation.bytes,
            "흐름": " ".join(conversation.history),
        }
        for conversation in conversations
    ]


HELP = load_help()


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
        hide_index=True,
        column_config=_columns(help_data, list(rows[0])),
        on_select="rerun",
        selection_mode="single-row",
        key=key if version == 0 else f"{key}_{version}",
    )


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
    with st.expander(
        f"경고 {len(alerts)}건 [근거 충분 {enough}] [더 확인 필요 {len(alerts) - enough}]",
        expanded=True,
    ):
        if not alerts:
            st.text("규칙에 걸린 경고가 없습니다. 이것은 안전하다는 뜻이 아닙니다.")
        rule_by_id = {rule.id: rule for rule in rules}
        for index, alert in enumerate(alerts):
            rule = rule_by_id[alert.rule_id]
            with st.container(border=True):
                st.text(
                    f"[!] [분류: {alert.category}] [level: {alert.level}] "
                    f"[신뢰도: {alert.confidence}]"
                )
                st.text(f"제목: {alert.msg}")
                st.text(f"왜 이상한가: {rule.why}")
                st.text("근거: " + ", ".join(map(str, alert.evidence)) + "  [원본 보기]")
                if alert.confidence == "더 확인 필요":
                    st.text(f"더 확인 필요: {alert.confidence_reason}")
                else:
                    st.text(f"신뢰도 판단: {alert.confidence_reason}")
                st.text(f"다음 확인 단계: {rule.next_steps}")
                st.text(
                    "Wireshark에서는: "
                    f"{rule.wireshark_filter.replace('{track}', alert.track_value)}"
                )
                st.text(f"오해 주의: {rule.caution}")
                choice = st.selectbox(
                    "[원본 보기] 근거 줄/패킷 강조",
                    [None, *alert.evidence],
                    format_func=lambda value: "선택 안 함" if value is None else str(value),
                    key=f"{scope}_alert_evidence_{index}",
                )
                if choice is not None:
                    selected.add(choice)
                if rule.suricata_example:
                    st.caption("Suricata 룰 예시 (참고용, 실행 안 함)")
                    st.code(rule.suricata_example)
    matched_hints = compute_hints(
        hint_items if hint_items is not None else records, hints, hint_target or target
    )
    with st.expander("오해 힌트", expanded=True):
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


st.set_page_config(page_title="easy-log-packet-analyzer", layout="wide")
st.title("easy-log-packet-analyzer")
st.write("로그와 패킷을 한곳에서, 쉬운 한국어로")
st.caption("지원: auth.log(sshd) · access.log · .evtx · .pcap/.pcapng · 최대 10MB")

with st.sidebar:
    st.subheader("시간 연결")
    log_tz = st.text_input("로그 시간대 (log_tz)", value="Asia/Seoul")
    sshd_year = st.number_input("sshd 연도", min_value=1970, max_value=2100, value=None, step=1)
    st.caption("연도는 직접 고른 값")
    window_seconds = int(
        st.number_input("앞뒤 초 (window_seconds)", min_value=0, max_value=86400, value=5, step=1)
    )

time_settings = TimeSettings(
    log_tz=log_tz or "Asia/Seoul",
    sshd_year=int(sshd_year) if sshd_year is not None else None,
    window_seconds=window_seconds,
)

log_upload = st.file_uploader("로그 파일 올리기")
log_type = "sshd"
if log_upload and Path(log_upload.name).suffix.lower() != ".evtx":
    log_type = st.selectbox(
        "로그 형식",
        ["sshd", "access"],
        format_func=lambda value: "auth.log (sshd)" if value == "sshd" else "access.log",
    )
packet_upload = st.file_uploader("패킷 파일 올리기")

if not log_upload and not packet_upload:
    st.info("아직 파일이 없습니다")
    st.write("로그나 pcap 파일을 올리면 여기에 요약이 나옵니다.")
    st.stop()

log_result = packet_result = None
with st.spinner("파일을 읽는 중입니다…"):
    if log_upload:
        try:
            extension = Path(log_upload.name).suffix.lower()
            reader = read_evtx if extension == ".evtx" else lambda path: read_text_log(path, log_type)
            log_result = read_upload(log_upload, reader)
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
chosen_conversation = None
log_kind = (
    "evtx"
    if log_upload and Path(log_upload.name).suffix.lower() == ".evtx"
    else log_type
)
log_points = build_timeline(log_records, log_kind, time_settings)
packet_points = build_timeline(packet_records, "pcap", time_settings)

st.subheader("요약")
metrics = st.columns(4)
metrics[0].metric("로그", len(log_records))
metrics[1].metric("패킷", len(packet_records))
metrics[2].metric("대화", len(conversations))
metrics[3].metric("읽지 못한 줄", log_result.unparsed if log_result else 0)
st.caption("로그·패킷·대화의 전체 건수입니다.")
st.write(_summary_time(log_records, packet_records, log_kind, time_settings))

log_tab, packet_tab, conversation_tab = st.tabs(["로그 탭", "패킷 탭", "대화 요약 탭"])
with log_tab:
    if log_result:
        alert_highlights = _render_alerts(
            log_records, log_kind, time_settings, scope="log", unparsed=log_result.unparsed
        )
        _show_parse_notices(log_result)
        _show_unparsed(log_result)
        if not log_records and log_result.unparsed:
            st.error("읽을 수 없는 로그 형식입니다")
            st.write(
                "지금은 auth.log(sshd), Apache/Nginx access.log,\n"
                "Windows .evtx만 읽습니다. 이 파일에서 읽은 줄은 0줄입니다.\n\n"
                "지원 목록과 샘플 링크를 확인해 주세요."
            )
            st.caption("지원 형식 보기 · 다른 파일 올리기")
        else:
            visible_log_records = _filtered_records(log_records, "로그")
            time_center = st.session_state.get("time_center")
            time_from = st.session_state.get("time_link_from")
            log_highlights = (
                numbers_near(log_points, time_center, time_settings.window_seconds)
                if time_center is not None and time_from == "packet"
                else set()
            )
            log_highlights |= alert_highlights
            log_event = (
                _render_selectable_table(
                    build_log_table(visible_log_records, log_kind, time_settings, log_highlights),
                    HELP,
                    key="log_table",
                )
                if visible_log_records
                else None
            )
            _render_filter_commands(
                st.session_state["step6_로그"], log_upload.name, log_kind == "access"
            )
            log_rows = log_event.selection.rows if log_event is not None else []
            prev_log_rows = st.session_state.get("prev_log_rows", [])
            st.session_state["prev_log_rows"] = list(log_rows)
            if log_rows != prev_log_rows:
                if log_rows:
                    st.session_state["packet_table_version"] = st.session_state.get("packet_table_version", 0) + 1
                    st.session_state["prev_packet_rows"] = []
                    when = record_time(visible_log_records[log_rows[0]], log_kind, time_settings)
                    if when is not None:
                        st.session_state["time_center"] = when
                        st.session_state["time_link_from"] = "log"
                elif st.session_state.get("time_link_from") == "log":
                    st.session_state.pop("time_center", None)
                    st.session_state.pop("time_link_from", None)
                st.rerun()
            time_center = st.session_state.get("time_center")
            time_from = st.session_state.get("time_link_from")
            if time_center is not None and time_from == "log":
                st.info("패킷 탭에서 강조해 두었습니다")
            elif time_center is not None and time_from == "packet":
                st.info("패킷 탭에서 고른 시각 앞뒤 몇 초를 강조해 두었습니다")
    else:
        st.info("아직 파일이 없습니다")
        st.write("로그나 pcap 파일을 올리면 여기에 요약이 나옵니다.")

with conversation_tab:
    st.write("대화를 먼저 보고, 필요하면 패킷으로 내려갑니다")
    if packet_result:
        conversation_alert_highlights = _render_alerts(
            packet_records,
            "pcap",
            time_settings,
            scope="conversation",
            unparsed=packet_result.unparsed,
            hint_items=conversations,
            hint_target="conversation",
        )
        st.session_state["step7_conversation_highlights"] = conversation_alert_highlights
        conversation_rows = build_conversation_table(conversations)
        if conversation_rows:
            event = st.dataframe(
                pd.DataFrame(conversation_rows),
                width="stretch",
                hide_index=True,
                column_config=_columns(HELP, list(conversation_rows[0])),
                on_select="rerun",
                selection_mode="single-row",
                key="conversation_table",
            )
            selected_rows = event.selection.rows
            if selected_rows:
                chosen_conversation = conversations[selected_rows[0]]
        else:
            _show_empty_records("conversation_empty")
    else:
        st.info("아직 파일이 없습니다")
        st.write("로그나 pcap 파일을 올리면 여기에 요약이 나옵니다.")

with packet_tab:
    if packet_result:
        alert_highlights = _render_alerts(
            packet_records, "pcap", time_settings, scope="packet", unparsed=packet_result.unparsed
        )
        _show_parse_notices(packet_result, packets=True)
        time_center = st.session_state.get("time_center")
        time_from = st.session_state.get("time_link_from")
        time_highlights = (
            numbers_near(packet_points, time_center, time_settings.window_seconds)
            if time_center is not None and time_from == "log"
            else set()
        )
        conversation_highlights = (
            set(chosen_conversation.packet_numbers) if chosen_conversation else set()
        )
        highlighted = (
            conversation_highlights
            | time_highlights
            | alert_highlights
            | st.session_state.get("step7_conversation_highlights", set())
        )
        visible_packet_records = _filtered_records(packet_records, "패킷")
        packet_rows = build_packet_table(visible_packet_records, highlighted)
        if visible_packet_records:
            packet_event = _render_selectable_table(
                packet_rows, HELP, key="packet_table"
            )
            packet_rows_sel = packet_event.selection.rows if packet_event is not None else []
            prev_packet_rows = st.session_state.get("prev_packet_rows", [])
            st.session_state["prev_packet_rows"] = list(packet_rows_sel)
            if packet_rows_sel != prev_packet_rows:
                if packet_rows_sel:
                    st.session_state["log_table_version"] = st.session_state.get("log_table_version", 0) + 1
                    st.session_state["prev_log_rows"] = []
                    when = record_time(visible_packet_records[packet_rows_sel[0]], "pcap", time_settings)
                    if when is not None:
                        st.session_state["time_center"] = when
                        st.session_state["time_link_from"] = "packet"
                elif st.session_state.get("time_link_from") == "packet":
                    st.session_state.pop("time_center", None)
                    st.session_state.pop("time_link_from", None)
                st.rerun()
            if chosen_conversation and conversation_highlights:
                st.info(f"대화 {chosen_conversation.uid}의 패킷을 강조해 두었습니다")
            time_center = st.session_state.get("time_center")
            time_from = st.session_state.get("time_link_from")
            if time_center is not None and time_from == "log":
                st.info("로그 탭에서 고른 시각 앞뒤 몇 초를 강조해 두었습니다")
            elif time_center is not None and time_from == "packet":
                st.info("로그 탭에서 강조해 두었습니다")
            selected_packet = st.selectbox(
                "패킷 상세",
                range(len(visible_packet_records)),
                format_func=lambda i: f"패킷 #{visible_packet_records[i].line_number}",
            )
            record = visible_packet_records[selected_packet]
            with st.expander(f"#{record.line_number} {record.fields.get('summary') or record.kind}"):
                st.write({key: value for key, value in record.fields.items() if value is not None})
                st.text(f"Wireshark에서는: frame.number == {record.line_number}")
                st.text("원본 값: 확인 못 함")
        _render_filter_commands(
            st.session_state["step6_패킷"], packet_upload.name
        )
        if not packet_records and not packet_result.notices:
            _show_empty_records("packet_empty")
    else:
        st.info("아직 파일이 없습니다")
        st.write("로그나 pcap 파일을 올리면 여기에 요약이 나옵니다.")
