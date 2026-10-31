"""Step 7.5: layer help box and beginner scenarios (layers.yaml, scenarios.yaml)."""

from __future__ import annotations

import html
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from pathlib import Path

import yaml

from elpa.conversations import Conversation
from elpa.limits import open_checked, read_bounded
from elpa.models import Record

_LAYERS_PATH = Path(__file__).resolve().parents[1] / "layers.yaml"
_SCENARIOS_PATH = Path(__file__).resolve().parents[1] / "scenarios.yaml"

_VALID_LAYER_IDS = frozenset({"link", "ip", "transport", "app", "log_auth", "log_web"})
_PACKET_LAYER_IDS = ("app", "transport", "ip", "link")
_LOG_AUTH_KINDS = frozenset({"sshd 실패", "sshd 성공", "sshd 없는 사용자", "sshd", "evtx"})
_ALLOWED_LAYER_KEYS = frozenset({"id", "name", "order", "text", "app_names"})
_ALLOWED_SCENARIO_KEYS = frozenset(
    {"id", "layer", "match", "title", "why", "check_next", "caution"}
)


@dataclass(frozen=True)
class LayerInfo:
    id: str
    name: str
    order: int
    text: str


@dataclass(frozen=True)
class Scenario:
    id: str
    layer: str
    match: dict[str, str]
    title: str
    why: str
    check_next: tuple[str, ...]
    caution: str


@dataclass(frozen=True)
class LayerHelp:
    layers: tuple[LayerInfo, ...]
    current: str | None
    scenarios: tuple[Scenario, ...]
    notes: tuple[str, ...] = ()

    @property
    def present(self) -> tuple[str, ...]:
        return getattr(self, "_present", (self.current,) if self.current else ())

    @property
    def layer_labels(self) -> dict[str, str]:
        return dict(getattr(self, "_layer_labels", {}))


class _LayerTuple(tuple[LayerInfo, ...]):
    """Tuple of LayerInfo that also remembers app_names loaded from layers.yaml."""

    app_names: tuple[str, ...] = ()

    def __new__(
        cls, items: Sequence[LayerInfo], app_names: Sequence[str] = ()
    ) -> _LayerTuple:
        obj = super().__new__(cls, items)
        obj.app_names = tuple(app_names)
        return obj


def _parse_app_names(raw: object) -> tuple[str, ...] | None:
    if not isinstance(raw, list) or not all(
        isinstance(x, str) and x.strip() for x in raw
    ):
        return None
    return tuple(x.strip() for x in raw)


def _parse_layer_entry(
    entry: object, index: int
) -> tuple[LayerInfo | None, tuple[str, ...] | None, str | None]:
    if not isinstance(entry, dict):
        return None, None, f"layers.yaml {index}번째 항목이 사전 형식이 아니라 건너뛰었습니다"
    unknown = set(entry.keys()) - _ALLOWED_LAYER_KEYS
    if unknown:
        names = ", ".join(sorted(map(str, unknown)))
        return None, None, f"layers.yaml {index}번째 항목에 알 수 없는 칸({names})이 있어 건너뛰었습니다"

    layer_id = entry.get("id")
    name = entry.get("name")
    order = entry.get("order")
    text = entry.get("text")
    entry_apps: tuple[str, ...] | None = None
    if "app_names" in entry:
        entry_apps = _parse_app_names(entry.get("app_names"))
        if entry_apps is None:
            return None, None, f"layers.yaml {index}번째 항목({layer_id or '?'})의 app_names가 올바르지 않아 건너뛰었습니다"

    if (
        not isinstance(layer_id, str)
        or layer_id not in _VALID_LAYER_IDS
        or not isinstance(name, str)
        or not name.strip()
        or isinstance(order, bool)
        or not isinstance(order, int)
        or not isinstance(text, str)
        or not text.strip()
    ):
        return (
            None,
            None,
            f"layers.yaml {index}번째 항목({layer_id or '?'})의 필수 칸이 빠졌거나 잘못되어 건너뛰었습니다",
        )

    return (
        LayerInfo(id=layer_id, name=name, order=order, text=text),
        entry_apps,
        None,
    )


def load_layers(
    path: str | Path = _LAYERS_PATH, notices: list[str] | None = None
) -> tuple[tuple[LayerInfo, ...], list[str]]:
    """Load layers.yaml via yaml.safe_load; skip invalid entries with notices."""
    out_notices: list[str] = []
    try:
        with open_checked(str(path)) as f:
            raw = read_bounded(f).decode("utf-8")
        data = yaml.safe_load(raw)
    except (OSError, ValueError, UnicodeDecodeError, yaml.YAMLError):
        out_notices.append("layers.yaml을 읽지 못해 계층 설명을 비웠습니다")
        if notices is not None:
            notices.extend(out_notices)
        return _LayerTuple(()), out_notices

    app_names: list[str] = []
    raw_layers: object
    if isinstance(data, dict):
        unknown_top = set(data.keys()) - {"layers", "app_names"}
        if unknown_top:
            names = ", ".join(sorted(map(str, unknown_top)))
            out_notices.append(f"layers.yaml에 알 수 없는 상위 칸({names})이 있습니다")
        if "app_names" in data:
            parsed_apps = _parse_app_names(data.get("app_names"))
            if parsed_apps is None:
                out_notices.append("layers.yaml의 app_names 형식이 올바르지 않아 무시했습니다")
            else:
                app_names.extend(parsed_apps)
        raw_layers = data.get("layers")
    else:
        raw_layers = data

    if not isinstance(raw_layers, list):
        out_notices.append("layers.yaml 형식이 올바르지 않아 계층 설명을 비웠습니다")
        if notices is not None:
            notices.extend(out_notices)
        return _LayerTuple((), app_names), out_notices

    layers: list[LayerInfo] = []
    for idx, entry in enumerate(raw_layers, start=1):
        if isinstance(entry, dict) and set(entry.keys()) == {"app_names"}:
            parsed_apps = _parse_app_names(entry.get("app_names"))
            if parsed_apps is None:
                out_notices.append(f"layers.yaml {idx}번째 app_names 형식이 올바르지 않아 건너뛰었습니다")
            else:
                app_names.extend(parsed_apps)
            continue
        info, entry_apps, err = _parse_layer_entry(entry, idx)
        if err is not None:
            out_notices.append(err)
        elif info is not None:
            layers.append(info)
            if entry_apps:
                app_names.extend(entry_apps)

    if notices is not None:
        notices.extend(out_notices)
    return _LayerTuple(layers, app_names), out_notices


def _parse_scenario(entry: object, index: int) -> tuple[Scenario | None, str | None]:
    if not isinstance(entry, dict):
        return None, f"scenarios.yaml {index}번째 항목이 사전 형식이 아니라 건너뛰었습니다"
    unknown = set(entry.keys()) - _ALLOWED_SCENARIO_KEYS
    if unknown:
        names = ", ".join(sorted(map(str, unknown)))
        return None, f"scenarios.yaml {index}번째 항목에 알 수 없는 칸({names})이 있어 건너뛰었습니다"

    sc_id = entry.get("id")
    layer = entry.get("layer")
    raw_match = entry.get("match")
    title = entry.get("title")
    why = entry.get("why")
    raw_check = entry.get("check_next")
    caution = entry.get("caution")

    match_dict: dict[str, str] | None = None
    if isinstance(raw_match, dict) and raw_match:
        converted: dict[str, str] = {}
        ok = True
        for k, v in raw_match.items():
            if (
                not isinstance(k, str)
                or not k.strip()
                or v is None
                or isinstance(v, (bool, list, dict))
                or (isinstance(v, str) and not v.strip())
            ):
                ok = False
                break
            converted[k] = str(v)
        if ok:
            match_dict = converted

    check_tuple: tuple[str, ...] | None = None
    if (
        isinstance(raw_check, list)
        and raw_check
        and all(isinstance(x, str) and x.strip() for x in raw_check)
    ):
        check_tuple = tuple(x for x in raw_check)

    if (
        not isinstance(sc_id, str)
        or not sc_id.strip()
        or not isinstance(layer, str)
        or layer not in _VALID_LAYER_IDS
        or match_dict is None
        or not isinstance(title, str)
        or not title.strip()
        or not isinstance(why, str)
        or not why.strip()
        or check_tuple is None
        or not isinstance(caution, str)
        or not caution.strip()
    ):
        return (
            None,
            f"scenarios.yaml {index}번째 시나리오({sc_id or '?'})의 필수 칸이 빠졌거나 잘못되어 건너뛰었습니다",
        )

    return (
        Scenario(
            id=sc_id,
            layer=layer,
            match=match_dict,
            title=title,
            why=why,
            check_next=check_tuple,
            caution=caution,
        ),
        None,
    )


def load_scenarios(
    path: str | Path = _SCENARIOS_PATH, notices: list[str] | None = None
) -> tuple[tuple[Scenario, ...], list[str]]:
    """Load scenarios.yaml via yaml.safe_load; skip invalid entries with notices."""
    out_notices: list[str] = []
    try:
        with open_checked(str(path)) as f:
            raw = read_bounded(f).decode("utf-8")
        data = yaml.safe_load(raw)
    except (OSError, ValueError, UnicodeDecodeError, yaml.YAMLError):
        out_notices.append("scenarios.yaml을 읽지 못해 상황 예시를 비웠습니다")
        if notices is not None:
            notices.extend(out_notices)
        return (), out_notices

    if not isinstance(data, list):
        out_notices.append("scenarios.yaml 형식이 올바르지 않아 상황 예시를 비웠습니다")
        if notices is not None:
            notices.extend(out_notices)
        return (), out_notices

    scenarios: list[Scenario] = []
    for idx, entry in enumerate(data, start=1):
        sc, err = _parse_scenario(entry, idx)
        if err is not None:
            out_notices.append(err)
        elif sc is not None:
            scenarios.append(sc)

    if notices is not None:
        notices.extend(out_notices)
    return tuple(scenarios), out_notices


def _normalize_source(
    item: Record | Conversation, source: str | None
) -> str:
    if source in ("packet", "pcap"):
        return "packet"
    if source in ("log", "sshd", "access", "evtx"):
        return "log"
    if source == "conversation":
        return "conversation"
    if isinstance(item, Conversation):
        return "conversation"
    if "transport" in item.fields or "summary" in item.fields:
        return "packet"
    if item.kind in _LOG_AUTH_KINDS or item.kind == "access.log":
        return "log"
    return source or "packet"


def _resolve_app_names(
    layers: Sequence[LayerInfo] | None = None,
    app_names: Collection[str] | None = None,
) -> frozenset[str]:
    if app_names is not None:
        return frozenset(app_names)
    if layers is not None:
        attached = getattr(layers, "app_names", None)
        if attached is not None:
            return frozenset(attached)
    loaded, _ = load_layers()
    return frozenset(getattr(loaded, "app_names", ()))


def _packet_token_layer(token: str, app_names: Collection[str]) -> str | None:
    if token in app_names:
        return "app"
    if token in ("TCP", "UDP"):
        return "transport"
    if token in ("IP", "IPv6"):
        return "ip"
    if token == "Ethernet":
        return "link"
    return None


def layer_of(
    record_or_conversation: Record | Conversation,
    source: str | None = None,
    layers: Sequence[LayerInfo] | None = None,
    *,
    app_names: Collection[str] | None = None,
) -> str | None:
    """Map a Record or Conversation to its layer id, or None if unmapped."""
    norm_source = _normalize_source(record_or_conversation, source)
    resolved_apps = _resolve_app_names(layers, app_names)

    if norm_source == "conversation":
        if isinstance(record_or_conversation, Conversation):
            proto = record_or_conversation.protocol
        elif isinstance(record_or_conversation, Record):
            proto = (
                record_or_conversation.fields.get("protocol")
                or record_or_conversation.kind
            )
        else:
            return None
        return "transport" if proto in ("TCP", "UDP") else None

    if not isinstance(record_or_conversation, Record):
        return None

    kind = record_or_conversation.kind
    if norm_source == "packet":
        return _packet_token_layer(kind, resolved_apps)

    if norm_source == "log":
        if kind in _LOG_AUTH_KINDS:
            return "log_auth"
        if kind == "access.log":
            return "log_web"
        return None

    return None


def _item_value(
    item: Record | Conversation, norm_source: str, raw_source: str | None, key: str
) -> str | None:
    if key == "source":
        return norm_source
    if isinstance(item, Record):
        if key == "kind":
            return item.kind
        val = item.fields.get(key)
        return str(val) if val is not None else None
    if isinstance(item, Conversation):
        if key == "kind":
            return item.service
        if hasattr(item, key):
            val = getattr(item, key)
            return str(val) if val is not None else None
    return None


def scenarios_for(
    item: Record | Conversation,
    source: str | None = None,
    scenarios: Sequence[Scenario] | None = None,
) -> tuple[Scenario, ...]:
    """Return up to 3 matching scenarios in file order using equality-only matching."""
    norm_source = _normalize_source(item, source)
    if scenarios is None:
        scenarios, _ = load_scenarios()

    matched: list[Scenario] = []
    for sc in scenarios:
        if not sc.match:
            continue
        ok = True
        for k, expected in sc.match.items():
            if k == "source":
                if expected not in (norm_source, source):
                    ok = False
                    break
                continue
            actual = _item_value(item, norm_source, source, k)
            if actual is None or actual != expected:
                ok = False
                break
        if ok:
            matched.append(sc)
            if len(matched) == 3:
                break
    return tuple(matched)


def _extract_present_and_labels(
    item: Record | Conversation,
    norm_source: str,
    current: str | None,
    app_names: Collection[str],
) -> tuple[tuple[str, ...], dict[str, str], tuple[str, ...]]:
    present: list[str] = []
    labels: dict[str, str] = {}
    raw_tokens: list[str] = []

    if norm_source == "packet" and isinstance(item, Record):
        if item.kind:
            raw_tokens.append(item.kind)
        summary = item.fields.get("summary") or ""
        if summary:
            for part in summary.split(" / "):
                token = part.strip()
                if not token:
                    continue
                if token not in raw_tokens:
                    raw_tokens.append(token)
                lid = _packet_token_layer(token, app_names)
                if lid is not None:
                    labels[lid] = token
                    if lid not in present:
                        present.append(lid)
        if current is not None:
            labels.setdefault(current, item.kind)
            if current not in present:
                present.append(current)
        for v in item.fields.values():
            if v and v not in raw_tokens:
                raw_tokens.append(str(v))
        if item.raw and item.raw not in raw_tokens:
            raw_tokens.append(item.raw)
    elif norm_source == "conversation":
        if isinstance(item, Conversation):
            proto = item.protocol
            service = item.service
            if proto:
                raw_tokens.append(proto)
            if service and service not in raw_tokens:
                raw_tokens.append(service)
            if current == "transport":
                labels["transport"] = proto
                present.append("transport")
            if service in app_names:
                labels["app"] = service
                present.append("app")
        elif isinstance(item, Record):
            proto = item.fields.get("protocol") or item.kind
            service = item.fields.get("service") or item.kind
            if proto:
                raw_tokens.append(proto)
            if current == "transport":
                labels["transport"] = proto
                present.append("transport")
            if service in app_names:
                labels["app"] = service
                present.append("app")
    elif norm_source == "log" and isinstance(item, Record):
        if item.kind:
            raw_tokens.append(item.kind)
        if current is not None:
            labels[current] = item.kind
            present.append(current)
        for v in item.fields.values():
            if v and v not in raw_tokens:
                raw_tokens.append(str(v))
        if item.raw and item.raw not in raw_tokens:
            raw_tokens.append(item.raw)

    ordered_present = tuple(
        lid for lid in (*_PACKET_LAYER_IDS, "log_auth", "log_web") if lid in present
    )
    return ordered_present, labels, tuple(raw_tokens)


def build_layer_help(
    item: Record | Conversation,
    source: str | None = None,
    layers: Sequence[LayerInfo] | None = None,
    scenarios: Sequence[Scenario] | None = None,
) -> LayerHelp:
    """Build LayerHelp for a selected Record or Conversation."""
    notes: list[str] = []
    if layers is None:
        layers, layer_notices = load_layers()
        notes.extend(layer_notices)
    if scenarios is None:
        scenarios, scenario_notices = load_scenarios()
        notes.extend(scenario_notices)

    norm_source = _normalize_source(item, source)
    app_names = _resolve_app_names(layers)
    layer_by_id = {layer.id: layer for layer in layers}

    raw_current = (
        layer_of(item, norm_source, layers, app_names=app_names)
        if layers
        else None
    )
    current = raw_current if raw_current in layer_by_id else None

    if norm_source in ("packet", "conversation"):
        display_layers = tuple(
            sorted(
                (l for l in layers if l.id in _PACKET_LAYER_IDS),
                key=lambda l: l.order,
                reverse=True,
            )
        )
    else:
        display_layers = (
            (layer_by_id[current],)
            if current is not None and current in layer_by_id
            else ()
        )

    matched_scenarios = (
        scenarios_for(item, norm_source, scenarios)
        if current is not None
        else ()
    )

    if current is None:
        notes.append("설명 없음")
    if not matched_scenarios:
        notes.append("이 기록에 맞는 예시 상황: 설명 없음")

    present, labels, raw_tokens = _extract_present_and_labels(
        item, norm_source, current, app_names
    )

    result = LayerHelp(
        layers=display_layers,
        current=current,
        scenarios=matched_scenarios,
        notes=tuple(notes),
    )
    object.__setattr__(result, "_present", present)
    object.__setattr__(result, "_layer_labels", labels)
    object.__setattr__(result, "_raw_tokens", raw_tokens)
    return result


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def render_layer_help(
    help_or_item: LayerHelp | Record | Conversation,
    item: Record | Conversation | None = None,
    source: str | None = None,
    layers: Sequence[LayerInfo] | None = None,
    scenarios: Sequence[Scenario] | None = None,
) -> str:
    """Render the layer picture and scenarios as a safe HTML string."""
    if isinstance(help_or_item, LayerHelp):
        layer_help = help_or_item
        if item is not None:
            norm_source = _normalize_source(item, source)
            app_names = _resolve_app_names(layer_help.layers)
            present, labels, raw_tokens = _extract_present_and_labels(
                item, norm_source, layer_help.current, app_names
            )
        else:
            present = layer_help.present
            labels = layer_help.layer_labels
            raw_tokens = getattr(layer_help, "_raw_tokens", ())
    else:
        layer_help = build_layer_help(
            help_or_item, source=source, layers=layers, scenarios=scenarios
        )
        present = layer_help.present
        labels = layer_help.layer_labels
        raw_tokens = getattr(layer_help, "_raw_tokens", ())

    parts: list[str] = [
        '<div class="elpa-layer-help" style="border: 1px solid #cbd5e1; border-radius: 6px; padding: 12px;">',
        '<div style="font-weight: 700; margin-bottom: 8px;">이 기록은 어느 계층?</div>',
    ]

    ordered_layers = sorted(layer_help.layers, key=lambda l: l.order, reverse=True)
    current_info: LayerInfo | None = None

    if not ordered_layers or layer_help.current is None:
        raw_suffix = (
            f" ({', '.join(_esc(t) for t in raw_tokens)})" if raw_tokens else ""
        )
        parts.append(f"<div>설명 없음{raw_suffix}</div>")
    else:
        for layer in ordered_layers:
            if layer.id == layer_help.current:
                current_info = layer
            is_current = layer.id == layer_help.current
            is_present = layer.id in present or is_current
            label_text = labels.get(layer.id, "")
            escaped_label = f" {_esc(label_text)}" if label_text else ""

            if is_current:
                style = (
                    "border: 2px solid #0f172a; font-weight: 700; "
                    "padding: 6px 10px; margin: 4px 0; border-radius: 4px;"
                )
                marker = "▶ "
                status = "← 지금 고른 것 (들어 있음)" if is_present else "← 지금 고른 것"
            elif is_present:
                style = (
                    "border: 1px solid #94a3b8; "
                    "padding: 6px 10px; margin: 4px 0; border-radius: 4px;"
                )
                marker = "&nbsp;&nbsp;"
                status = "들어 있음"
            else:
                style = (
                    "border: 1px solid #e2e8f0; "
                    "padding: 6px 10px; margin: 4px 0; border-radius: 4px;"
                )
                marker = "&nbsp;&nbsp;"
                status = "없음"

            parts.append(
                f'<div data-layer="{_esc(layer.id)}" style="{style}">'
                f"{marker}[{_esc(layer.name)}]{escaped_label} "
                f"<span>{_esc(status)}</span>"
                f"</div>"
            )

        if current_info is not None:
            parts.append(
                f'<div style="margin-top: 8px;">'
                f"{_esc(current_info.name)}: {_esc(current_info.text)}"
                f"</div>"
            )
        else:
            parts.append('<div style="margin-top: 8px;">설명 없음</div>')

        if raw_tokens:
            escaped_tokens = ", ".join(_esc(t) for t in raw_tokens)
            parts.append(
                f'<div style="display:none;" data-raw="{escaped_tokens}"></div>'
            )

    parts.append('<hr style="margin: 10px 0; border: 0; border-top: 1px solid #cbd5e1;" />')
    parts.append('<div style="font-weight: 700; margin-bottom: 6px;">이런 상황에서 보입니다</div>')

    if layer_help.scenarios:
        for sc in layer_help.scenarios:
            checks = ", ".join(_esc(c) for c in sc.check_next)
            parts.append(
                '<div style="margin-bottom: 8px;">'
                f'<div style="font-weight: 600;">{_esc(sc.title)}</div>'
                f"<div>왜: {_esc(sc.why)}</div>"
                f"<div>다음에 볼 것: {checks}</div>"
                f"<div>오해 주의: {_esc(sc.caution)}</div>"
                "</div>"
            )
    else:
        parts.append("<div>이 기록에 맞는 예시 상황: 설명 없음</div>")

    if layer_help.notes:
        for note in layer_help.notes:
            parts.append(f'<div class="elpa-layer-note">{_esc(note)}</div>')

    parts.append("</div>")
    return "\n".join(parts)


render_layer_picture = render_layer_help
render_layers_html = render_layer_help
