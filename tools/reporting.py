from __future__ import annotations

import dataclasses
import html
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from tools.analyzer import AnalysisReport, Finding, Indicator


@dataclasses.dataclass
class ReportFiles:
    html_path: Path


KIND_LABELS = {
    "domain": "Домен",
    "email": "Email",
    "ip": "IP",
    "phone": "Телефон",
    "telegram": "Telegram",
    "unknown": "Неизвестно",
    "url": "URL",
    "username": "Username",
}

LEVEL_LABELS = {
    "error": "Ошибка",
    "high": "Высокий",
    "info": "Инфо",
    "warning": "Проверить",
}

KIND_COLORS = {
    "domain": "#11a36a",
    "email": "#2f80ed",
    "ip": "#d8841f",
    "phone": "#0f9f8f",
    "telegram": "#229ed9",
    "url": "#d6536d",
    "username": "#7c5cc4",
    "unknown": "#7a8694",
}

TOOL_CATEGORY_LABELS = {
    "username": "Username tools",
    "email": "Email tools",
    "phone": "Phone tools",
    "telegram": "Telegram tools",
    "breach": "Breach tools",
    "infrastructure": "Infrastructure tools",
    "url": "URL discovery tools",
    "orchestrator": "Runner status",
}


def _slug(value: str, limit: int = 42) -> str:
    value = re.sub(r"[^A-Za-z0-9_.@+-]+", "_", value).strip("_")
    return (value[:limit] or "report").strip("._")


def _to_dict(report: AnalysisReport) -> Dict[str, Any]:
    return dataclasses.asdict(report)


def _format_value(value: Any) -> str:
    if value is None or value == "":
        return "-"
    if isinstance(value, bool):
        return "да" if value else "нет"
    if isinstance(value, (list, tuple)):
        return ", ".join(_format_value(item) for item in value) or "-"
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, indent=2)
    return str(value)


def _short_value(value: Any, limit: int = 180) -> str:
    text = re.sub(r"\s+", " ", _format_value(value)).strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"


def _dict_preview(data: Dict[str, Any], keys: Iterable[str], item_limit: int = 5) -> str:
    parts = []
    for key in keys:
        value = data.get(key)
        if value in (None, "", [], {}):
            continue
        parts.append(f"{key}: {_short_value(value, 90)}")
        if len(parts) >= item_limit:
            break
    return "; ".join(parts)


def _finding_preview(finding: Finding) -> str:
    details = finding.details if isinstance(finding.details, dict) else {}

    if finding.source in {"tool_orchestrator", "tool_inventory"}:
        enabled = details.get("ENABLE_TOOL_RUNNERS")
        personal_enabled = details.get("ENABLE_PERSONAL_OSINT_TOOLS")
        available = details.get("available_tools") or []
        configured = details.get("enabled_tools") or []
        if enabled is False:
            return (
                "CLI runners выключены: ENABLE_TOOL_RUNNERS=0. "
                f"Локально найдено: {_short_value(available) if available else 'нет'}."
            )
        if personal_enabled is False:
            return (
                "Personal OSINT tools выключены: ENABLE_PERSONAL_OSINT_TOOLS=0. "
                f"Включённые runner-ы: {_short_value(configured) if configured else 'нет'}."
            )
        return (
            f"Включённые runner-ы: {_short_value(configured) if configured else 'нет'}; "
            f"локально найдено: {_short_value(available) if available else 'нет'}."
        )

    if finding.source.startswith("tool_"):
        if details.get("error") and not details.get("ok"):
            return _short_value(details.get("error"), 260)
        stdout = details.get("stdout")
        if isinstance(stdout, dict):
            if "raw" in stdout:
                return _short_value(stdout.get("raw"), 260)
            if "json" in stdout:
                return _short_value(stdout.get("json"), 260)
            if "json_lines" in stdout:
                return _short_value(stdout.get("json_lines"), 260)
            if "csv_rows" in stdout:
                return _short_value(stdout.get("csv_rows"), 260)
            if "text_file" in stdout:
                return _short_value(stdout.get("text_file"), 260)
        return _dict_preview(details, ("ok", "configured", "returncode", "command"), 4)

    if finding.source == "external_api_config":
        public_sources = details.get("public_sources_enabled") or {}
        api_keys = details.get("api_keys_configured") or {}
        enabled_sources = [key for key, value in public_sources.items() if value]
        configured_keys = [key for key, value in api_keys.items() if value]
        return (
            f"Публичные источники: {_short_value(enabled_sources) if enabled_sources else 'нет'}; "
            f"API-ключи: {_short_value(configured_keys) if configured_keys else 'нет'}."
        )

    if finding.source == "web_discovery":
        pivots = details.get("pivots") if isinstance(details.get("pivots"), list) else []
        if not pivots:
            return ""
        first = pivots[0] if isinstance(pivots[0], dict) else {}
        links = first.get("links") if isinstance(first.get("links"), dict) else {}
        return (
            f"Пивотов: {len(pivots)}; первый: {first.get('kind')} {first.get('target')}; "
            f"ссылки: {_short_value(list(links.keys())[:6])}."
        )

    data = details.get("data")
    if isinstance(data, dict):
        preferred = (
            "status",
            "country",
            "countryCode",
            "regionName",
            "city",
            "isp",
            "org",
            "as",
            "reverse",
            "name",
            "ldhName",
            "handle",
            "type",
            "startAddress",
            "endAddress",
            "nameservers",
            "events",
            "reputation",
            "last_analysis_stats",
            "certificate_rows_seen",
            "unique_names_sample",
        )
        preview = _dict_preview(data, preferred, 5)
        return preview or _dict_preview(data, data.keys(), 4)

    if isinstance(data, list):
        return f"Элементов: {len(data)}; первый: {_short_value(data[0], 220) if data else '-'}"

    if details.get("error"):
        return _short_value(details.get("error"), 260)

    return _dict_preview(
        details,
        (
            "title",
            "description",
            "extra",
            "action",
            "public_posts_found",
            "reason",
            "note",
            "url",
        ),
        4,
    )


def _indicator_label(indicator: Indicator) -> str:
    return KIND_LABELS.get(indicator.kind, indicator.kind)


def _finding_level(finding: Finding) -> str:
    return LEVEL_LABELS.get(finding.level, finding.level)


def _json_block(value: Any) -> str:
    return html.escape(json.dumps(value, ensure_ascii=False, indent=2, default=str))


def _source_target_kind(source: str) -> str | None:
    if source in {"tool_maigret", "tool_sherlock", "tool_blackbird", "tool_social_analyzer"}:
        return "username"
    if source == "tool_socialscan":
        return "username"
    if source in {"tool_holehe", "tool_ghunt", "tool_h8mail", "tool_detectdee"}:
        return "email"
    if source in {"tool_phoneinfoga", "tool_ignorant"}:
        return "phone"
    if source in {"tool_telepathy", "tool_telerecon"}:
        return "telegram"
    if source in {
        "tool_spiderfoot",
        "tool_theharvester",
        "tool_subfinder",
        "tool_amass_passive",
        "tool_assetfinder",
        "tool_orchestrator",
    }:
        return None
    if source in {"tool_waybackurls", "tool_urlfinder"}:
        return "url"
    if source.startswith("telegram"):
        return "telegram"
    if source == "spiderfoot":
        return None
    if source == "web_discovery":
        return None
    if source.startswith("domain") or source in {"rdap_domain", "certificate_transparency", "virustotal_domain"}:
        return "domain"
    if source.startswith("ip") or source in {"rdap_ip", "abuseipdb", "ipinfo", "virustotal_ip"}:
        return "ip"
    if source.startswith("url") or source == "virustotal_url":
        return "url"
    if source.startswith("email"):
        return "email"
    if source.startswith("phone"):
        return "phone"
    if source.startswith("username"):
        return "username"
    return None


def _indicator_highlights(indicator: Indicator) -> List[str]:
    meta = indicator.metadata

    def kv(label: str, value: Any) -> str:
        if value in (None, "", [], {}):
            return ""
        return f"{label}: {_format_value(value)}"

    if indicator.kind == "telegram":
        return [
            kv("Username", f"@{meta.get('username')}" if meta.get("username") else None),
            kv("t.me", meta.get("public_url")),
            kv("Bot API", meta.get("bot_api_accessible")),
            kv("Тип чата", meta.get("chat_type")),
        ]
    if indicator.kind == "phone":
        return [
            kv("E.164", meta.get("e164")),
            kv("Регион", meta.get("region_code")),
            kv("Тип", meta.get("type")),
            kv("Оператор", meta.get("carrier")),
            kv("Ошибка", meta.get("error")),
        ]
    if indicator.kind == "email":
        return [
            kv("Домен", meta.get("domain")),
            kv("MX", meta.get("has_mx")),
            kv("SPF", meta.get("has_spf")),
            kv("DMARC", meta.get("has_dmarc")),
        ]
    if indicator.kind == "domain":
        return [
            kv("A", meta.get("a_records")),
            kv("NS", meta.get("ns_records")),
            kv("MX", meta.get("mx_records")),
            kv("Найден в", meta.get("observed_in")),
        ]
    if indicator.kind == "ip":
        return [
            kv("Версия", f"IPv{meta.get('version')}" if meta.get("version") else None),
            kv("Публичный", meta.get("is_global")),
            kv("Приватный", meta.get("is_private")),
            kv("Reverse pointer", meta.get("reverse_pointer")),
        ]
    if indicator.kind == "url":
        return [
            kv("Схема", meta.get("scheme")),
            kv("Хост", meta.get("host")),
            kv("Параметров", meta.get("query_parameter_count")),
            kv("Флаги", meta.get("suspicious_flags")),
        ]
    if indicator.kind == "username":
        return [kv("Username", meta.get("username")), "Добавлены ссылки для ручной проверки."]
    return [_format_value(meta.get("note"))]


def format_report_text(report: AnalysisReport, max_chars: int = 3800) -> str:
    valid_count = sum(1 for item in report.indicators if item.valid)
    source_count = len({finding.source for finding in report.findings})
    warning_count = sum(1 for finding in report.findings if finding.level in {"warning", "error", "high"})
    type_counts = Counter(indicator.kind for indicator in report.indicators)

    lines = [
        "<b>OSINT-отчёт</b>",
        f"<b>Запрос:</b> <code>{html.escape(report.query)}</code>",
        f"<b>Индикаторы:</b> {len(report.indicators)} найдено, {valid_count} валидных",
        f"<b>Источники:</b> {source_count} | <b>Предупреждения:</b> {warning_count}",
        "",
        "<b>Типы:</b> "
        + ", ".join(f"{html.escape(KIND_LABELS.get(kind, kind))}: {count}" for kind, count in sorted(type_counts.items())),
        "",
        "<b>Ключевые данные:</b>",
    ]

    for indicator in report.indicators[:10]:
        status = "valid" if indicator.valid else "check"
        lines.append(
            f"• <b>{html.escape(_indicator_label(indicator))}</b>: <code>{html.escape(indicator.normalized)}</code> ({status})"
        )
        for item in _indicator_highlights(indicator)[:4]:
            if item and item != "-":
                lines.append(f"  {html.escape(item)}")

    if report.findings:
        lines.extend(["", "<b>Последние находки:</b>"])
        for finding in report.findings[-12:]:
            target = finding.details.get("target") if isinstance(finding.details, dict) else None
            suffix = f" → {target}" if target else ""
            lines.append(f"• {html.escape(finding.source)}: {html.escape(_finding_level(finding))}{html.escape(suffix)}")
            preview = _finding_preview(finding)
            if preview:
                lines.append(f"  {html.escape(preview)}")

    lines.extend(["", "Полный HTML-отчёт с новой визуализацией, Telegram-блоком, таблицами и JSON прикреплён файлом."])

    result_lines: List[str] = []
    total = 0
    for line in lines:
        next_total = total + len(line) + 1
        if next_total > max_chars:
            result_lines.append("…часть деталей в HTML-отчёте.")
            break
        result_lines.append(line)
        total = next_total
    return "\n".join(result_lines)


def _node_rect(x: int, y: int, width: int, height: int, title: str, subtitle: str, color: str) -> str:
    title = html.escape(title[:30])
    subtitle = html.escape(subtitle[:42])
    return (
        f'<g class="node">'
        f'<rect x="{x}" y="{y}" width="{width}" height="{height}" rx="8" fill="#fff" stroke="{color}" stroke-width="2"/>'
        f'<rect x="{x}" y="{y}" width="8" height="{height}" rx="4" fill="{color}"/>'
        f'<text x="{x + 18}" y="{y + 24}" class="node-title">{title}</text>'
        f'<text x="{x + 18}" y="{y + 44}" class="node-subtitle">{subtitle}</text>'
        "</g>"
    )


def _lane_positions(count: int, height: int, box_height: int = 58) -> List[int]:
    if count <= 0:
        return []
    gap = 78
    total = (count - 1) * gap + box_height
    start = max(92, (height - total) // 2)
    return [start + index * gap for index in range(count)]


def render_svg(report: AnalysisReport) -> str:
    indicators = report.indicators[:14]
    sources = sorted({finding.source for finding in report.findings})[:18]
    source_counts = Counter(finding.source for finding in report.findings)
    warning_sources = {
        finding.source for finding in report.findings if finding.level in {"warning", "error", "high"}
    }

    inventory = None
    for finding in reversed(report.findings):
        if finding.source in {"tool_orchestrator", "tool_inventory"} and isinstance(finding.details, dict):
            configured = finding.details.get("configured_tools")
            if isinstance(configured, dict):
                inventory = finding.details
                break

    configured_tools = inventory.get("configured_tools", {}) if isinstance(inventory, dict) else {}
    enabled_tools = [key for key, item in configured_tools.items() if isinstance(item, dict) and item.get("enabled")]
    available_tools = [key for key, item in configured_tools.items() if isinstance(item, dict) and item.get("available")]

    row_count = max(len(indicators), len(sources), 5)
    width = 1280
    height = max(620, 290 + row_count * 64)
    query_x, indicator_x, source_x = 42, 390, 756
    box_w, box_h = 284, 52
    query_y = 240
    indicator_ys = [250 + index * 64 for index in range(len(indicators))]
    source_ys = [250 + index * 64 for index in range(len(sources))]

    def text(value: Any, limit: int) -> str:
        value = re.sub(r"\s+", " ", _format_value(value)).strip()
        return html.escape(value[:limit])

    def pill(x: int, y: int, label: str, value: Any, color: str) -> str:
        return (
            f'<g><rect x="{x}" y="{y}" width="214" height="58" rx="8" fill="#ffffff" stroke="#d8e0ea"/>'
            f'<rect x="{x}" y="{y}" width="7" height="58" rx="4" fill="{color}"/>'
            f'<text x="{x + 18}" y="{y + 23}" class="metric-label">{html.escape(label)}</text>'
            f'<text x="{x + 18}" y="{y + 44}" class="metric-value">{html.escape(_format_value(value))}</text></g>'
        )

    def node(x: int, y: int, title: str, subtitle: str, color: str, warn: bool = False) -> str:
        stroke = "#d8841f" if warn else color
        badge = "#d8841f" if warn else color
        return (
            f'<g class="node"><rect x="{x}" y="{y}" width="{box_w}" height="{box_h}" rx="8" fill="#ffffff" stroke="{stroke}" stroke-width="1.8"/>'
            f'<rect x="{x}" y="{y}" width="8" height="{box_h}" rx="4" fill="{badge}"/>'
            f'<text x="{x + 18}" y="{y + 21}" class="node-title">{text(title, 31)}</text>'
            f'<text x="{x + 18}" y="{y + 40}" class="node-subtitle">{text(subtitle, 42)}</text></g>'
        )

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="OSINT workflow visualization">',
        "<style>",
        "svg{font-family:Arial,sans-serif;background:#eef3f8}",
        ".title{font-size:27px;font-weight:900;fill:#101820}",
        ".subtitle{font-size:13px;fill:#607086}",
        ".lane{fill:#f8fbff;stroke:#d8e0ea}",
        ".lane-label{font-size:12px;fill:#607086;font-weight:800;text-transform:uppercase}",
        ".node-title{font-size:14px;fill:#101820;font-weight:800}",
        ".node-subtitle{font-size:12px;fill:#607086}",
        ".metric-label{font-size:12px;fill:#607086;font-weight:700}",
        ".metric-value{font-size:18px;fill:#101820;font-weight:900}",
        ".edge{stroke:#8fa0b4;stroke-width:2;fill:none;opacity:.64}",
        ".edge-warn{stroke:#d8841f;opacity:.9}",
        ".status-ok{fill:#11a36a}.status-warn{fill:#d8841f}.status-off{fill:#7a8694}",
        "</style>",
        '<rect x="20" y="18" width="1240" height="74" rx="8" fill="#ffffff" stroke="#d8e0ea"/>',
        f'<text x="42" y="50" class="title">OSINT workflow board</text>',
        f'<text x="42" y="74" class="subtitle">Query: {text(report.query, 118)}</text>',
        pill(42, 116, "Indicators", len(report.indicators), "#2f80ed"),
        pill(274, 116, "Findings", len(report.findings), "#11a36a"),
        pill(506, 116, "Warnings", sum(1 for f in report.findings if f.level in {"warning", "error", "high"}), "#d8841f"),
        pill(738, 116, "Tools enabled", len(enabled_tools), "#7c5cc4"),
        pill(970, 116, "Tools installed", len(available_tools), "#0f9f8f"),
        '<rect class="lane" x="26" y="206" width="316" height="164" rx="8"/>',
        '<rect class="lane" x="366" y="206" width="332" height="{0}" rx="8"/>'.format(max(250, height - 250)),
        '<rect class="lane" x="732" y="206" width="512" height="{0}" rx="8"/>'.format(max(250, height - 250)),
        '<text x="42" y="230" class="lane-label">Seed</text>',
        '<text x="390" y="230" class="lane-label">Normalized indicators</text>',
        '<text x="756" y="230" class="lane-label">Sources, APIs and GitHub utilities</text>',
    ]

    parts.append(node(query_x, query_y, "Query", report.query, "#101820"))

    indicator_by_kind: Dict[str, Tuple[int, int]] = {}
    for indicator, y in zip(indicators, indicator_ys):
        color = KIND_COLORS.get(indicator.kind, "#7a8694")
        label = KIND_LABELS.get(indicator.kind, indicator.kind)
        indicator_by_kind.setdefault(indicator.kind, (indicator_x, y))
        parts.append(node(indicator_x, y, label, indicator.normalized, color, not indicator.valid))
        parts.append(
            f'<path class="edge" d="M{query_x + box_w},{query_y + box_h // 2} C350,{query_y + box_h // 2} 344,{y + box_h // 2} {indicator_x},{y + box_h // 2}"/>'
        )

    for source, y in zip(sources, source_ys):
        target_kind = _source_target_kind(source)
        color = KIND_COLORS.get(target_kind or "unknown", "#64748b")
        warn = source in warning_sources
        subtitle = f"{source_counts[source]} findings"
        parts.append(node(source_x, y, source, subtitle, color, warn))

        target_pos = indicator_by_kind.get(target_kind or "")
        if target_pos:
            x1 = target_pos[0] + box_w
            y1 = target_pos[1] + box_h // 2
        else:
            x1 = query_x + box_w
            y1 = query_y + box_h // 2
        edge_class = "edge edge-warn" if warn else "edge"
        parts.append(
            f'<path class="{edge_class}" d="M{x1},{y1} C690,{y1} 704,{y + box_h // 2} {source_x},{y + box_h // 2}"/>'
        )

    if configured_tools:
        status_y = height - 58
        runner_enabled = bool(inventory.get("ENABLE_TOOL_RUNNERS")) if isinstance(inventory, dict) else False
        status_color = "#11a36a" if runner_enabled else "#7a8694"
        missing_enabled = [
            key for key, item in configured_tools.items() if isinstance(item, dict) and item.get("enabled") and not item.get("available")
        ]
        status_text = f"ready {len(set(enabled_tools) & set(available_tools))} / missing {len(missing_enabled)} / installed {len(available_tools)}"
        parts.append(node(42, status_y, "GitHub runner status", status_text, status_color, bool(missing_enabled)))

    parts.append("</svg>")
    return "\n".join(parts)


def _bar_chart(items: Counter[str], labels: Dict[str, str] | None = None) -> str:
    if not items:
        return "<p class=\"muted\">Нет данных.</p>"
    maximum = max(items.values()) or 1
    rows = []
    for key, count in items.most_common():
        label = labels.get(key, key) if labels else key
        width = max(6, round((count / maximum) * 100))
        rows.append(
            "<div class=\"bar-row\">"
            f"<span>{html.escape(label)}</span>"
            f"<div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:{width}%\"></div></div>"
            f"<strong>{count}</strong>"
            "</div>"
        )
    return "".join(rows)


def _link_chips(links: Dict[str, str]) -> str:
    chips = []
    for label, url in links.items():
        chips.append(f'<a class="chip" href="{html.escape(url)}" target="_blank" rel="noreferrer">{html.escape(label)}</a>')
    return "".join(chips)


def _telegram_panel(report: AnalysisReport) -> str:
    tg_indicators = [item for item in report.indicators if item.kind in {"telegram", "username"}]
    tg_findings = [item for item in report.findings if item.source.startswith("telegram")]
    if not tg_indicators and not tg_findings:
        return ""

    indicator_cards = []
    for indicator in tg_indicators:
        links = indicator.metadata.get("manual_profile_links") if isinstance(indicator.metadata, dict) else None
        lines = "".join(f"<li>{html.escape(item)}</li>" for item in _indicator_highlights(indicator) if item)
        indicator_cards.append(
            "<article class=\"card compact\">"
            f"<h3>{html.escape(_indicator_label(indicator))}: <code>{html.escape(indicator.normalized)}</code></h3>"
            f"<ul>{lines}</ul>"
            f"{_link_chips(links) if isinstance(links, dict) else ''}"
            "</article>"
        )

    finding_cards = []
    for finding in tg_findings:
        details = finding.details if isinstance(finding.details, dict) else {}
        links = details.get("links") if isinstance(details.get("links"), dict) else {}
        posts = details.get("posts_sample") if isinstance(details.get("posts_sample"), list) else []
        preview_parts = []
        for key in ("title", "description", "extra", "action", "url", "public_posts_found", "reason", "error"):
            if details.get(key) not in (None, "", [], {}):
                preview_parts.append(f"<dt>{html.escape(key)}</dt><dd>{html.escape(_format_value(details.get(key)))}</dd>")
        post_html = "".join(
            f"<li><strong>{html.escape(_format_value(post.get('post')))}</strong> "
            f"{html.escape(_format_value(post.get('date')))}<br>{html.escape(_format_value(post.get('text_preview')))}</li>"
            for post in posts
        )
        post_block = f"<ul class=\"posts\">{post_html}</ul>" if post_html else ""
        finding_cards.append(
            "<article class=\"card compact\">"
            f"<div class=\"card-top\"><span class=\"source\">{html.escape(finding.source)}</span><span class=\"level level-{html.escape(finding.level)}\">{html.escape(_finding_level(finding))}</span></div>"
            f"<h3>{html.escape(finding.title)}</h3>"
            f"<dl>{''.join(preview_parts)}</dl>"
            f"{_link_chips(links)}"
            f"{post_block}"
            "</article>"
        )

    return (
        "<section>"
        "<div class=\"section-title\"><h2>Telegram-разведка</h2><p>Публичные ссылки, Bot API, t.me web preview и видимые посты каналов.</p></div>"
        f"<div class=\"cards three\">{''.join(indicator_cards + finding_cards)}</div>"
        "</section>"
    )


def _tool_inventory_panel(report: AnalysisReport) -> str:
    inventory = None
    for finding in reversed(report.findings):
        if finding.source in {"tool_orchestrator", "tool_inventory"} and isinstance(finding.details, dict):
            if isinstance(finding.details.get("configured_tools"), dict):
                inventory = finding.details
                break

    if not inventory:
        return ""

    configured_tools = inventory.get("configured_tools")
    if not isinstance(configured_tools, dict):
        return ""

    enabled_count = sum(1 for item in configured_tools.values() if isinstance(item, dict) and item.get("enabled"))
    available_count = sum(1 for item in configured_tools.values() if isinstance(item, dict) and item.get("available"))
    personal_enabled = inventory.get("ENABLE_PERSONAL_OSINT_TOOLS")
    runner_enabled = inventory.get("ENABLE_TOOL_RUNNERS")

    rows = []
    for key, item in sorted(configured_tools.items(), key=lambda pair: (str(pair[1].get("category", "")), pair[0])):
        if not isinstance(item, dict):
            continue
        enabled = bool(item.get("enabled"))
        available = bool(item.get("available"))
        status = "ready" if enabled and available else "enabled-missing" if enabled else "installed-off" if available else "off"
        repo = item.get("repository") or ""
        install = item.get("install") or item.get("hint") or ""
        repo_link = (
            f'<a href="{html.escape(_format_value(repo))}" target="_blank" rel="noreferrer">GitHub</a>'
            if repo
            else "-"
        )
        rows.append(
            "<tr>"
            f"<td><strong>{html.escape(str(key))}</strong><small>{html.escape(_format_value(item.get('category')))}</small></td>"
            f"<td><span class=\"tool-status tool-status-{status}\">{html.escape(status)}</span></td>"
            f"<td>{html.escape('on' if enabled else 'off')}</td>"
            f"<td>{html.escape('yes' if available else 'no')}</td>"
            f"<td>{repo_link}</td>"
            f"<td><code>{html.escape(_short_value(install, 160))}</code></td>"
            "</tr>"
        )

    return (
        "<section>"
        "<div class=\"section-title\"><h2>Tool Inventory</h2><p>Local CLI status for GitHub OSINT runners.</p></div>"
        "<div class=\"tool-radar\">"
        f"<div class=\"radar-metric\"><span>Runners</span><strong>{html.escape('on' if runner_enabled else 'off')}</strong></div>"
        f"<div class=\"radar-metric\"><span>Personal tools</span><strong>{html.escape('on' if personal_enabled else 'off')}</strong></div>"
        f"<div class=\"radar-metric\"><span>Enabled</span><strong>{enabled_count}</strong></div>"
        f"<div class=\"radar-metric\"><span>Installed</span><strong>{available_count}</strong></div>"
        "</div>"
        "<table class=\"tool-inventory\"><thead><tr><th>Tool</th><th>Status</th><th>Enabled</th><th>Installed</th><th>Repo</th><th>Install / Hint</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
        "</section>"
    )


def _tool_results_panel(report: AnalysisReport) -> str:
    tool_findings = [
        finding
        for finding in report.findings
        if finding.source.startswith("tool_") or finding.source == "tool_orchestrator"
    ]
    if not tool_findings:
        return ""

    grouped: Dict[str, List[Finding]] = {}
    for finding in tool_findings:
        details = finding.details if isinstance(finding.details, dict) else {}
        category = str(details.get("tool_category") or "orchestrator")
        grouped.setdefault(category, []).append(finding)

    sections = []
    for category, findings in sorted(grouped.items()):
        cards = []
        for finding in findings:
            details = finding.details if isinstance(finding.details, dict) else {}
            tool = details.get("tool") or finding.source.replace("tool_", "")
            target = details.get("target", "")
            ok = details.get("ok")
            configured = details.get("configured")
            stdout = details.get("stdout")
            preview = ""
            if isinstance(stdout, dict):
                if "json" in stdout:
                    preview = json.dumps(stdout.get("json"), ensure_ascii=False, default=str)[:900]
                elif "json_lines" in stdout:
                    preview = json.dumps(stdout.get("json_lines"), ensure_ascii=False, default=str)[:900]
                elif "csv_rows" in stdout:
                    preview = json.dumps(stdout.get("csv_rows"), ensure_ascii=False, default=str)[:900]
                elif "text_file" in stdout:
                    preview = _format_value(stdout.get("text_file"))[:900]
                else:
                    preview = _format_value(stdout.get("raw"))[:900]
            if not preview:
                preview = _finding_preview(finding) or _format_value(details.get("error") or details.get("note") or details)[:900]
            repo = details.get("repository") or ""
            repo_link = (
                f'<a href="{html.escape(_format_value(repo))}" target="_blank" rel="noreferrer">GitHub</a>'
                if repo
                else ""
            )
            cards.append(
                "<article class=\"tool-card\">"
                f"<div class=\"card-top\"><span class=\"source\">{html.escape(_format_value(tool))}</span><span class=\"level level-{html.escape(finding.level)}\">{html.escape(_finding_level(finding))}</span></div>"
                f"<h3>{html.escape(finding.title)}</h3>"
                f"<dl><dt>target</dt><dd>{html.escape(_format_value(target))}</dd><dt>ok</dt><dd>{html.escape(_format_value(ok))}</dd><dt>configured</dt><dd>{html.escape(_format_value(configured))}</dd></dl>"
                f"{repo_link}"
                f"<small>{html.escape(preview)}</small>"
                "</article>"
            )
        label = TOOL_CATEGORY_LABELS.get(category, category.title())
        sections.append(
            "<div class=\"tool-section\">"
            f"<h3>{html.escape(label)}</h3>"
            f"<div class=\"tool-grid\">{''.join(cards)}</div>"
            "</div>"
        )

    return (
        "<section>"
        "<div class=\"section-title\"><h2>External tool runners</h2><p>GitHub OSINT utilities and local CLI output.</p></div>"
        f"{''.join(sections)}"
        "</section>"
    )


def _finding_cards(report: AnalysisReport) -> str:
    cards = []
    for finding in report.findings[-12:]:
        details = finding.details if isinstance(finding.details, dict) else {}
        target = details.get("target", "")
        data = details.get("data")
        if isinstance(data, dict):
            preview = ", ".join(f"{key}: {_format_value(value)}" for key, value in list(data.items())[:4])
        else:
            preview = _finding_preview(finding) or _format_value(data or details.get("error") or details)[:280]
        cards.append(
            "<article class=\"card\">"
            f"<div class=\"card-top\"><span class=\"source\">{html.escape(finding.source)}</span><span class=\"level level-{html.escape(finding.level)}\">{html.escape(_finding_level(finding))}</span></div>"
            f"<h3>{html.escape(finding.title)}</h3>"
            f"<p>{html.escape(_format_value(target))}</p>"
            f"<small>{html.escape(preview)}</small>"
            "</article>"
        )
    return "".join(cards) or "<p class=\"muted\">Находок пока нет.</p>"


def _indicator_rows(report: AnalysisReport) -> str:
    rows = []
    for indicator in report.indicators:
        color = KIND_COLORS.get(indicator.kind, "#7a8694")
        rows.append(
            "<tr>"
            f"<td><span class=\"dot\" style=\"background:{color}\"></span>{html.escape(_indicator_label(indicator))}</td>"
            f"<td><code>{html.escape(indicator.raw)}</code></td>"
            f"<td><code>{html.escape(indicator.normalized)}</code></td>"
            f"<td>{'да' if indicator.valid else 'проверить'}</td>"
            f"<td><details><summary>Показать</summary><pre>{_json_block(indicator.metadata)}</pre></details></td>"
            "</tr>"
        )
    return "".join(rows)


def _finding_rows(report: AnalysisReport) -> str:
    rows = []
    for finding in report.findings:
        rows.append(
            "<tr>"
            f"<td>{html.escape(finding.source)}</td>"
            f"<td>{html.escape(finding.title)}</td>"
            f"<td><span class=\"level level-{html.escape(finding.level)}\">{html.escape(_finding_level(finding))}</span></td>"
            f"<td><details><summary>Детали</summary><pre>{_json_block(finding.details)}</pre></details></td>"
            "</tr>"
        )
    return "".join(rows)


def _coverage_matrix(report: AnalysisReport) -> str:
    indicators = report.indicators[:14]
    sources = sorted({finding.source for finding in report.findings})[:14]
    if not indicators or not sources:
        return "<p class=\"muted\">Матрица появится, когда будут индикаторы и источники.</p>"

    rows = []
    for indicator in indicators:
        cells = []
        for source in sources:
            kind = _source_target_kind(source)
            active = kind == indicator.kind or source == "external_api_config"
            cells.append(f"<td class=\"{'hit' if active else ''}\">{'•' if active else ''}</td>")
        rows.append(
            f"<tr><th>{html.escape(KIND_LABELS.get(indicator.kind, indicator.kind))}<br><small>{html.escape(indicator.normalized[:32])}</small></th>{''.join(cells)}</tr>"
        )

    source_heads = "".join(f"<th>{html.escape(source[:18])}</th>" for source in sources)
    return f"<table class=\"matrix\"><thead><tr><th>Индикатор</th>{source_heads}</tr></thead><tbody>{''.join(rows)}</tbody></table>"


def render_html(report: AnalysisReport, svg: str) -> str:
    type_counts = Counter(indicator.kind for indicator in report.indicators)
    source_counts = Counter(finding.source for finding in report.findings)
    level_counts = Counter(finding.level for finding in report.findings)
    valid_count = sum(1 for indicator in report.indicators if indicator.valid)
    warning_count = sum(1 for finding in report.findings if finding.level in {"warning", "error", "high"})
    report_json = json.dumps(_to_dict(report), ensure_ascii=False, indent=2, default=str)
    script_json = report_json.replace("</", "<\\/")

    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OSINT-отчёт</title>
  <style>
    :root {{
      --ink: #111827;
      --muted: #607086;
      --line: #dbe3ee;
      --paper: #ffffff;
      --bg: #f4f7fb;
      --blue: #2f80ed;
      --teal: #0f9f8f;
      --green: #11a36a;
      --amber: #d8841f;
      --rose: #d6536d;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: Arial, sans-serif; background: var(--bg); color: var(--ink); }}
    main {{ max-width: 1320px; margin: 0 auto; padding: 28px 18px 60px; }}
    header {{ background: #101820; color: #fff; border-radius: 8px; padding: 22px; display: grid; gap: 10px; }}
    h1 {{ margin: 0; font-size: 34px; letter-spacing: 0; }}
    h2 {{ margin: 0; font-size: 22px; letter-spacing: 0; }}
    h3 {{ margin: 8px 0 8px; font-size: 16px; letter-spacing: 0; }}
    p {{ margin: 0; color: var(--muted); line-height: 1.45; }}
    header p {{ color: #cbd5e1; }}
    code, pre {{ font-family: Consolas, "Courier New", monospace; font-size: 13px; }}
    pre {{ white-space: pre-wrap; margin: 12px 0 0; max-height: 440px; overflow: auto; }}
    section {{ margin-top: 24px; }}
    .section-title {{ display: flex; justify-content: space-between; gap: 16px; align-items: end; margin-bottom: 12px; }}
    .summary {{ display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 12px; margin-top: 16px; }}
    .metric {{ background: var(--paper); border: 1px solid var(--line); border-radius: 8px; padding: 14px; }}
    .metric span {{ display: block; color: var(--muted); font-size: 13px; }}
    .metric strong {{ display: block; margin-top: 6px; font-size: 25px; }}
    .grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }}
    .panel, .card {{ background: var(--paper); border: 1px solid var(--line); border-radius: 8px; padding: 16px; overflow: hidden; }}
    .graph {{ overflow-x: auto; background: var(--paper); border: 1px solid var(--line); border-radius: 8px; }}
    .graph svg {{ display: block; min-width: 980px; }}
    .bar-row {{ display: grid; grid-template-columns: 160px minmax(120px, 1fr) 42px; align-items: center; gap: 10px; margin: 10px 0; }}
    .bar-row span {{ color: var(--muted); overflow-wrap: anywhere; }}
    .bar-track {{ height: 12px; background: #edf2f7; border-radius: 999px; overflow: hidden; }}
    .bar-fill {{ height: 100%; background: linear-gradient(90deg, var(--green), var(--blue)); }}
    .cards {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }}
    .cards.three {{ grid-template-columns: repeat(3, minmax(0, 1fr)); }}
    .tool-section {{ margin-top: 12px; }}
    .tool-section h3 {{ color: #263445; margin: 0 0 10px; }}
    .tool-grid {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }}
    .tool-card {{ background: #ffffff; border: 1px solid var(--line); border-left: 4px solid var(--blue); border-radius: 8px; padding: 14px; overflow: hidden; }}
    .tool-card a {{ display: inline-flex; margin-top: 8px; color: var(--blue); font-size: 12px; text-decoration: none; }}
    .tool-card small {{ display: block; color: var(--muted); white-space: pre-wrap; overflow-wrap: anywhere; margin-top: 8px; }}
    .tool-radar {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-bottom: 12px; }}
    .radar-metric {{ background: #ffffff; border: 1px solid var(--line); border-radius: 8px; padding: 14px; }}
    .radar-metric span {{ display: block; color: var(--muted); font-size: 12px; }}
    .radar-metric strong {{ display: block; margin-top: 5px; font-size: 22px; }}
    .tool-inventory small {{ display: block; color: var(--muted); margin-top: 3px; }}
    .tool-status {{ display: inline-flex; align-items: center; border-radius: 999px; padding: 4px 8px; font-size: 12px; color: #fff; background: #7a8694; }}
    .tool-status-ready {{ background: var(--green); }}
    .tool-status-enabled-missing {{ background: var(--amber); }}
    .tool-status-installed-off {{ background: var(--teal); }}
    .tool-status-off {{ background: #7a8694; }}
    .compact {{ padding: 14px; }}
    .card-top {{ display: flex; gap: 8px; align-items: center; justify-content: space-between; }}
    .card small {{ display: block; color: var(--muted); line-height: 1.35; overflow-wrap: anywhere; }}
    .source {{ color: var(--muted); font-size: 12px; }}
    .level {{ display: inline-block; border-radius: 999px; padding: 3px 8px; font-size: 12px; color: #fff; background: var(--blue); }}
    .level-warning {{ background: var(--amber); }}
    .level-error, .level-high {{ background: var(--rose); }}
    .level-info {{ background: var(--teal); }}
    .chip {{ display: inline-flex; margin: 4px 6px 2px 0; padding: 6px 9px; border: 1px solid var(--line); border-radius: 999px; color: var(--blue); text-decoration: none; font-size: 12px; background: #f8fbff; }}
    dl {{ display: grid; grid-template-columns: 96px 1fr; gap: 6px 10px; margin: 0; }}
    dt {{ color: var(--muted); font-size: 12px; }}
    dd {{ margin: 0; overflow-wrap: anywhere; }}
    ul {{ margin: 8px 0 0; padding-left: 18px; }}
    .posts li {{ margin-bottom: 8px; }}
    table {{ width: 100%; border-collapse: collapse; background: var(--paper); border: 1px solid var(--line); }}
    th, td {{ padding: 10px 12px; border-bottom: 1px solid #edf2f7; text-align: left; vertical-align: top; }}
    th {{ background: #eef3f8; color: #263445; }}
    td {{ overflow-wrap: anywhere; }}
    details summary {{ cursor: pointer; color: var(--blue); }}
    .dot {{ display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 8px; vertical-align: middle; }}
    .matrix th, .matrix td {{ text-align: center; font-size: 12px; }}
    .matrix tbody th {{ text-align: left; min-width: 180px; }}
    .matrix small {{ color: var(--muted); font-weight: 400; }}
    .matrix .hit {{ background: #e8f7f2; color: var(--green); font-weight: 900; }}
    .raw-json {{ background: #101820; color: #f7fafc; border-radius: 8px; padding: 16px; overflow: auto; }}
    .muted {{ color: var(--muted); }}
    @media (max-width: 900px) {{
      .summary, .grid, .cards, .cards.three, .tool-grid, .tool-radar {{ grid-template-columns: 1fr; }}
      .section-title {{ display: block; }}
      h1 {{ font-size: 27px; }}
      .bar-row {{ grid-template-columns: 120px minmax(90px, 1fr) 36px; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>OSINT-отчёт</h1>
      <p><strong>Запрос:</strong> <code>{html.escape(report.query)}</code></p>
      <p><strong>Сформирован:</strong> {html.escape(report.generated_at)}</p>
    </header>

    <section class="summary" aria-label="Сводка">
      <div class="metric"><span>Индикаторов</span><strong>{len(report.indicators)}</strong></div>
      <div class="metric"><span>Валидных</span><strong>{valid_count}</strong></div>
      <div class="metric"><span>Источников</span><strong>{len(source_counts)}</strong></div>
      <div class="metric"><span>Находок</span><strong>{len(report.findings)}</strong></div>
      <div class="metric"><span>Проверить</span><strong>{warning_count}</strong></div>
    </section>

    <section class="grid">
      <div class="panel">
        <h2>Типы индикаторов</h2>
        {_bar_chart(type_counts, KIND_LABELS)}
      </div>
      <div class="panel">
        <h2>Источники</h2>
        {_bar_chart(source_counts)}
      </div>
    </section>

    <section>
      <div class="section-title"><h2>Карта связей</h2><p>Слева запрос, в центре нормализованные индикаторы, справа источники и утилиты.</p></div>
      <div class="graph">{svg}</div>
    </section>

    {_telegram_panel(report)}

    {_tool_inventory_panel(report)}

    {_tool_results_panel(report)}

    <section>
      <div class="section-title"><h2>Матрица покрытия</h2><p>Быстрый вид, какие источники относятся к каким индикаторам.</p></div>
      {_coverage_matrix(report)}
    </section>

    <section>
      <div class="section-title"><h2>Последние находки</h2><p>Краткие карточки по свежим результатам.</p></div>
      <div class="cards">{_finding_cards(report)}</div>
    </section>

    <section>
      <div class="section-title"><h2>Индикаторы</h2><p>Нормализация и технические метаданные.</p></div>
      <table>
        <thead><tr><th>Тип</th><th>Оригинал</th><th>Нормализовано</th><th>Валидность</th><th>Метаданные</th></tr></thead>
        <tbody>{_indicator_rows(report)}</tbody>
      </table>
    </section>

    <section>
      <div class="section-title"><h2>Все находки</h2><p>Полные ответы источников и утилит.</p></div>
      <table>
        <thead><tr><th>Источник</th><th>Название</th><th>Уровень</th><th>Детали</th></tr></thead>
        <tbody>{_finding_rows(report)}</tbody>
      </table>
    </section>

    <section>
      <div class="section-title"><h2>JSON-данные отчёта</h2><p>Сырые данные для дальнейшей обработки.</p></div>
      <pre class="raw-json">{html.escape(report_json)}</pre>
      <script type="application/json" id="report-data">{script_json}</script>
    </section>
  </main>
</body>
</html>"""


def build_report_files(report: AnalysisReport, report_dir: Path) -> ReportFiles:
    report_dir.mkdir(parents=True, exist_ok=True)
    name = f"{report.generated_at.replace(':', '').replace('-', '')}_{_slug(report.query)}"
    html_path = report_dir / f"{name}.html"

    svg = render_svg(report)
    html_path.write_text(render_html(report, svg), encoding="utf-8")
    return ReportFiles(html_path=html_path)
