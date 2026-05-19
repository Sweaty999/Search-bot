from __future__ import annotations

import dataclasses
import html
import json
import math
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from tools.analyzer import AnalysisReport


@dataclasses.dataclass
class ReportFiles:
    json_path: Path
    svg_path: Path
    html_path: Path


def _slug(value: str, limit: int = 42) -> str:
    value = re.sub(r"[^A-Za-z0-9_.@+-]+", "_", value).strip("_")
    return (value[:limit] or "report").strip("._")


def _to_dict(report: AnalysisReport) -> Dict[str, Any]:
    return dataclasses.asdict(report)


def _format_value(value: Any) -> str:
    if value is None or value == "":
        return "-"
    if isinstance(value, (list, tuple)):
        return ", ".join(_format_value(item) for item in value) or "-"
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, indent=2)
    return str(value)


def format_report_text(report: AnalysisReport) -> str:
    lines = ["<b>OSINT-звіт</b>", f"<b>Запит:</b> <code>{html.escape(report.query)}</code>", ""]
    if not report.indicators:
        return "\n".join(lines + ["Індикаторів не знайдено."])

    lines.append("<b>Індикатори:</b>")
    for indicator in report.indicators:
        status = "valid" if indicator.valid else "check"
        lines.append(
            f"- <b>{html.escape(indicator.kind)}</b>: <code>{html.escape(indicator.normalized)}</code> ({status})"
        )

    highlights: List[str] = []
    for indicator in report.indicators:
        if indicator.kind == "phone":
            meta = indicator.metadata
            highlights.append(
                "phone: "
                + ", ".join(
                    part
                    for part in [
                        meta.get("region_code"),
                        meta.get("type"),
                        meta.get("carrier"),
                        meta.get("location"),
                    ]
                    if part
                )
            )
        elif indicator.kind == "email":
            meta = indicator.metadata
            highlights.append(
                f"email domain: {meta.get('domain')} | MX={bool(meta.get('has_mx'))} | SPF={bool(meta.get('has_spf'))} | DMARC={bool(meta.get('has_dmarc'))}"
            )
        elif indicator.kind == "telegram":
            meta = indicator.metadata
            highlights.append(f"telegram: {meta.get('public_url')}")

    if highlights:
        lines.extend(["", "<b>Коротко:</b>"])
        for item in highlights[:8]:
            lines.append(f"- {html.escape(item)}")

    lines.append("")
    lines.append("Повний JSON, SVG-граф і HTML-звіт прикріплені файлами.")
    return "\n".join(lines)


def _node_positions(count: int, center: Tuple[int, int], radius: int) -> List[Tuple[float, float]]:
    if count <= 0:
        return []
    positions = []
    for index in range(count):
        angle = (2 * math.pi * index / count) - math.pi / 2
        positions.append((center[0] + radius * math.cos(angle), center[1] + radius * math.sin(angle)))
    return positions


def _node_svg(x: float, y: float, label: str, color: str, node_id: str) -> str:
    safe_label = html.escape(label)
    safe_id = html.escape(node_id)
    return (
        f'<g class="node" id="{safe_id}">'
        f'<circle cx="{x:.1f}" cy="{y:.1f}" r="46" fill="{color}" stroke="#17202a" stroke-width="2"/>'
        f'<text x="{x:.1f}" y="{y - 5:.1f}" text-anchor="middle">{safe_label[:18]}</text>'
        f'<text x="{x:.1f}" y="{y + 13:.1f}" text-anchor="middle" class="small">{safe_label[18:36]}</text>'
        "</g>"
    )


def render_svg(report: AnalysisReport) -> str:
    width, height = 1000, 720
    center = (width // 2, height // 2)
    indicator_positions = _node_positions(len(report.indicators), center, 230)
    source_names = sorted({finding.source for finding in report.findings})
    source_positions = _node_positions(len(source_names), center, 330)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        "<style>",
        "svg{font-family:Arial,sans-serif;background:#f7f8fa;color:#17202a}",
        "text{font-size:15px;fill:#17202a;font-weight:700}",
        ".small{font-size:11px;font-weight:500}",
        ".edge{stroke:#7d8793;stroke-width:2;opacity:.75}",
        ".title{font-size:24px;font-weight:800}",
        "</style>",
        f'<text x="40" y="48" class="title">OSINT graph: {html.escape(report.query)[:80]}</text>',
    ]

    for x, y in indicator_positions:
        parts.append(f'<line class="edge" x1="{center[0]}" y1="{center[1]}" x2="{x:.1f}" y2="{y:.1f}"/>')

    source_lookup = {name: source_positions[index] for index, name in enumerate(source_names)}
    indicator_lookup = {indicator.kind: indicator_positions[index] for index, indicator in enumerate(report.indicators)}
    for finding in report.findings:
        source_position = source_lookup.get(finding.source)
        target_position = indicator_lookup.get(finding.source.split("_")[0])
        if not source_position or not target_position:
            continue
        parts.append(
            f'<line class="edge" x1="{source_position[0]:.1f}" y1="{source_position[1]:.1f}" '
            f'x2="{target_position[0]:.1f}" y2="{target_position[1]:.1f}"/>'
        )

    parts.append(_node_svg(center[0], center[1], "query", "#f3d166", "query"))

    colors = {"phone": "#7bc6a4", "email": "#83b8f4", "telegram": "#9fd0ff", "unknown": "#d4d8dd"}
    for index, indicator in enumerate(report.indicators):
        x, y = indicator_positions[index]
        label = f"{indicator.kind}:{indicator.normalized}"
        parts.append(_node_svg(x, y, label, colors.get(indicator.kind, "#d4d8dd"), f"indicator-{index}"))

    for index, source_name in enumerate(source_names):
        x, y = source_positions[index]
        parts.append(_node_svg(x, y, source_name, "#f0a6a6", f"source-{index}"))

    parts.append("</svg>")
    return "\n".join(parts)


def render_html(report: AnalysisReport, svg: str) -> str:
    rows = []
    for indicator in report.indicators:
        rows.append(
            "<tr>"
            f"<td>{html.escape(indicator.kind)}</td>"
            f"<td><code>{html.escape(indicator.raw)}</code></td>"
            f"<td><code>{html.escape(indicator.normalized)}</code></td>"
            f"<td>{indicator.valid}</td>"
            f"<td><pre>{html.escape(json.dumps(indicator.metadata, ensure_ascii=False, indent=2))}</pre></td>"
            "</tr>"
        )

    finding_rows = []
    for finding in report.findings:
        finding_rows.append(
            "<tr>"
            f"<td>{html.escape(finding.source)}</td>"
            f"<td>{html.escape(finding.title)}</td>"
            f"<td>{html.escape(finding.level)}</td>"
            f"<td><pre>{html.escape(json.dumps(finding.details, ensure_ascii=False, indent=2))}</pre></td>"
            "</tr>"
        )

    return f"""<!doctype html>
<html lang="uk">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OSINT report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 0; background: #f7f8fa; color: #17202a; }}
    main {{ max-width: 1160px; margin: 0 auto; padding: 32px 20px 56px; }}
    h1, h2 {{ margin: 0 0 16px; }}
    section {{ margin-top: 28px; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #d8dee6; }}
    th, td {{ padding: 10px 12px; border-bottom: 1px solid #e8ecf1; text-align: left; vertical-align: top; }}
    th {{ background: #edf1f5; }}
    code, pre {{ font-family: Consolas, monospace; font-size: 13px; }}
    pre {{ white-space: pre-wrap; margin: 0; }}
    .graph {{ overflow-x: auto; background: #fff; border: 1px solid #d8dee6; }}
  </style>
</head>
<body>
  <main>
    <h1>OSINT report</h1>
    <p><strong>Query:</strong> <code>{html.escape(report.query)}</code></p>
    <p><strong>Generated:</strong> {html.escape(report.generated_at)}</p>
    <section>
      <h2>Graph</h2>
      <div class="graph">{svg}</div>
    </section>
    <section>
      <h2>Indicators</h2>
      <table>
        <thead><tr><th>Type</th><th>Raw</th><th>Normalized</th><th>Valid</th><th>Metadata</th></tr></thead>
        <tbody>{''.join(rows)}</tbody>
      </table>
    </section>
    <section>
      <h2>Findings</h2>
      <table>
        <thead><tr><th>Source</th><th>Title</th><th>Level</th><th>Details</th></tr></thead>
        <tbody>{''.join(finding_rows)}</tbody>
      </table>
    </section>
  </main>
</body>
</html>"""


def build_report_files(report: AnalysisReport, report_dir: Path) -> ReportFiles:
    report_dir.mkdir(parents=True, exist_ok=True)
    name = f"{report.generated_at.replace(':', '').replace('-', '')}_{_slug(report.query)}"
    json_path = report_dir / f"{name}.json"
    svg_path = report_dir / f"{name}.svg"
    html_path = report_dir / f"{name}.html"

    svg = render_svg(report)
    json_path.write_text(json.dumps(_to_dict(report), ensure_ascii=False, indent=2), encoding="utf-8")
    svg_path.write_text(svg, encoding="utf-8")
    html_path.write_text(render_html(report, svg), encoding="utf-8")
    return ReportFiles(json_path=json_path, svg_path=svg_path, html_path=html_path)
