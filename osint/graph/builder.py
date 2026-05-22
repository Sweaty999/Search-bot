from __future__ import annotations

import html
import json
from pathlib import Path

import networkx as nx
import pyvis

from core.localization import locale_json, t
from osint.models import Entity, GraphData, GraphEdge, GraphNode, ScanResult, SearchHit


GROUP_COLORS = {
    "root": "#48f0ff",
    "telegram": "#229ed9",
    "username": "#ff4fd8",
    "email": "#8cff66",
    "phone": "#ffd166",
    "domain": "#7aa2ff",
    "ip": "#ff7a7a",
    "url": "#9dffef",
    "social": "#f6c1ff",
    "metadata": "#d4d4d8",
    "search": "#a7f3d0",
    "image_url": "#fbbf24",
    "pdf_url": "#f472b6",
    "organization": "#c4b5fd",
    "website": "#9dffef",
}

GROUP_ICONS = {
    "root": "◎",
    "telegram": "TG",
    "username": "@",
    "email": "✉",
    "phone": "☎",
    "domain": "🌐",
    "ip": "▣",
    "url": "↗",
    "social": "★",
    "metadata": "i",
    "search": "⌕",
    "image_url": "▧",
    "pdf_url": "PDF",
}

REPO_ROOT = Path(__file__).resolve().parents[2]


def build_graph(result: ScanResult) -> GraphData:
    graph = nx.MultiDiGraph()
    root_id = _entity_id(result.entity)
    graph.add_node(root_id, label=_label("root", result.entity.normalized), group="root", title=result.entity.kind.value, value=6)

    for finding in result.findings:
        finding_id = f"finding:{finding.id}"
        graph.add_node(
            finding_id,
            label=_label("metadata", finding.title[:42]),
            group="metadata",
            title=_tooltip(finding.title, finding.source, finding.confidence),
            value=max(1, int(finding.confidence * 5)),
        )
        graph.add_edge(root_id, finding_id, label=finding.category, confidence=finding.confidence)
        for entity in finding.entities:
            entity_id = _entity_id(entity)
            group = _group_for_entity(entity)
            graph.add_node(
                entity_id,
                label=_label(group, entity.normalized[:48]),
                group=group,
                title=entity.kind.value,
                value=max(1, int(entity.confidence * 5)),
            )
            graph.add_edge(finding_id, entity_id, label=t("graph.contains"), confidence=entity.confidence)

        for hit in _finding_hits(finding):
            _add_hit(graph, finding_id, hit)

        for row in _finding_source_rows(finding):
            _add_source_row(graph, finding_id, row)

    for hit in result.search_hits:
        _add_hit(graph, root_id, hit)

    nodes = [
        GraphNode(
            id=str(node_id),
            label=str(data.get("label", node_id)),
            group=str(data.get("group", "metadata")),
            title=str(data.get("title", "")),
            value=int(data.get("value", 1)),
            icon=str(data.get("icon", "")),
        )
        for node_id, data in graph.nodes(data=True)
    ]
    edges = [
        GraphEdge(
            source=str(source),
            target=str(target),
            label=str(data.get("label", "")),
            confidence=float(data.get("confidence", 0.5)),
        )
        for source, target, data in graph.edges(data=True)
    ]
    return GraphData(nodes=nodes, edges=edges)


def export_pyvis_html(graph_data: GraphData, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_render_graph_export_html(graph_data), encoding="utf-8")
    return path


def graph_visualization_assets() -> dict[str, str]:
    pyvis_root = Path(pyvis.__file__).resolve().parent
    vis_root = pyvis_root / "lib" / "vis-9.1.2"
    return {
        "vis_network_js": _inline_script(_read_text(vis_root / "vis-network.min.js")),
        "vis_network_css": _inline_style(_read_text(vis_root / "vis-network.css")),
        "graph_renderer_js": _inline_script(_read_text(REPO_ROOT / "web" / "js" / "graph-visualization.js")),
    }


def _render_graph_export_html(graph_data: GraphData) -> str:
    assets = graph_visualization_assets()
    graph_json = _safe_json(graph_data.model_dump(mode="json"))
    nodes_count = len(graph_data.nodes)
    edges_count = len(graph_data.edges)
    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{t("report.graph_export")}</title>
  <style>{assets["vis_network_css"]}</style>
  <style>{_inline_style(_GRAPH_EXPORT_CSS)}</style>
</head>
<body>
  <main class="export-shell">
    <header class="export-header">
      <div>
        <p class="eyebrow">{t("report.graph")}</p>
        <h1>{t("report.graph_export")}</h1>
      </div>
      <div class="export-stats">
        <div><span>{t("report.nodes")}</span><b>{nodes_count}</b></div>
        <div><span>{t("report.edges")}</span><b>{edges_count}</b></div>
      </div>
    </header>
    <section class="graph-card">
      <div class="toolbar">
        <input id="graphSearch" class="graph-search" placeholder="{t("report.search_graph")}" autocomplete="off">
        <div id="groupFilters" class="filters"></div>
      </div>
      <div id="graph"></div>
    </section>
  </main>
  <script>{assets["vis_network_js"]}</script>
  <script>{assets["graph_renderer_js"]}</script>
  <script>
    window.__GRAPH__ = {graph_json};
    window.__I18N__ = {locale_json()};
    window.addEventListener("DOMContentLoaded", function () {{
      var controller = window.OsintGraph.renderGraph(document.getElementById("graph"), window.__GRAPH__, {{
        emptyText: window.__I18N__.report.graph_empty_export
      }});
      window.OsintGraph.bindFilters(document.getElementById("groupFilters"), controller);
      window.OsintGraph.bindSearch(document.getElementById("graphSearch"), controller);
    }});
  </script>
</body>
</html>"""


_GRAPH_EXPORT_CSS = """
:root {
  color-scheme: dark;
  --bg: #080807;
  --panel: #111417;
  --panel-2: #181710;
  --line: #303536;
  --text: #f4f7f2;
  --muted: #a9b1b0;
  --cyan: #48f0ff;
  --green: #8cff66;
  --yellow: #ffd166;
}

* { box-sizing: border-box; }

html, body {
  margin: 0;
  min-width: 0;
  height: 100%;
  background: var(--bg);
  color: var(--text);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

body {
  min-height: 100vh;
  overflow: hidden;
}

.export-shell {
  width: min(1480px, 100%);
  height: 100vh;
  margin: 0 auto;
  padding: 18px;
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
  gap: 14px;
}

@supports (height: 100svh) {
  .export-shell {
    height: 100svh;
  }
}

.export-header {
  display: flex;
  align-items: end;
  justify-content: space-between;
  gap: 16px;
}

.eyebrow {
  margin: 0 0 5px;
  color: var(--muted);
  font-size: 12px;
  text-transform: uppercase;
}

h1 {
  margin: 0;
  font-size: 34px;
  line-height: 1.05;
}

.export-stats {
  display: grid;
  grid-template-columns: repeat(2, minmax(92px, 1fr));
  gap: 10px;
}

.export-stats div {
  min-width: 0;
  padding: 10px 12px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--panel);
}

.export-stats span {
  display: block;
  color: var(--muted);
  font-size: 12px;
}

.export-stats b {
  display: block;
  margin-top: 4px;
  font-size: 18px;
}

.graph-card {
  min-width: 0;
  min-height: 0;
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
  overflow: hidden;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--panel);
  box-shadow: 0 18px 48px rgba(0, 0, 0, 0.32);
}

.toolbar {
  min-width: 0;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px;
  border-bottom: 1px solid var(--line);
}

.graph-search {
  width: min(260px, 36vw);
  min-height: 38px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: #0b0d0f;
  color: var(--text);
  padding: 0 12px;
  outline: none;
}

.graph-search:focus {
  border-color: rgba(72, 240, 255, 0.78);
  box-shadow: 0 0 0 3px rgba(72, 240, 255, 0.12);
}

.filters {
  min-width: 0;
  display: flex;
  gap: 6px;
  overflow-x: auto;
  scrollbar-width: thin;
}

.filters button {
  min-height: 32px;
  flex: 0 0 auto;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: #171b1d;
  color: var(--text);
  padding: 0 10px;
  font: inherit;
  font-size: 12px;
  white-space: nowrap;
  cursor: pointer;
}

.filters button:hover,
.filters button.is-active,
.filters button[aria-pressed="true"] {
  border-color: rgba(72, 240, 255, 0.72);
  background: rgba(72, 240, 255, 0.12);
}

#graph {
  position: relative;
  height: 100%;
  min-height: 0;
  background: #080a0b;
  overflow: hidden;
}

#graph[data-state="empty"]::after {
  content: attr(data-empty);
  position: absolute;
  inset: 0;
  z-index: 3;
  display: grid;
  place-items: center;
  padding: 24px;
  color: var(--muted);
  text-align: center;
  pointer-events: none;
}

#graph .vis-network:focus,
#graph canvas:focus {
  outline: none;
}

@media (max-width: 760px) {
  .export-shell {
    padding: 12px;
  }

  .export-header {
    align-items: stretch;
    flex-direction: column;
  }

  h1 {
    font-size: 28px;
  }

  .toolbar {
    align-items: stretch;
    flex-direction: column;
  }

  .graph-search,
  .filters {
    width: 100%;
    max-width: none;
  }

  #graph {
    min-height: 0;
  }
}

@media (max-width: 480px) {
  h1 {
    font-size: 24px;
  }

  .export-stats {
    grid-template-columns: 1fr;
  }
}
"""


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _inline_script(value: str) -> str:
    return value.replace("</script", "<\\/script")


def _inline_style(value: str) -> str:
    return value.replace("</style", "<\\/style")


def _safe_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str).replace("</", "<\\/")


def _entity_id(entity: Entity) -> str:
    return f"{entity.kind.value}:{entity.normalized}"


def _group_for_entity(entity: Entity) -> str:
    if entity.metadata.get("platform"):
        return "social"
    return entity.kind.value


def _tooltip(title: str, source: str, confidence: float) -> str:
    return html.escape(f"{title}\n{t('report.source')}: {source}\n{t('report.confidence')}: {confidence:.2f}")


def _label(group: str, text: str) -> str:
    prefixes = {
        "root": t("web.group.root"),
        "telegram": t("web.group.telegram"),
        "username": "@",
        "email": t("web.group.email"),
        "phone": t("web.group.phone"),
        "domain": t("web.group.domain"),
        "ip": "ip",
        "url": t("web.group.url"),
        "social": t("web.group.social"),
        "metadata": t("web.group.metadata"),
        "search": t("web.group.search"),
        "image_url": t("web.group.image_url"),
        "pdf_url": "pdf",
    }
    prefix = prefixes.get(group, group)
    return f"{prefix} {text}" if prefix else text


def _finding_hits(finding: object) -> list[SearchHit]:
    data = getattr(finding, "data", {}) or {}
    hits = data.get("hits", [])
    output: list[SearchHit] = []
    for hit in hits if isinstance(hits, list) else []:
        if isinstance(hit, SearchHit):
            output.append(hit)
        elif isinstance(hit, dict) and hit.get("url"):
            output.append(SearchHit(**hit))
    return output[:20]


def _finding_source_rows(finding: object) -> list[dict[str, object]]:
    data = getattr(finding, "data", {}) or {}
    rows = data.get("source_table", [])
    return [row for row in rows if isinstance(row, dict) and row.get("url")][:40] if isinstance(rows, list) else []


def _add_hit(graph: nx.MultiDiGraph, source_id: str, hit: SearchHit) -> None:
    hit_id = f"search:{hit.url}"
    graph.add_node(
        hit_id,
        label=_label("search", (hit.title or hit.url)[:48]),
        group="search",
        title=html.escape(f"{hit.url}\n{hit.snippet}"),
        value=max(1, int(hit.confidence * 4)),
    )
    graph.add_edge(source_id, hit_id, label=hit.engine, confidence=hit.confidence)


def _add_source_row(graph: nx.MultiDiGraph, source_id: str, row: dict[str, object]) -> None:
    url = str(row.get("url"))
    title = str(row.get("title") or url)
    node_id = f"source:{url}"
    graph.add_node(
        node_id,
        label=_label("search", title[:48]),
        group="search",
        title=html.escape(f"{url}\n{t('report.confidence')}: {row.get('confidence')}\n{t('report.risk')}: {row.get('risk_score')}"),
        value=max(1, int(float(row.get("confidence") or 0.4) * 5)),
    )
    graph.add_edge(source_id, node_id, label=str(row.get("engine") or "source"), confidence=float(row.get("confidence") or 0.4))
    domain = str(row.get("domain") or "")
    if domain:
        domain_id = f"domain:{domain}"
        graph.add_node(domain_id, label=_label("domain", domain), group="domain", title=domain, value=3)
        graph.add_edge(node_id, domain_id, label=t("graph.hosted_on"), confidence=0.7)
