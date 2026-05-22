(function () {
  const I18N = window.__I18N__ || {};
  function t(path) {
    return String(path).split(".").reduce((value, key) => (value && value[key] != null ? value[key] : null), I18N) || path;
  }

  const graphData = window.__GRAPH__ || { nodes: [], edges: [] };
  const container = document.getElementById("graph");
  if (!container || !window.OsintGraph) return;

  const controller = window.OsintGraph.renderGraph(container, graphData, {
    emptyText: t("report.graph_empty_report"),
  });

  window.OsintGraph.bindFilters(document.getElementById("groupFilters"), controller);
  window.OsintGraph.bindSearch(document.getElementById("graphSearch"), controller);
})();
