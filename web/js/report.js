(function () {
  const graphData = window.__GRAPH__ || { nodes: [], edges: [] };
  const container = document.getElementById("graph");
  if (!container || !window.OsintGraph) return;

  const controller = window.OsintGraph.renderGraph(container, graphData, {
    emptyText: "No graph data in this report",
  });

  window.OsintGraph.bindFilters(document.getElementById("groupFilters"), controller);
  window.OsintGraph.bindSearch(document.getElementById("graphSearch"), controller);
})();
