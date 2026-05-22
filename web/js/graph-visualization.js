(function () {
  const I18N = window.__I18N__ || {};
  function t(path) {
    return String(path).split(".").reduce((value, key) => (value && value[key] != null ? value[key] : null), I18N) || path;
  }

  const COLORS = {
    root: "#48f0ff",
    telegram: "#229ed9",
    username: "#ff4fd8",
    email: "#8cff66",
    phone: "#ffd166",
    domain: "#7aa2ff",
    ip: "#ff7a7a",
    url: "#9dffef",
    social: "#f6c1ff",
    metadata: "#d4d4d8",
    search: "#a7f3d0",
    image_url: "#fbbf24",
    pdf_url: "#f472b6",
    organization: "#c4b5fd",
    website: "#9dffef",
  };

  function renderGraph(container, graph, config = {}) {
    if (!container) return null;

    if (container.__osintGraphController) {
      container.__osintGraphController.destroy();
    }

    const rawGraph = normalizeGraph(graph);
    container.setAttribute("data-empty", config.emptyText || t("web.graph_no_data"));
    container.setAttribute("data-state", rawGraph.nodes.length ? "ready" : "empty");

    if (!window.vis || !window.vis.Network) {
      container.setAttribute("data-state", "empty");
      container.setAttribute("data-empty", t("web.graph_renderer_unavailable"));
      return null;
    }

    const isCompact = window.matchMedia("(max-width: 700px)").matches;
    const animate = config.animate !== false && !prefersReducedMotion();
    const preparedNodes = rawGraph.nodes.map((node, index) => prepareNode(node, index, isCompact));
    const preparedEdges = rawGraph.edges.map((edge, index) => prepareEdge(edge, index, isCompact));
    const nodeData = animate ? preparedNodes.map((node) => fadedNode(node, 0.08, true, isCompact)) : preparedNodes;
    const edgeData = animate ? preparedEdges.map((edge) => fadedEdge(edge, 0.08, true, isCompact)) : preparedEdges;
    const nodes = new vis.DataSet(nodeData);
    const edges = new vis.DataSet(edgeData);
    const network = new vis.Network(container, { nodes, edges }, networkOptions(isCompact));
    const controller = {
      network,
      nodes,
      edges,
      preparedNodes,
      preparedEdges,
      nodeById: new Map(preparedNodes.map((node) => [node.id, node])),
      activeGroup: "all",
      searchTerm: "",
      revealedNodes: animate ? new Set() : new Set(preparedNodes.map((node) => node.id)),
      revealedEdges: animate ? new Set() : new Set(preparedEdges.map((edge) => edge.id)),
      resizeObserver: null,
      setGroup(group) {
        this.activeGroup = group || "all";
        applyVisibility(this, true);
      },
      setSearch(term) {
        this.searchTerm = String(term || "").trim().toLowerCase();
        applyVisibility(this, true);
      },
      fit(delay = 0) {
        window.setTimeout(() => fitNetwork(this.network), delay);
      },
      destroy() {
        if (this.resizeObserver) this.resizeObserver.disconnect();
        this.network.destroy();
      },
    };

    container.__osintGraphController = controller;

    if (window.ResizeObserver) {
      controller.resizeObserver = new ResizeObserver(() => {
        window.requestAnimationFrame(() => controller.network.redraw());
      });
      controller.resizeObserver.observe(container);
    }

    if (!preparedNodes.length) {
      controller.fit(0);
      return controller;
    }

    if (animate) {
      revealGraph(controller, isCompact);
    } else {
      applyVisibility(controller, false);
      controller.fit(140);
    }

    return controller;
  }

  function bindFilters(holder, controller) {
    if (!holder || !controller) return;
    holder.innerHTML = "";

    const groups = Array.from(new Set(controller.preparedNodes.map((node) => node.group)))
      .filter(Boolean)
      .sort();
    const buttons = [];

    ["all", ...groups].forEach((group) => {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = group === "all" ? t("web.all") : t(`web.group.${group}`).replace(/_/g, " ");
      button.setAttribute("aria-pressed", group === "all" ? "true" : "false");
      if (group === "all") button.classList.add("is-active");
      button.addEventListener("click", () => {
        buttons.forEach((item) => {
          const active = item === button;
          item.classList.toggle("is-active", active);
          item.setAttribute("aria-pressed", active ? "true" : "false");
        });
        controller.setGroup(group);
      });
      buttons.push(button);
      holder.appendChild(button);
    });
  }

  function bindSearch(input, controller) {
    if (!input || !controller) return;
    input.value = "";
    input.oninput = () => controller.setSearch(input.value);
  }

  function revealGraph(controller, isCompact) {
    const order = [...controller.preparedNodes].sort((a, b) => {
      if (a.group === "root") return -1;
      if (b.group === "root") return 1;
      return (b.value || 0) - (a.value || 0) || a.label.localeCompare(b.label);
    });
    const chunkSize = order.length > 220 ? 6 : order.length > 140 ? 4 : order.length > 80 ? 2 : 1;
    const stagger = Math.max(12, Math.min(42, 1900 / Math.max(order.length, 1)));
    let index = 0;

    function step() {
      order.slice(index, index + chunkSize).forEach((node) => revealNode(controller, node, isCompact));
      index += chunkSize;
      revealReadyEdges(controller, false, isCompact);

      if (index < order.length) {
        window.setTimeout(step, stagger);
        return;
      }

      revealReadyEdges(controller, true, isCompact);
      controller.fit(260);
    }

    step();
  }

  function revealNode(controller, node, isCompact) {
    controller.revealedNodes.add(node.id);
    const hidden = !matchesNode(controller, node);
    controller.nodes.update(fadedNode(node, 0.12, hidden, isCompact));
    fadeNode(controller, node, isCompact);
  }

  function revealReadyEdges(controller, flush, isCompact) {
    controller.preparedEdges.forEach((edge) => {
      if (controller.revealedEdges.has(edge.id)) return;
      const endpointsReady = controller.revealedNodes.has(edge.from) && controller.revealedNodes.has(edge.to);
      if (!endpointsReady && !flush) return;
      controller.revealedEdges.add(edge.id);
      const hidden = !edgeVisible(controller, edge);
      controller.edges.update(fadedEdge(edge, 0.12, hidden, isCompact));
      fadeEdge(controller, edge, isCompact);
    });
  }

  function fadeNode(controller, node, isCompact) {
    const start = performance.now();
    const duration = 360 + Math.min(260, (node.value || 1) * 24);

    function frame(now) {
      const progress = Math.min(1, (now - start) / duration);
      const alpha = 0.12 + easeOut(progress) * 0.88;
      const hidden = !matchesNode(controller, node);
      controller.nodes.update(fadedNode(node, alpha, hidden, isCompact));
      if (progress < 1) window.requestAnimationFrame(frame);
    }

    window.requestAnimationFrame(frame);
  }

  function fadeEdge(controller, edge, isCompact) {
    const start = performance.now();
    const duration = 420;

    function frame(now) {
      const progress = Math.min(1, (now - start) / duration);
      const alpha = 0.12 + easeOut(progress) * 0.88;
      const hidden = !edgeVisible(controller, edge);
      controller.edges.update(fadedEdge(edge, alpha, hidden, isCompact));
      if (progress < 1) window.requestAnimationFrame(frame);
    }

    window.requestAnimationFrame(frame);
  }

  function applyVisibility(controller, refit) {
    const visibleNodes = new Set();
    controller.nodes.update(controller.preparedNodes.map((node) => {
      const hidden = !controller.revealedNodes.has(node.id) || !matchesNode(controller, node);
      if (!hidden) visibleNodes.add(node.id);
      return { id: node.id, hidden };
    }));
    controller.edges.update(controller.preparedEdges.map((edge) => ({
      id: edge.id,
      hidden: !controller.revealedEdges.has(edge.id) || !visibleNodes.has(edge.from) || !visibleNodes.has(edge.to),
    })));
    if (refit) controller.fit(80);
  }

  function matchesNode(controller, node) {
    const groupMatch = controller.activeGroup === "all" || node.group === controller.activeGroup || node.group === "root";
    const searchText = `${node.label} ${node.title} ${node.group}`.toLowerCase();
    const searchMatch = !controller.searchTerm || searchText.includes(controller.searchTerm);
    return groupMatch && searchMatch;
  }

  function edgeVisible(controller, edge) {
    const from = controller.nodeById.get(edge.from);
    const to = controller.nodeById.get(edge.to);
    return Boolean(
      from &&
      to &&
      controller.revealedEdges.has(edge.id) &&
      controller.revealedNodes.has(edge.from) &&
      controller.revealedNodes.has(edge.to) &&
      matchesNode(controller, from) &&
      matchesNode(controller, to)
    );
  }

  function normalizeGraph(graph) {
    const source = graph || {};
    const nodes = Array.isArray(source.nodes) ? source.nodes.filter((node) => node && node.id != null) : [];
    const edges = Array.isArray(source.edges)
      ? source.edges.filter((edge) => edge && (edge.source != null || edge.from != null) && (edge.target != null || edge.to != null))
      : [];
    return { nodes, edges };
  }

  function prepareNode(node, index, isCompact) {
    const group = String(node.group || "metadata");
    const id = String(node.id || `node-${index}`);
    const value = clamp(Number(node.value) || 1, 1, 12);
    return {
      id,
      label: trimLabel(String(node.label || id), isCompact ? 28 : 48),
      title: String(node.title || node.label || id),
      group,
      value,
      shape: "dot",
      size: group === "root" ? (isCompact ? 20 : 24) : undefined,
      borderWidth: group === "root" ? 2 : 1,
      color: nodeColor(group, 1),
      font: nodeFont(isCompact, 1),
      shadow: {
        enabled: true,
        color: withAlpha(COLORS[group] || "#d4d4d8", group === "root" ? 0.24 : 0.16),
        size: group === "root" ? 16 : 9,
        x: 0,
        y: 2,
      },
    };
  }

  function prepareEdge(edge, index, isCompact) {
    const confidence = clamp(Number(edge.confidence) || 0.5, 0.15, 1);
    const label = String(edge.label || "");
    return {
      id: String(edge.id || `${edge.source || edge.from}->${edge.target || edge.to}:${index}`),
      from: String(edge.source || edge.from),
      to: String(edge.target || edge.to),
      label: isCompact ? "" : trimLabel(label, 22),
      title: label ? `${label} | ${t("report.confidence")}: ${confidence.toFixed(2)}` : `${t("report.confidence")}: ${confidence.toFixed(2)}`,
      confidence,
      arrows: { to: { enabled: true, scaleFactor: isCompact ? 0.42 : 0.55 } },
      width: 0.8 + confidence * 1.6,
      color: edgeColor(confidence, 1),
      font: edgeFont(isCompact, 1),
      selectionWidth: 1.2,
      smooth: { type: "continuous", roundness: 0.28 },
    };
  }

  function fadedNode(node, alpha, hidden, isCompact) {
    return {
      ...node,
      hidden,
      color: nodeColor(node.group, alpha),
      font: nodeFont(isCompact, alpha),
    };
  }

  function fadedEdge(edge, alpha, hidden, isCompact) {
    return {
      ...edge,
      hidden,
      color: edgeColor(edge.confidence, alpha),
      font: edgeFont(isCompact, alpha),
    };
  }

  function nodeColor(group, alpha) {
    const base = COLORS[group] || "#d4d4d8";
    return {
      background: withAlpha(base, Math.max(0.08, alpha)),
      border: withAlpha("#f8fafc", 0.18 + alpha * 0.42),
      highlight: {
        background: withAlpha(base, 1),
        border: withAlpha("#ffffff", 0.86),
      },
      hover: {
        background: withAlpha(base, 1),
        border: withAlpha("#ffffff", 0.78),
      },
    };
  }

  function edgeColor(confidence, alpha) {
    const tint = confidence >= 0.75 ? "#8cff66" : confidence >= 0.45 ? "#48f0ff" : "#ffd166";
    return {
      color: withAlpha(tint, 0.16 + alpha * 0.58),
      highlight: withAlpha("#ffffff", 0.76),
      hover: withAlpha(tint, 0.86),
    };
  }

  function nodeFont(isCompact, alpha) {
    return {
      color: withAlpha("#eef5ff", 0.2 + alpha * 0.8),
      size: isCompact ? 11 : 13,
      face: "Inter, Segoe UI, sans-serif",
      strokeWidth: isCompact ? 3 : 4,
      strokeColor: withAlpha("#080807", 0.38 + alpha * 0.48),
    };
  }

  function edgeFont(isCompact, alpha) {
    return {
      color: withAlpha("#aeb8c9", alpha * 0.82),
      size: isCompact ? 9 : 10,
      face: "Inter, Segoe UI, sans-serif",
      strokeWidth: 0,
      align: "top",
    };
  }

  function networkOptions(isCompact) {
    return {
      autoResize: true,
      layout: {
        improvedLayout: true,
      },
      physics: {
        enabled: true,
        solver: "forceAtlas2Based",
        forceAtlas2Based: {
          gravitationalConstant: isCompact ? -36 : -54,
          centralGravity: 0.018,
          springLength: isCompact ? 118 : 158,
          springConstant: 0.075,
          avoidOverlap: 0.45,
        },
        stabilization: {
          enabled: true,
          iterations: isCompact ? 85 : 135,
          fit: false,
        },
        adaptiveTimestep: true,
      },
      interaction: {
        hover: true,
        tooltipDelay: 120,
        navigationButtons: false,
        zoomView: true,
        dragView: true,
        keyboard: false,
      },
      nodes: {
        shape: "dot",
        borderWidth: 1,
        labelHighlightBold: false,
        scaling: {
          min: isCompact ? 9 : 11,
          max: isCompact ? 24 : 32,
        },
      },
      edges: {
        smooth: {
          enabled: true,
          type: "continuous",
          roundness: 0.28,
        },
      },
    };
  }

  function fitNetwork(network) {
    if (!network) return;
    network.fit({
      animation: {
        duration: prefersReducedMotion() ? 0 : 520,
        easingFunction: "easeInOutQuad",
      },
    });
  }

  function trimLabel(value, limit) {
    if (!value || value.length <= limit) return value || "";
    return `${value.slice(0, Math.max(0, limit - 1))}...`;
  }

  function withAlpha(hex, alpha) {
    const rgb = hexToRgb(hex);
    return `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, ${clamp(alpha, 0, 1).toFixed(3)})`;
  }

  function hexToRgb(hex) {
    const clean = String(hex || "#d4d4d8").replace("#", "");
    const full = clean.length === 3 ? clean.split("").map((char) => char + char).join("") : clean;
    const value = Number.parseInt(full, 16);
    if (Number.isNaN(value)) return { r: 212, g: 212, b: 216 };
    return {
      r: (value >> 16) & 255,
      g: (value >> 8) & 255,
      b: value & 255,
    };
  }

  function clamp(value, min, max) {
    return Math.min(max, Math.max(min, value));
  }

  function easeOut(value) {
    return 1 - Math.pow(1 - value, 3);
  }

  function prefersReducedMotion() {
    return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }

  window.OsintGraph = {
    colors: COLORS,
    renderGraph,
    bindFilters,
    bindSearch,
  };
})();
