(function () {
  const I18N = window.__I18N__ || {};
  function t(path) {
    return String(path).split(".").reduce((value, key) => (value && value[key] != null ? value[key] : null), I18N) || path;
  }

  const tg = window.Telegram && window.Telegram.WebApp ? window.Telegram.WebApp : null;
  if (tg) {
    tg.ready();
    tg.expand();
  }

  const state = { graph: { nodes: [], edges: [] }, profile: null, network: null, graphController: null };
  const queryInput = document.getElementById("queryInput");
  const entityType = document.getElementById("entityType");

  document.getElementById("searchBtn").addEventListener("click", () => runSearch(false));
  document.getElementById("deepBtn").addEventListener("click", () => runSearch(true));
  document.getElementById("historyBtn").addEventListener("click", loadHistory);
  document.getElementById("adminBtn").addEventListener("click", loadAdmin);
  queryInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") runSearch(false);
  });

  boot();

  async function boot() {
    await loadProfile();
    await loadHistory();
    renderGraph(state.graph);
  }

  async function api(path, options = {}) {
    const headers = {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    };
    if (tg && tg.initData) headers["X-Telegram-Init-Data"] = tg.initData;
    const response = await fetch(path, { ...options, headers });
    if (!response.ok) {
      let detail = response.statusText;
      try {
        detail = (await response.json()).detail || detail;
      } catch (_error) {}
      throw new Error(detail);
    }
    return response.json();
  }

  async function loadProfile() {
    try {
      const profile = await api("/api/profile");
      state.profile = profile;
      document.getElementById("profileLine").textContent =
        `@${profile.username || t("web.user")} | ${t("web.role")}=${profile.role} | ${profile.premium ? t("web.premium_active") : t("web.premium_inactive")}`;
      if (["admin", "owner"].includes(profile.role)) {
        document.getElementById("adminBtn").classList.remove("hidden");
        document.getElementById("adminPanel").classList.remove("hidden");
      }
    } catch (error) {
      document.getElementById("profileLine").textContent = error.message;
    }
  }

  async function runSearch(deep) {
    const query = queryInput.value.trim();
    if (!query) return;
    setSummary({ [t("report.status")]: t("web.running"), [t("web.query")]: query });
    document.getElementById("findings").innerHTML = "";
    try {
      const payload = {
        query,
        entity_type: entityType.value,
        deep,
        force_refresh: false,
      };
      const response = await api("/api/search", { method: "POST", body: JSON.stringify(payload) });
      renderResult(response.result, response.report_url);
      await loadHistory();
    } catch (error) {
      setSummary({ [t("web.error")]: error.message });
    }
  }

  async function loadHistory() {
    try {
      const data = await api("/api/history");
      const holder = document.getElementById("history");
      holder.innerHTML = "";
      data.items.forEach((item) => {
        const button = document.createElement("button");
        button.textContent = `${t(`entities.${item.entity_type}`)} | ${item.query}`;
        button.title = item.created_at;
        button.addEventListener("click", () => loadSearch(item.id));
        holder.appendChild(button);
      });
    } catch (_error) {}
  }

  async function loadSearch(id) {
    try {
      const data = await api(`/api/search/${id}`);
      renderResult(data.result, `/api/reports/search/${id}`);
    } catch (error) {
      setSummary({ [t("web.error")]: error.message });
    }
  }

  async function loadAdmin() {
    try {
      const stats = await api("/api/admin/stats");
      const apiStatus = await api("/api/admin/api-status");
      const holder = document.getElementById("adminStats");
      holder.innerHTML = "";
      Object.entries(stats).forEach(([key, value]) => {
        const div = document.createElement("div");
        div.innerHTML = `<span>${escapeHtml(statLabel(key))}</span><b>${escapeHtml(String(value))}</b>`;
        holder.appendChild(div);
      });
      const providerHolder = document.getElementById("providerHealth");
      providerHolder.innerHTML = "";
      apiStatus.providers.forEach((provider) => {
        const card = document.createElement("article");
        card.className = "finding-card";
        const state = provider.fallback ? "fallback" : provider.enabled ? "enabled" : "missing";
        card.innerHTML = `
          <div class="finding-head">
            <h3>${escapeHtml(provider.name)}</h3>
            <span>${escapeHtml(t(`web.${state}`))}</span>
          </div>
          <p>${escapeHtml(t("web.last"))}=${escapeHtml(provider.last_status)} | ${escapeHtml(t("web.latency"))}=${escapeHtml(String(provider.last_response_ms || "-"))}ms</p>
          <p>${escapeHtml(provider.last_error || "")}</p>
        `;
        providerHolder.appendChild(card);
      });
    } catch (error) {
      setSummary({ [t("web.error")]: error.message });
    }
  }

  function renderResult(result, reportUrl) {
    setSummary({
      [t("web.entity")]: t(`entities.${result.entity.kind}`),
      [t("web.value")]: result.entity.normalized,
      [t("report.mode")]: t(`search.mode_${result.mode}`),
      [t("web.confidence")]: result.confidence,
      [t("web.findings")]: result.findings.length,
      [t("web.search_hits")]: result.search_hits.length,
      [t("web.report")]: reportUrl || t("web.premium"),
    });
    renderFindings(result.findings, reportUrl);
    renderGraph(result.graph);
  }

  function setSummary(data) {
    const holder = document.getElementById("summary");
    holder.innerHTML = "";
    Object.entries(data).forEach(([key, value]) => {
      const div = document.createElement("div");
      div.innerHTML = `<span>${escapeHtml(key)}</span><b>${escapeHtml(String(value))}</b>`;
      holder.appendChild(div);
    });
  }

  function renderFindings(findings, reportUrl) {
    const holder = document.getElementById("findings");
    holder.innerHTML = "";
    if (reportUrl) {
      const link = document.createElement("a");
      link.href = reportUrl;
      link.target = "_blank";
      link.textContent = t("web.open_report");
      holder.appendChild(link);
    }
    findings.slice(0, 20).forEach((finding) => {
      const article = document.createElement("article");
      article.className = "finding-card";
      article.innerHTML = `
        <div class="finding-head">
          <h3>${escapeHtml(finding.title)}</h3>
          <span>${escapeHtml(String(finding.confidence))}</span>
        </div>
        <p>${escapeHtml(finding.category)} | ${escapeHtml(finding.source)}</p>
        ${finding.source_url ? `<a href="${escapeAttr(finding.source_url)}" target="_blank" rel="noreferrer">${escapeHtml(finding.source_url)}</a>` : ""}
        <pre>${escapeHtml(JSON.stringify(finding.data || {}, null, 2))}</pre>
      `;
      holder.appendChild(article);
    });
  }

  function renderGraph(graph) {
    state.graph = graph || { nodes: [], edges: [] };
    const container = document.getElementById("graph");
    if (!container || !window.OsintGraph) return;
    state.graphController = window.OsintGraph.renderGraph(container, state.graph, {
      emptyText: t("web.run_search_graph"),
    });
    state.network = state.graphController ? state.graphController.network : null;
    window.OsintGraph.bindFilters(document.getElementById("groupFilters"), state.graphController);
    window.OsintGraph.bindSearch(document.getElementById("graphSearch"), state.graphController);
  }

  function escapeHtml(value) {
    return value.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[char]));
  }

  function statLabel(key) {
    return {
      users: t("admin.stat_users"),
      searches: t("admin.stat_searches"),
      reports: t("admin.stat_reports"),
      payments: t("admin.stat_payments"),
    }[key] || key;
  }

  function escapeAttr(value) {
    return escapeHtml(value).replace(/`/g, "&#096;");
  }
})();
