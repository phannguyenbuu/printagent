async function jget(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
}

function qs(id) { return document.getElementById(id); }
function fmtNumber(v) {
  if (v === null || v === undefined || v === "") return "-";
  const n = Number(v);
  if (!Number.isFinite(n)) return String(v);
  return n.toLocaleString("en-US");
}

async function loadSummary() {
  const data = await jget("/api/dashboard/summary");
  qs("summary-cards").innerHTML = `
    <div class="card"><div>Counter Rows</div><h3>${data.counter_rows}</h3></div>
    <div class="card"><div>Status Rows</div><h3>${data.status_rows}</h3></div>
    <div class="card"><div>Printers / Leads</div><h3>${data.printers} / ${data.leads}</h3></div>
    <div class="card"><div>Latest Counter</div><div>${data.latest_counter_at || "-"}</div></div>
    <div class="card"><div>Latest Status</div><div>${data.latest_status_at || "-"}</div></div>
  `;
}

const state = {
  counter: { page: 1, totalPages: 1 },
  status: { page: 1, totalPages: 1 },
  heatmap: { page: 1, totalPages: 1, mode: "day", hour: 0 },
  autoRefresh: { enabled: true, intervalMs: 10000, timerId: null },
};

function currentPage() {
  return document.body.dataset.page;
}

function refreshCurrentPage() {
  const page = currentPage();
  if (page === "dashboard") return loadSummary();
  if (page === "counter") return loadCounter();
  if (page === "status") return loadStatus();
  if (page === "heatmap") return loadHeatmap();
  return Promise.resolve();
}

function updateAutoRefreshStateText() {
  const el = qs("auto-refresh-state");
  if (!el) return;
  el.textContent = state.autoRefresh.enabled
    ? `Auto refresh: ON (${Math.round(state.autoRefresh.intervalMs / 1000)}s)`
    : "Auto refresh: OFF";
}

function stopAutoRefresh() {
  if (state.autoRefresh.timerId) {
    window.clearInterval(state.autoRefresh.timerId);
    state.autoRefresh.timerId = null;
  }
}

function startAutoRefresh() {
  stopAutoRefresh();
  if (!state.autoRefresh.enabled) {
    updateAutoRefreshStateText();
    return;
  }
  state.autoRefresh.timerId = window.setInterval(() => {
    if (document.hidden) return;
    refreshCurrentPage().catch(() => {});
  }, state.autoRefresh.intervalMs);
  updateAutoRefreshStateText();
}

async function loadCounter() {
  const lead = (qs("counter-lead")?.value || "").trim();
  const ip = (qs("counter-ip")?.value || "").trim();
  const p = state.counter.page;
  const query = new URLSearchParams({ page: String(p), page_size: "120", lead, ip });
  const data = await jget(`/api/counter/timelapse?${query.toString()}`);
  state.counter.totalPages = data.total_pages;
  qs("counter-page").textContent = `${data.page} / ${data.total_pages}`;
  qs("counter-table").querySelector("tbody").innerHTML = data.rows.length
    ? data.rows.map((r) => `<tr>
      <td>${r.timestamp || "-"}</td><td>${r.lead || "-"}</td><td>${r.printer_name || "-"}</td><td>${r.ip || "-"}</td>
      <td>${fmtNumber(r.total)}</td><td>${fmtNumber(r.copier_bw)}</td><td>${fmtNumber(r.printer_bw)}</td><td>${fmtNumber(r.scanner_send_bw)}</td><td>${fmtNumber(r.scanner_send_color)}</td><td>${fmtNumber(r.a3_dlt)}</td><td>${fmtNumber(r.duplex)}</td>
    </tr>`).join("")
    : `<tr><td colspan="11">No data</td></tr>`;
  const meta = qs("counter-meta");
  if (meta) {
    const latest = data.rows.length ? data.rows[0].timestamp : "-";
    const fetchedAt = new Date().toLocaleTimeString();
    meta.textContent = `DB rows: ${fmtNumber(data.total)} | Latest row: ${latest} | Fetched: ${fetchedAt}`;
  }
}

async function loadStatus() {
  const lead = (qs("status-lead")?.value || "").trim();
  const ip = (qs("status-ip")?.value || "").trim();
  const p = state.status.page;
  const query = new URLSearchParams({ page: String(p), page_size: "120", lead, ip });
  const data = await jget(`/api/status/timelapse?${query.toString()}`);
  state.status.totalPages = data.total_pages;
  qs("status-page").textContent = `${data.page} / ${data.total_pages}`;
  qs("status-table").querySelector("tbody").innerHTML = data.rows.length
    ? data.rows.map((r) => `<tr>
      <td>${r.timestamp || "-"}</td><td>${r.lead || "-"}</td><td>${r.printer_name || "-"}</td><td>${r.ip || "-"}</td>
      <td>${r.system_status || "-"}</td><td>${r.printer_status || "-"}</td><td>${r.copier_status || "-"}</td><td>${r.scanner_status || "-"}</td><td>${r.toner_black || "-"}</td><td>${r.tray_1_status || "-"}</td>
    </tr>`).join("")
    : `<tr><td colspan="10">No data</td></tr>`;
}

function renderHeatmapRows(rows) {
  const wrap = qs("heatmap-wrap");
  if (!wrap) return;
  const dayMode = state.heatmap.mode === "day";
  if (!rows.length) {
    wrap.textContent = "No data";
    return;
  }
  wrap.innerHTML = rows
    .map((r) => {
      const mins = Array.isArray(r.minutes) ? r.minutes : [];
      const segment = dayMode ? mins : mins.slice(state.heatmap.hour * 60, state.heatmap.hour * 60 + 60);
      const dots = segment
        .map((v, idx) => {
          const isSep = dayMode && idx > 0 && idx % 60 === 0;
          return `<span class="dot ${v ? "on" : "off"} ${isSep ? "hour-sep" : ""}"></span>`;
        })
        .join("");
      return `<div class="heatmap-row">
        <div class="heatmap-label">
          <div class="name">${r.printer_name || "-"}</div>
          <div class="meta">${r.ip || "-"} | samples: ${r.samples ?? 0}</div>
          <div class="meta">${r.first_total ?? "-"} -> ${r.last_total ?? "-"}</div>
        </div>
        <div class="dots ${dayMode ? "day" : "hour"}">${dots}</div>
      </div>`;
    })
    .join("");
}

async function loadHeatmap() {
  const dateValue = qs("heatmap-date")?.value || new Date().toISOString().slice(0, 10);
  const lead = (qs("heatmap-lead")?.value || "").trim();
  const p = state.heatmap.page;
  const query = new URLSearchParams({ page: String(p), page_size: "12", date: dateValue, lead });
  const data = await jget(`/api/counter/heatmap?${query.toString()}`);
  state.heatmap.totalPages = data.total_pages;
  qs("heatmap-page").textContent = `${data.page} / ${data.total_pages}`;
  renderHeatmapRows(data.rows || []);
}

function bind() {
  const page = currentPage();
  qs("refresh-btn")?.addEventListener("click", () => {
    refreshCurrentPage().catch(() => {});
  });
  qs("auto-refresh-toggle")?.addEventListener("change", (event) => {
    state.autoRefresh.enabled = Boolean(event.target?.checked);
    startAutoRefresh();
  });
  qs("auto-refresh-interval")?.addEventListener("change", (event) => {
    const raw = Number(event.target?.value || 10000);
    state.autoRefresh.intervalMs = Number.isFinite(raw) && raw > 0 ? raw : 10000;
    startAutoRefresh();
  });

  if (page === "dashboard") loadSummary().catch(() => {});
  if (page === "counter") {
    qs("counter-filter")?.addEventListener("click", () => { state.counter.page = 1; loadCounter(); });
    qs("counter-prev")?.addEventListener("click", () => { state.counter.page = Math.max(1, state.counter.page - 1); loadCounter(); });
    qs("counter-next")?.addEventListener("click", () => { state.counter.page = Math.min(state.counter.totalPages, state.counter.page + 1); loadCounter(); });
    loadCounter().catch(() => {});
  }
  if (page === "status") {
    qs("status-filter")?.addEventListener("click", () => { state.status.page = 1; loadStatus(); });
    qs("status-prev")?.addEventListener("click", () => { state.status.page = Math.max(1, state.status.page - 1); loadStatus(); });
    qs("status-next")?.addEventListener("click", () => { state.status.page = Math.min(state.status.totalPages, state.status.page + 1); loadStatus(); });
    loadStatus().catch(() => {});
  }
  if (page === "heatmap") {
    const dateInput = qs("heatmap-date");
    if (dateInput && !dateInput.value) dateInput.value = new Date().toISOString().slice(0, 10);
    const hourSelect = qs("heatmap-hour");
    if (hourSelect && !hourSelect.options.length) {
      hourSelect.innerHTML = Array.from({ length: 24 }, (_, h) => `<option value="${h}">Hour ${String(h).padStart(2, "0")}</option>`).join("");
      hourSelect.value = "0";
    }
    qs("heatmap-apply")?.addEventListener("click", () => { state.heatmap.page = 1; loadHeatmap(); });
    qs("heatmap-prev")?.addEventListener("click", () => { state.heatmap.page = Math.max(1, state.heatmap.page - 1); loadHeatmap(); });
    qs("heatmap-next")?.addEventListener("click", () => { state.heatmap.page = Math.min(state.heatmap.totalPages, state.heatmap.page + 1); loadHeatmap(); });
    qs("heatmap-mode-day")?.addEventListener("click", () => {
      state.heatmap.mode = "day";
      qs("heatmap-mode-day")?.classList.add("active");
      qs("heatmap-mode-hour")?.classList.remove("active");
      loadHeatmap();
    });
    qs("heatmap-mode-hour")?.addEventListener("click", () => {
      state.heatmap.mode = "hour";
      qs("heatmap-mode-hour")?.classList.add("active");
      qs("heatmap-mode-day")?.classList.remove("active");
      loadHeatmap();
    });
    hourSelect?.addEventListener("change", () => {
      state.heatmap.hour = Number(hourSelect.value || 0);
      if (state.heatmap.mode === "hour") loadHeatmap();
    });
    loadHeatmap().catch(() => {});
  }
  startAutoRefresh();
}

document.addEventListener("DOMContentLoaded", bind);
