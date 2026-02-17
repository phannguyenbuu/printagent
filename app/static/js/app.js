function clamp(v, min, max) {
  return Math.max(min, Math.min(max, v));
}

function avg(values) {
  if (!values.length) return 0;
  return Math.round(values.reduce((a, b) => a + b, 0) / values.length);
}

function makePath(values, width, height, pad) {
  if (!values.length) return "";
  const min = Math.min(...values);
  const max = Math.max(...values);
  const spread = Math.max(max - min, 1);
  return values
    .map((value, idx) => {
      const x = pad + (idx * (width - pad * 2)) / Math.max(values.length - 1, 1);
      const normalized = (value - min) / spread;
      const y = height - pad - normalized * (height - pad * 2);
      return `${idx === 0 ? "M" : "L"} ${x.toFixed(2)} ${y.toFixed(2)}`;
    })
    .join(" ");
}

function jsonString(value) {
  return JSON.stringify(value, null, 2);
}

async function jsonFetch(url, options = {}) {
  const res = await fetch(url, options);
  let body = {};
  try {
    body = await res.json();
  } catch (_e) {
    body = {};
  }
  if (!res.ok) {
    const message = body.error || body.message || `HTTP ${res.status}`;
    throw new Error(message);
  }
  return body;
}

function renderTrendChart(el, labels, seriesA, seriesB, seriesC) {
  if (!el) return;
  const width = 900;
  const height = 320;
  const pad = 30;
  const grid = [];
  for (let i = 0; i < 5; i++) {
    const y = pad + ((height - pad * 2) / 4) * i;
    grid.push(`<line x1="${pad}" y1="${y}" x2="${width - pad}" y2="${y}" stroke="#e6edf7" stroke-width="1" />`);
  }
  const labelNodes = labels
    .map((label, idx) => {
      const x = pad + (idx * (width - pad * 2)) / Math.max(labels.length - 1, 1);
      return `<text x="${x}" y="${height - 8}" font-size="11" fill="#728197" text-anchor="middle">${label}</text>`;
    })
    .join("");

  el.innerHTML = `
    ${grid.join("")}
    <path d="${makePath(seriesA, width, height, pad)}" fill="none" stroke="#2e78ff" stroke-width="4" stroke-linecap="round" />
    <path d="${makePath(seriesB, width, height, pad)}" fill="none" stroke="#ff7a1a" stroke-width="4" stroke-linecap="round" />
    <path d="${makePath(seriesC, width, height, pad)}" fill="none" stroke="#10b8b8" stroke-width="4" stroke-linecap="round" />
    ${labelNodes}
  `;
}

function renderBars(el, labels, a, b, c) {
  if (!el) return;
  const maxVal = Math.max(...a, ...b, ...c, 1);
  el.innerHTML = labels
    .map((label, i) => {
      const ha = clamp((a[i] / maxVal) * 100, 4, 100);
      const hb = clamp((b[i] / maxVal) * 100, 4, 100);
      const hc = clamp((c[i] / maxVal) * 100, 4, 100);
      return `
      <div class="bar-col">
        <div class="bar-stack">
          <div class="bar a" style="height:${ha}%"></div>
          <div class="bar b" style="height:${hb}%"></div>
          <div class="bar c" style="height:${hc}%"></div>
        </div>
        <div class="bar-label">${label}</div>
      </div>`;
    })
    .join("");
}

async function loadOverview() {
  const data = await jsonFetch("/api/overview");
  const stats = data.stats || {};
  const trend = data.trend || {};
  const alerts = data.alerts || [];

  const byId = (id) => document.getElementById(id);
  if (byId("stat-total")) byId("stat-total").textContent = stats.total_devices ?? "--";
  if (byId("stat-ricoh")) byId("stat-ricoh").textContent = stats.ricoh_devices ?? "--";
  if (byId("stat-active")) byId("stat-active").textContent = stats.active_devices ?? "--";
  if (byId("stat-offline")) byId("stat-offline").textContent = stats.offline_devices ?? "--";
  const copierTotal = byId("stat-copier-total");
  const printTotal = byId("stat-print-total");
  const scanTotal = byId("stat-scan-total");
  if (copierTotal) copierTotal.textContent = stats.copier_pages_total ?? "--";
  if (printTotal) printTotal.textContent = stats.print_pages_total ?? "--";
  if (scanTotal) scanTotal.textContent = stats.scan_pages_total ?? "--";

  renderBars(
    byId("bar-chart"),
    trend.labels || [],
    trend.copier_pages || [],
    trend.print_pages || [],
    trend.scan_pages || []
  );

  renderTrendChart(
    byId("trend-chart"),
    trend.labels || [],
    trend.copier_pages || [],
    trend.print_pages || [],
    trend.scan_pages || []
  );

  renderTrendChart(
    byId("analytics-chart"),
    trend.labels || [],
    trend.copier_pages || [],
    trend.print_pages || [],
    trend.scan_pages || []
  );

  if (byId("avg-copier")) byId("avg-copier").textContent = avg(trend.copier_pages || []);
  if (byId("avg-print")) byId("avg-print").textContent = avg(trend.print_pages || []);
  if (byId("avg-scan")) byId("avg-scan").textContent = avg(trend.scan_pages || []);

  const alertsEl = byId("alerts");
  if (alertsEl) {
    alertsEl.innerHTML = alerts
      .map(
        (item) => `
      <div class="alert-item">
        <div>${item.title}</div>
        <div class="count">${item.count}</div>
      </div>`
      )
      .join("");
  }
}

async function runAction(ip, action, options = {}) {
  const silent = Boolean(options.silent);
  const out = document.getElementById("collect-output");
  if (out) out.textContent = `Running ${action} on ${ip}...`;
  const simplifyError = (raw) => {
    const msg = String(raw || "");
    const lowered = msg.toLowerCase();
    if (
      lowered.includes("connecttimeout") ||
      lowered.includes("timed out") ||
      lowered.includes("max retries exceeded")
    ) {
      return `Device ${ip || ""} is unreachable (connection timeout).`;
    }
    if (lowered.includes("connection refused")) {
      return `Device ${ip || ""} refused the connection.`;
    }
    if (lowered.includes("name or service not known") || lowered.includes("nodename nor servname")) {
      return `Cannot resolve device address: ${ip || "unknown host"}.`;
    }
    return `Action "${action}" failed for ${ip || "selected device"}.`;
  };

  try {
    const data = await jsonFetch("/api/devices/action", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip, action }),
    });
    if (data.ok) {
      if (out) out.textContent = jsonString(data);
      if (!out && !silent) {
        const msg = data.message || `${action} succeeded`;
        alert(msg);
      }
      return data;
    }
    const friendly = simplifyError(data.error || "Unknown error");
    if (out) out.textContent = friendly;
    if (!out && !silent) alert(friendly);
    return { ...data, ok: false, error: friendly };
  } catch (err) {
    const friendly = simplifyError(err?.message || err);
    if (out) out.textContent = friendly;
    if (!out && !silent) alert(friendly);
    return { ok: false, error: friendly };
  }
}

function setRowEnabled(row, enabled) {
  if (!row) return;
  row.classList.toggle("device-row-disabled", !enabled);
  row.querySelectorAll("button, input, select, textarea").forEach((el) => {
    if (el.dataset.rowChecker === "enable") return;
    el.disabled = !enabled;
  });
}

async function loadDevices() {
  const body = document.getElementById("device-table-body");
  if (!body) return;
  const data = await jsonFetch("/api/devices");
  const devices = data.devices || [];
  if (!devices.length) {
    body.innerHTML = `<tr><td colspan="11">No devices found.</td></tr>`;
    return;
  }
  body.innerHTML = devices
    .map((d) => {
      const ok = ["active", "online", "ready"].includes(String(d.status || "").toLowerCase());
      const hasIp = Boolean(d.ip);
      return `
      <tr>
        <td>
          <label class="mini-switch">
            <input type="checkbox" data-row-checker="enable" data-ip="${d.ip || ""}" ${hasIp ? "checked" : "disabled"} />
            <span class="mini-slider"></span>
          </label>
        </td>
        <td>${d.name}</td>
        <td>${d.ip || "-"}</td>
        <td>${d.port_name || "-"}</td>
        <td>${d.connection_type || "-"}</td>
        <td>${d.type}</td>
        <td><span class="badge ${ok ? "ok" : "warn"}">${d.status || "unknown"}</span></td>
        <td>${d.source || "-"}</td>
        <td>
          <button class="btn action" data-ip="${d.ip || ""}" data-action="status" ${hasIp ? "" : "disabled"}>Status</button>
          <button class="btn action alt" data-ip="${d.ip || ""}" data-action="counter" ${hasIp ? "" : "disabled"}>Counter</button>
        </td>
        <td>
          <label class="mini-switch">
            <input type="checkbox" data-row-checker="counter" data-ip="${d.ip || ""}" ${hasIp ? "" : "disabled"} />
            <span class="mini-slider"></span>
          </label>
        </td>
        <td>
          <label class="mini-switch">
            <input type="checkbox" data-row-checker="status" data-ip="${d.ip || ""}" ${hasIp ? "" : "disabled"} />
            <span class="mini-slider"></span>
          </label>
        </td>
      </tr>`;
    })
    .join("");

  body.querySelectorAll("button[data-ip][data-action]").forEach((btn) => {
    btn.addEventListener("click", () => runAction(btn.dataset.ip, btn.dataset.action));
  });

  const rowCheckerInputs = body.querySelectorAll("input[data-row-checker][data-ip]");
  const ipSet = new Set();
  rowCheckerInputs.forEach((inp) => {
    const ip = inp.dataset.ip || "";
    if (!ip) return;
    ipSet.add(ip);
    if (inp.dataset.bound) return;
    inp.dataset.bound = "1";
    inp.addEventListener("change", async () => {
      const isChecked = inp.checked;
      const kind = inp.dataset.rowChecker;
      const row = inp.closest("tr");
      let action = "";
      if (kind === "enable") action = isChecked ? "enable_machine" : "lock_machine";
      if (kind === "counter") action = isChecked ? "log_counter_start" : "log_counter_stop";
      if (kind === "status") action = isChecked ? "log_status_start" : "log_status_stop";
      if (!action) return;
      const result = await runAction(ip, action);
      if (!result.ok) {
        inp.checked = !isChecked;
        return;
      }
      if (kind === "enable") {
        if (!isChecked) {
          const counterInp = row?.querySelector('input[data-row-checker="counter"]');
          const statusInp = row?.querySelector('input[data-row-checker="status"]');
          if (counterInp) counterInp.checked = false;
          if (statusInp) statusInp.checked = false;
        }
        setRowEnabled(row, isChecked);
      }
    });
  });

  body.querySelectorAll('input[data-row-checker="enable"]').forEach((enableInput) => {
    setRowEnabled(enableInput.closest("tr"), !enableInput.disabled && enableInput.checked);
  });

  for (const ip of ipSet) {
    try {
      const st = await runAction(ip, "job_status", { silent: true });
      const counterOn = Boolean(st.counter_running);
      const statusOn = Boolean(st.status_running);
      const e = body.querySelector(`input[data-row-checker="enable"][data-ip="${ip}"]`);
      const c = body.querySelector(`input[data-row-checker="counter"][data-ip="${ip}"]`);
      const s = body.querySelector(`input[data-row-checker="status"][data-ip="${ip}"]`);
      if (e) {
        e.checked = true;
        setRowEnabled(e.closest("tr"), true);
      }
      if (c) c.checked = counterOn;
      if (s) s.checked = statusOn;
    } catch (_e) {}
  }
}

const dashboardState = {
  env: {},
  network: {},
  computers: [],
  printers: [],
  links: [],
};

function setDashboardMessage(text) {
  const out = document.getElementById("dashboard-config-output");
  if (out) out.textContent = text;
}

function renderEnvGrid(envPayload) {
  const root = document.getElementById("env-config-grid");
  if (!root) return;
  const keys = Object.keys(envPayload || {});
  if (!keys.length) {
    root.innerHTML = `<div class="hint">No env values available.</div>`;
    return;
  }
  root.innerHTML = keys
    .map(
      (key) => `
      <div class="env-item">
        <div class="env-key">${key}</div>
        <div class="env-value">${envPayload[key] ?? ""}</div>
      </div>`
    )
    .join("");
}

function renderNetworkForm(networkPayload) {
  const form = document.getElementById("network-config-form");
  if (!form) return;
  ["subnet_mask", "gateway", "dns_primary", "dns_secondary", "snmp_community", "snmp_port", "timeout_seconds"].forEach(
    (key) => {
      if (!form.elements[key]) return;
      form.elements[key].value = networkPayload[key] ?? "";
    }
  );
}

function renderComputersTable(computers) {
  const body = document.getElementById("computers-body");
  if (!body) return;
  if (!computers.length) {
    body.innerHTML = `<tr><td colspan="4">No computers configured.</td></tr>`;
    return;
  }
  body.innerHTML = computers
    .map(
      (row) => `
      <tr>
        <td>${row.name}</td>
        <td>${row.ip || "-"}</td>
        <td>${row.department || "-"}</td>
        <td><button class="btn action alt js-delete-computer" data-id="${row.id}">Delete</button></td>
      </tr>`
    )
    .join("");
}

function renderPrintersTable(printers) {
  const body = document.getElementById("printers-body");
  if (!body) return;
  if (!printers.length) {
    body.innerHTML = `<tr><td colspan="5">No printers configured.</td></tr>`;
    return;
  }
  body.innerHTML = printers
    .map(
      (row) => `
      <tr>
        <td>${row.name}</td>
        <td>${row.ip || "-"}</td>
        <td>${row.model || "-"}</td>
        <td>${row.location || "-"}</td>
        <td><button class="btn action alt js-delete-printer" data-id="${row.id}">Delete</button></td>
      </tr>`
    )
    .join("");
}

function buildLinkKey(computerId, printerId) {
  return `${computerId}:${printerId}`;
}

function renderLinkMatrix(computers, printers, links) {
  const table = document.getElementById("link-matrix");
  if (!table) return;
  const thead = table.querySelector("thead");
  const tbody = table.querySelector("tbody");
  if (!thead || !tbody) return;
  if (!computers.length || !printers.length) {
    thead.innerHTML = "";
    tbody.innerHTML = `<tr><td>Need at least 1 computer and 1 printer to map.</td></tr>`;
    return;
  }

  const selected = new Set((links || []).map((row) => buildLinkKey(row.computer_id, row.printer_id)));
  thead.innerHTML = `
    <tr>
      <th>Computer \\ Printer</th>
      ${printers.map((printer) => `<th>${printer.name}</th>`).join("")}
    </tr>`;

  tbody.innerHTML = computers
    .map((computer) => {
      return `
        <tr>
          <td><strong>${computer.name}</strong><br /><span class="hint">${computer.ip || "-"}</span></td>
          ${printers
            .map((printer) => {
              const key = buildLinkKey(computer.id, printer.id);
              const checked = selected.has(key) ? "checked" : "";
              return `
                <td>
                  <label class="mini-switch">
                    <input type="checkbox" data-link-check="1" data-computer-id="${computer.id}" data-printer-id="${printer.id}" ${checked} />
                    <span class="mini-slider"></span>
                  </label>
                </td>`;
            })
            .join("")}
        </tr>`;
    })
    .join("");
}

function collectLinkPayload() {
  const nodes = document.querySelectorAll('input[data-link-check="1"]:checked');
  return Array.from(nodes).map((node) => ({
    computer_id: Number(node.dataset.computerId || 0),
    printer_id: Number(node.dataset.printerId || 0),
  }));
}

function bindDashboardActions() {
  const networkForm = document.getElementById("network-config-form");
  const computerForm = document.getElementById("computer-form");
  const printerForm = document.getElementById("printer-form");
  const saveLinksBtn = document.getElementById("save-links-btn");
  const computersBody = document.getElementById("computers-body");
  const printersBody = document.getElementById("printers-body");

  if (networkForm && !networkForm.dataset.bound) {
    networkForm.dataset.bound = "1";
    networkForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const payload = {
        subnet_mask: networkForm.elements.subnet_mask.value,
        gateway: networkForm.elements.gateway.value,
        dns_primary: networkForm.elements.dns_primary.value,
        dns_secondary: networkForm.elements.dns_secondary.value,
        snmp_community: networkForm.elements.snmp_community.value,
        snmp_port: Number(networkForm.elements.snmp_port.value || 161),
        timeout_seconds: Number(networkForm.elements.timeout_seconds.value || 10),
      };
      try {
        await jsonFetch("/api/dashboard/network", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        setDashboardMessage("Saved network config.");
      } catch (err) {
        setDashboardMessage(`Save network config failed: ${err.message}`);
      }
    });
  }

  if (computerForm && !computerForm.dataset.bound) {
    computerForm.dataset.bound = "1";
    computerForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const payload = {
        name: computerForm.elements.name.value,
        ip: computerForm.elements.ip.value,
        department: computerForm.elements.department.value,
      };
      try {
        await jsonFetch("/api/dashboard/computers", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        computerForm.reset();
        await loadDashboardConfig();
        setDashboardMessage("Added computer.");
      } catch (err) {
        setDashboardMessage(`Add computer failed: ${err.message}`);
      }
    });
  }

  if (printerForm && !printerForm.dataset.bound) {
    printerForm.dataset.bound = "1";
    printerForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const payload = {
        name: printerForm.elements.name.value,
        ip: printerForm.elements.ip.value,
        model: printerForm.elements.model.value,
        location: printerForm.elements.location.value,
      };
      try {
        await jsonFetch("/api/dashboard/printers", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        printerForm.reset();
        await loadDashboardConfig();
        setDashboardMessage("Added printer.");
      } catch (err) {
        setDashboardMessage(`Add printer failed: ${err.message}`);
      }
    });
  }

  if (saveLinksBtn && !saveLinksBtn.dataset.bound) {
    saveLinksBtn.dataset.bound = "1";
    saveLinksBtn.addEventListener("click", async () => {
      const payload = { links: collectLinkPayload() };
      try {
        const resp = await jsonFetch("/api/dashboard/links", {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        setDashboardMessage(`Saved mapping: ${resp.total_links} links.`);
      } catch (err) {
        setDashboardMessage(`Save mapping failed: ${err.message}`);
      }
    });
  }

  if (computersBody && !computersBody.dataset.bound) {
    computersBody.dataset.bound = "1";
    computersBody.addEventListener("click", async (event) => {
      const btn = event.target.closest(".js-delete-computer");
      if (!btn) return;
      try {
        await jsonFetch(`/api/dashboard/computers/${btn.dataset.id}`, { method: "DELETE" });
        await loadDashboardConfig();
        setDashboardMessage("Deleted computer.");
      } catch (err) {
        setDashboardMessage(`Delete computer failed: ${err.message}`);
      }
    });
  }

  if (printersBody && !printersBody.dataset.bound) {
    printersBody.dataset.bound = "1";
    printersBody.addEventListener("click", async (event) => {
      const btn = event.target.closest(".js-delete-printer");
      if (!btn) return;
      try {
        await jsonFetch(`/api/dashboard/printers/${btn.dataset.id}`, { method: "DELETE" });
        await loadDashboardConfig();
        setDashboardMessage("Deleted printer.");
      } catch (err) {
        setDashboardMessage(`Delete printer failed: ${err.message}`);
      }
    });
  }
}

async function loadDashboardConfig() {
  try {
    const data = await jsonFetch("/api/dashboard/config");
    dashboardState.env = data.env || {};
    dashboardState.network = data.network || {};
    dashboardState.computers = data.computers || [];
    dashboardState.printers = data.printers || [];
    dashboardState.links = data.links || [];

    renderEnvGrid(dashboardState.env);
    renderNetworkForm(dashboardState.network);
    renderComputersTable(dashboardState.computers);
    renderPrintersTable(dashboardState.printers);
    renderLinkMatrix(dashboardState.computers, dashboardState.printers, dashboardState.links);
  } catch (err) {
    setDashboardMessage(`Load dashboard config failed: ${err.message}`);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const page = document.body.dataset.page;
  if (page === "dashboard") {
    bindDashboardActions();
    loadDashboardConfig();
  }
  if (page === "analytics") loadOverview().catch(() => {});
  if (page === "devices") {
    loadOverview().catch(() => {});
    loadDevices();
  }
  const refresh = document.getElementById("refresh-btn");
  if (refresh) {
    refresh.addEventListener("click", () => {
      if (page === "dashboard") {
        loadDashboardConfig();
      } else if (page === "devices") {
        loadOverview().catch(() => {});
        loadDevices();
      } else {
        loadOverview().catch(() => {});
      }
    });
  }
});
