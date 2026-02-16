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
  const res = await fetch("/api/overview");
  const data = await res.json();
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
    const res = await fetch("/api/devices/action", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip, action }),
    });
    let data = {};
    try {
      data = await res.json();
    } catch (_e) {
      data = { ok: false, error: `HTTP ${res.status}` };
    }
    if (!res.ok && data.ok === undefined) data.ok = false;

    if (data.ok) {
      if (out) out.textContent = JSON.stringify(data, null, 2);
      if (!out && !silent) {
        const msg = data.message || `${action} succeeded`;
        alert(msg);
      }
      return data;
    }

    const friendly = simplifyError(data.error || `HTTP ${res.status}`);
    if (out) out.textContent = friendly;
    if (!out && !silent) alert(friendly);
    if (data.error) console.error(`[${action}] raw error for ${ip}:`, data.error);
    return { ...data, ok: false, error: friendly, raw_error: data.error || null };
  } catch (err) {
    const friendly = simplifyError(err?.message || err);
    if (out) out.textContent = friendly;
    if (!out && !silent) alert(friendly);
    console.error(`[${action}] network error for ${ip}:`, err);
    return { ok: false, error: friendly, raw_error: String(err || "") };
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
  const res = await fetch("/api/devices");
  const data = await res.json();
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

  // Load current running log state per printer row
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

document.addEventListener("DOMContentLoaded", () => {
  const page = document.body.dataset.page;
  if (["dashboard", "analytics"].includes(page)) loadOverview();
  if (page === "devices") {
    loadOverview();
    loadDevices();
  }
  const refresh = document.getElementById("refresh-btn");
  if (refresh) {
    refresh.addEventListener("click", () => {
      if (page === "devices") {
        loadOverview();
        loadDevices();
      } else {
        loadOverview();
      }
    });
  }
});
