const palette = ["#3fbf9f", "#e0a33a", "#6f8cff", "#d85d7c", "#7fcf5f", "#9f80ff"];
const emptyText = "No data returned by API";
const state = {
  session: null,
  data: {},
  failures: [],
  search: "",
  metricSeries: {},
};

const endpoints = {
  overview: "/api/v1/metrics/overview",
  capacity: "/api/v1/metrics/capacity",
  dependencies: "/api/v1/metrics/dependencies",
  nodes: "/api/v1/nodes",
  kernel: "/api/v1/nodes/kernel-tuning",
  rules: "/api/v1/rules",
  ruleSources: "/api/v1/rules/rule-sets",
  traces: "/api/v1/routes/traces?limit=40",
  subscriptions: "/api/v1/subscriptions",
  conversions: "/api/v1/subscriptions/conversions",
  warp: "/api/v1/warp/profiles",
  protocols: "/api/v1/protocols/stats",
  logs: "/api/v1/logs",
  audit: "/api/v1/audit-logs",
  alerts: "/api/v1/alerts",
  waivers: "/api/v1/security/waivers",
  incidents: "/api/v1/incidents",
  runbooks: "/api/v1/incidents/runbooks",
  argo: "/api/v1/argo/tunnels",
};

const regionCoordinates = {
  CN: [720, 248],
  HK: [748, 286],
  SG: [705, 336],
  JP: [805, 236],
  KR: [780, 238],
  TW: [772, 276],
  US: [230, 238],
  CA: [210, 180],
  BR: [360, 390],
  GB: [470, 190],
  DE: [500, 205],
  FR: [486, 220],
  NL: [495, 196],
  RU: [620, 160],
  IN: [650, 290],
  AU: [815, 410],
};

function byId(id) {
  return document.getElementById(id);
}

function valueOf(row, ...names) {
  if (!row || typeof row !== "object") return undefined;
  for (const name of names) {
    if (Object.prototype.hasOwnProperty.call(row, name)) return row[name];
  }
  return undefined;
}

function text(value, fallback = "—") {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

function number(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function percent(value) {
  if (value === null || value === undefined || value === "") return "—";
  return `${Math.round(number(value) * 100)}%`;
}

function compactNumber(value) {
  const n = number(value);
  return new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(n);
}

function bytes(value) {
  let n = Math.max(0, number(value));
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let unit = 0;
  while (n >= 1024 && unit < units.length - 1) {
    n /= 1024;
    unit += 1;
  }
  return `${n.toFixed(n >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function bps(value) {
  return `${bytes(number(value))}/s`;
}

function ms(value) {
  return value === null || value === undefined || value === "" ? "—" : `${Math.round(number(value))} ms`;
}

function timeAgo(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString();
}

function normalizeRows(value) {
  return Array.isArray(value) ? value : [];
}

function setStatus(el, label, tone = "") {
  if (!el) return;
  el.textContent = label;
  el.className = `status ${tone}`.trim();
}

function rowMatchesSearch(row) {
  if (!state.search) return true;
  return JSON.stringify(row).toLowerCase().includes(state.search);
}

function filterRows(rows) {
  return normalizeRows(rows).filter(rowMatchesSearch);
}

function renderEmpty(tbody, colspan) {
  tbody.innerHTML = `<tr class="empty"><td colspan="${colspan}">${emptyText}</td></tr>`;
}

function renderRows(tbodyId, rows, colspan, renderRow) {
  const tbody = byId(tbodyId);
  if (!tbody) return;
  const filtered = filterRows(rows);
  if (!filtered.length) {
    renderEmpty(tbody, colspan);
    return;
  }
  tbody.replaceChildren(...filtered.map(renderRow));
}

function tr(cells) {
  const row = document.createElement("tr");
  for (const cell of cells) {
    const td = document.createElement("td");
    if (cell instanceof Node) td.appendChild(cell);
    else td.textContent = text(cell);
    row.appendChild(td);
  }
  return row;
}

function badge(label, tone = "") {
  const span = document.createElement("span");
  span.className = `badge ${tone}`.trim();
  span.textContent = text(label);
  return span;
}

function loadSession() {
  try {
    const raw = sessionStorage.getItem("mi-panel-session");
    state.session = raw ? JSON.parse(raw) : null;
  } catch {
    state.session = null;
  }
}

function saveSession(session) {
  state.session = session;
  sessionStorage.setItem("mi-panel-session", JSON.stringify(session));
}

function clearSession() {
  state.session = null;
  state.data = {};
  sessionStorage.removeItem("mi-panel-session");
  renderAll();
}

function apiBase() {
  const base = text(valueOf(state.session, "apiBase"), "").trim();
  return base === "/" ? "" : base.replace(/\/$/, "");
}

function authHeaders(method = "GET") {
  const headers = { Accept: "application/json" };
  const session = state.session || {};
  if (session.authMode === "bearer" && session.apiToken) {
    headers.Authorization = `Bearer ${session.apiToken}`;
  }
  if (session.authMode === "gateway") {
    if (session.userId) headers["X-User-ID"] = session.userId;
    if (session.tenantId) headers["X-Tenant-ID"] = session.tenantId;
    if (session.role) headers["X-Role"] = session.role;
    if (session.csrfToken) headers["X-CSRF-Token"] = session.csrfToken;
    if (session.confirmationToken) headers["X-Confirm-Token"] = session.confirmationToken;
  }
  if (method !== "GET") headers["Content-Type"] = "application/json";
  return headers;
}

async function apiFetch(path, options = {}) {
  const method = options.method || "GET";
  const res = await fetch(`${apiBase()}${path}`, {
    ...options,
    method,
    headers: { ...authHeaders(method), ...(options.headers || {}) },
  });
  const contentType = res.headers.get("Content-Type") || "";
  const body = contentType.includes("application/json") ? await res.json() : await res.text();
  if (!res.ok) {
    const message = typeof body === "string" ? body.trim() : JSON.stringify(body);
    throw new Error(message || `${res.status} ${res.statusText}`);
  }
  return body;
}

async function refreshData() {
  if (!state.session) {
    setConnection("Disconnected", "warn");
    return;
  }
  setConnection("Loading", "warn");
  state.failures = [];
  state.data = {};
  const entries = Object.entries(endpoints);
  const results = await Promise.allSettled(entries.map(([key, path]) => apiFetch(path).then(data => [key, data])));
  let successCount = 0;
  for (const result of results) {
    if (result.status === "fulfilled") {
      const [key, data] = result.value;
      state.data[key] = data;
      successCount += 1;
    } else {
      state.failures.push(result.reason.message);
    }
  }
  await loadNodeMetricSamples();
  await loadScholarGuard();
  const connected = successCount > 0;
  setConnection(connected ? "Live" : "Error", connected ? "ok" : "bad");
  byId("lastUpdated").textContent = connected ? `Updated ${new Date().toLocaleString()}` : "No API data loaded";
  renderAll();
}

async function loadNodeMetricSamples() {
  const nodes = normalizeRows(state.data.nodes).slice(0, 6);
  const samples = [];
  await Promise.allSettled(nodes.map(async node => {
    const id = valueOf(node, "ID", "id");
    if (!id) return;
    const data = await apiFetch(`/api/v1/metrics/nodes/${encodeURIComponent(id)}?limit=24`);
    samples.push(...normalizeRows(data).map(sample => ({ ...sample, NodeID: valueOf(sample, "NodeID", "nodeId") || id })));
  }));
  state.data.nodeSamples = samples;
}

async function loadScholarGuard() {
  if (!state.session) return;
  try {
    state.data.scholarGuard = await apiFetch("/api/v1/rules/test-domain?input=scholar.google.com");
  } catch (err) {
    state.data.scholarGuard = { error: err.message };
  }
}

function setConnection(label, tone) {
  const pill = byId("connectionPill");
  if (!pill) return;
  pill.textContent = label;
  pill.className = `pill ${tone}`.trim();
}

function metricCard(label, value, series) {
  const article = document.createElement("article");
  const span = document.createElement("span");
  const strong = document.createElement("strong");
  const canvas = document.createElement("canvas");
  span.textContent = label;
  strong.textContent = value;
  article.append(span, strong, canvas);
  requestAnimationFrame(() => drawLine(canvas, series || [number(String(value).replace(/[^\d.]/g, ""))]));
  return article;
}

function renderMetrics() {
  const overview = state.data.overview || {};
  const capacity = state.data.capacity || {};
  const metricGrid = byId("metricGrid");
  if (!metricGrid) return;
  setStatus(byId("healthStatus"), text(valueOf(overview, "Health", "health"), "Unknown"), healthTone(valueOf(overview, "Health", "health")));
  const metrics = [
    ["Online nodes", compactNumber(valueOf(overview, "OnlineNodes", "onlineNodes"))],
    ["Offline nodes", compactNumber(valueOf(overview, "OfflineNodes", "offlineNodes"))],
    ["Alerts", compactNumber(valueOf(overview, "Alerts", "alerts"))],
    ["Total connections", compactNumber(valueOf(overview, "TotalConnections", "totalConnections"))],
    ["Active connections", compactNumber(valueOf(overview, "ActiveConnections", "activeConnections"))],
    ["New connection rate", `${compactNumber(valueOf(overview, "NewConnectionRate", "newConnectionRate"))}/s`],
    ["Total traffic", bytes(valueOf(overview, "TotalTrafficBytes", "totalTrafficBytes"))],
    ["Up / Down", `${bps(valueOf(overview, "UpBps", "upBps"))} / ${bps(valueOf(overview, "DownBps", "downBps"))}`],
    ["CPU / memory", `${percent(valueOf(overview, "CPU", "cpu"))} / ${percent(valueOf(overview, "Memory", "memory"))}`],
    ["Disk / FD", `${percent(valueOf(overview, "Disk", "disk"))} / ${percent(valueOf(overview, "FDUsage", "fdUsage"))}`],
    ["Network PPS", compactNumber(valueOf(overview, "NetworkPPS", "networkPPS"))],
    ["99p API latency", ms(valueOf(overview, "API99pMs", "api99pMs"))],
    ["Subscription latency", ms(valueOf(overview, "Subscription99pMs", "subscription99pMs"))],
    ["Config apply latency", ms(valueOf(overview, "ConfigApply99pMs", "configApply99pMs"))],
    ["Capacity tier", text(valueOf(capacity, "Tier", "tier"))],
    ["Autoscaling recommendation", `${compactNumber(valueOf(capacity, "RecommendedAPIReplicas", "recommendedAPIReplicas"))} API replicas`],
    ["Cost guardrail", text((valueOf(capacity, "CostActions", "costActions") || [])[0])],
  ];
  metricGrid.replaceChildren(...metrics.map(([label, value], index) => metricCard(label, value, metricSeriesFor(label, index))));
}

function metricSeriesFor(label, index) {
  const samples = normalizeRows(state.data.nodeSamples);
  const fieldByLabel = {
    "Total connections": ["Connections", "connections"],
    "Active connections": ["Connections", "connections"],
    "Up / Down": ["TxBps", "txBps"],
    "CPU / memory": ["CPU", "cpu"],
    "Disk / FD": ["Disk", "disk"],
    "Network PPS": ["NetworkPPS", "networkPPS"],
  };
  const fields = fieldByLabel[label];
  if (!fields || !samples.length) return [0];
  return samples.map(sample => number(valueOf(sample, ...fields))).slice(-24 + index % 4);
}

function renderOverviewPanels() {
  const overview = state.data.overview || {};
  const capacity = state.data.capacity || {};
  renderTrafficMap();
  renderRows("exitQualityBody", valueOf(overview, "TopExitQualityRows", "topExitQualityRows"), 4, row => {
    const probe = valueOf(row, "LastProbe", "lastProbe") || {};
    return tr([
      valueOf(row, "Name", "name", "ID", "id"),
      badge(valueOf(row, "Status", "status"), warpTone(valueOf(row, "Status", "status"))),
      ms(valueOf(probe, "LatencyMs", "latencyMs")),
      percent(valueOf(probe, "Loss", "loss")),
    ]);
  });
  byId("capacityPlan").replaceChildren(
    ...[
      ["Tier", valueOf(capacity, "Tier", "tier")],
      ["Control plane mode", valueOf(capacity, "ControlPlaneMode", "controlPlaneMode")],
      ["Target API RPS", compactNumber(valueOf(capacity, "TargetAPIRPS", "targetAPIRPS"))],
      ["Target subscription RPS", compactNumber(valueOf(capacity, "TargetSubscriptionRPS", "targetSubscriptionRPS"))],
      ["Actions", normalizeRows(valueOf(capacity, "AutoscalingActions", "autoscalingActions")).join("; ")],
      ["Reasons", normalizeRows(valueOf(capacity, "Reasons", "reasons")).join("; ")],
    ].map(([label, value]) => keyValue(label, value))
  );
  let deps = normalizeRows(valueOf(state.data.dependencies, "Dependencies", "dependencies"));
  if (!deps.length) deps = normalizeRows(valueOf(overview, "DependencyRows", "dependencyRows"));
  renderRows("dependencyBody", deps, 3, row => tr([
    valueOf(row, "Name", "name"),
    badge(valueOf(row, "State", "state"), healthTone(valueOf(row, "State", "state"))),
    valueOf(row, "Message", "message"),
  ]));
  renderResourceRings();
  drawLine(byId("trafficTrendChart"), normalizeRows(state.data.nodeSamples).map(sample => number(valueOf(sample, "RxBps", "rxBps")) + number(valueOf(sample, "TxBps", "txBps"))));
  drawLine(byId("resourceChart"), normalizeRows(state.data.nodeSamples).map(sample => number(valueOf(sample, "CPU", "cpu"))));
}

function keyValue(label, value) {
  const div = document.createElement("div");
  div.className = "kv";
  const k = document.createElement("span");
  const v = document.createElement("strong");
  k.textContent = label;
  v.textContent = text(value);
  div.append(k, v);
  return div;
}

function renderResourceRings() {
  const overview = state.data.overview || {};
  const rings = byId("resourceRings");
  if (!rings) return;
  const items = [
    ["CPU", valueOf(overview, "CPU", "cpu")],
    ["Memory", valueOf(overview, "Memory", "memory")],
    ["FD", valueOf(overview, "FDUsage", "fdUsage")],
  ];
  rings.replaceChildren(...items.map(([label, value]) => {
    const span = document.createElement("span");
    const ratio = Math.max(0, Math.min(1, number(value)));
    span.style.setProperty("--ring", `${Math.round(ratio * 100)}%`);
    span.innerHTML = `${label}<strong>${percent(ratio)}</strong>`;
    return span;
  }));
}

function renderTrafficMap() {
  const nodes = normalizeRows(state.data.nodes);
  const warp = normalizeRows(state.data.warp);
  const map = byId("trafficMap");
  if (!map) return;
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 1000 520");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "Node topology by region");
  svg.innerHTML = `
    <path class="land" d="M116 162c68-74 184-68 250-18 44 33 92 24 148 13 80-15 145-10 205 39 45 37 97 35 157 26 28-4 48 18 36 43-24 48-100 45-150 65-68 28-97 86-182 72-80-13-106-72-167-77-78-6-104 83-190 62-51-13-82-50-105-92-22-41-48-88-2-133z"/>
    <path class="land secondary" d="M188 346c60-13 97 28 136 66 22 22 54 42 44 70-14 37-82 22-120-3-42-28-105-39-103-88 1-22 17-39 43-45z"/>
    <path class="land secondary" d="M735 368c40-12 91 5 126 34 29 23 21 60-19 66-55 8-129-18-141-58-5-17 7-34 34-42z"/>
  `;
  const center = [500, 270];
  const regionCounts = new Map();
  nodes.forEach(node => {
    const region = text(valueOf(node, "Region", "region"), "unknown").toUpperCase();
    regionCounts.set(region, (regionCounts.get(region) || 0) + 1);
    const point = coordinatesForRegion(region);
    svg.appendChild(svgLine(center, point, "link"));
  });
  nodes.forEach(node => {
    const region = text(valueOf(node, "Region", "region"), "unknown").toUpperCase();
    const [x, y] = jitter(coordinatesForRegion(region), valueOf(node, "ID", "id"));
    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("cx", x);
    circle.setAttribute("cy", y);
    circle.setAttribute("r", Math.max(6, Math.min(18, 6 + Math.sqrt(number(valueOf(node, "Connections", "connections")) || 1))));
    circle.setAttribute("class", `map-node ${nodeTone(valueOf(node, "Status", "status"))}`);
    const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
    title.textContent = `${text(valueOf(node, "Name", "name", "ID", "id"))} ${region} ${text(valueOf(node, "Status", "status"))}`;
    circle.appendChild(title);
    svg.appendChild(circle);
  });
  warp.forEach(profile => {
    const nodeID = valueOf(profile, "NodeID", "nodeId");
    const node = nodes.find(item => valueOf(item, "ID", "id") === nodeID);
    if (!node) return;
    const [x, y] = jitter(coordinatesForRegion(text(valueOf(node, "Region", "region"), "").toUpperCase()), valueOf(profile, "ID", "id"));
    const ring = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    ring.setAttribute("cx", x);
    ring.setAttribute("cy", y);
    ring.setAttribute("r", 22);
    ring.setAttribute("class", `warp-ring ${warpTone(valueOf(profile, "Status", "status"))}`);
    svg.appendChild(ring);
  });
  map.replaceChildren(svg);
  const summary = [...regionCounts.entries()].sort().map(([region, count]) => `${region} ${count}`).join(" · ");
  byId("mapSummary").textContent = summary || "No node coordinates";
}

function svgLine(a, b, klass) {
  const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
  line.setAttribute("x1", a[0]);
  line.setAttribute("y1", a[1]);
  line.setAttribute("x2", b[0]);
  line.setAttribute("y2", b[1]);
  line.setAttribute("class", klass);
  return line;
}

function coordinatesForRegion(region) {
  if (regionCoordinates[region]) return regionCoordinates[region];
  let hash = 0;
  for (const char of region) hash = (hash * 31 + char.charCodeAt(0)) % 997;
  return [140 + (hash % 720), 140 + ((hash * 7) % 260)];
}

function jitter(point, seed = "") {
  let hash = 0;
  for (const char of String(seed)) hash = (hash * 33 + char.charCodeAt(0)) % 97;
  return [point[0] + (hash % 19) - 9, point[1] + ((hash * 5) % 19) - 9];
}

function renderNodes() {
  renderRows("nodeBody", state.data.nodes, 9, row => tr([
    valueOf(row, "Name", "name", "ID", "id"),
    valueOf(row, "Region", "region"),
    badge(valueOf(row, "Status", "status"), nodeTone(valueOf(row, "Status", "status"))),
    valueOf(row, "SingBoxVersion", "singBoxVersion"),
    compactNumber(valueOf(row, "Connections", "connections")),
    percent(valueOf(row, "CPU", "cpu")),
    percent(valueOf(row, "Memory", "memory")),
    valueOf(row, "KernelVersion", "kernelVersion"),
    `${text(valueOf(row, "PortRangeStart", "portRangeStart"))}-${text(valueOf(row, "PortRangeEnd", "portRangeEnd"))}`,
  ]));
  renderRows("kernelBody", state.data.kernel, 6, row => tr([
    valueOf(row, "NodeID", "nodeId"),
    valueOf(row, "Region", "region"),
    valueOf(row, "CongestionControl", "congestionControl"),
    valueOf(row, "QueueDiscipline", "queueDiscipline"),
    valueOf(row, "NoFile", "noFile"),
    normalizeRows(valueOf(row, "Issues", "issues")).join(", "),
  ]));
  drawBars(byId("regionChart"), regionCounts());
  drawLine(byId("nodeResourceChart"), normalizeRows(state.data.nodeSamples).map(sample => number(valueOf(sample, "CPU", "cpu"))));
}

function regionCounts() {
  const counts = {};
  normalizeRows(state.data.nodes).forEach(node => {
    const region = text(valueOf(node, "Region", "region"), "unknown").toUpperCase();
    counts[region] = (counts[region] || 0) + 1;
  });
  return counts;
}

function renderRoutes() {
  renderRows("ruleSourceBody", state.data.ruleSources, 3, row => tr([
    valueOf(row, "name", "Name"),
    valueOf(row, "sourceUrl", "SourceURL"),
    valueOf(row, "checksum", "Checksum"),
  ]));
  renderRows("routeTraceBody", state.data.traces, 7, routeTraceRow);
  renderRows("recentFlowBody", state.data.traces, 5, row => tr([
    valueOf(row, "Input", "input"),
    valueOf(row, "Protocol", "protocol"),
    valueOf(row, "NodeID", "nodeId"),
    valueOf(row, "Outbound", "outbound"),
    valueOf(row, "Decision", "decision", "Reason", "reason"),
  ]));
  renderRows("ruleBody", state.data.rules, 4, row => tr([
    valueOf(row, "ID", "id", "RuleID", "ruleId", "MatchedRule", "matchedRule"),
    valueOf(row, "Type", "type", "RuleType", "ruleType"),
    valueOf(row, "Outbound", "outbound"),
    valueOf(row, "Source", "source", "MatchedSource", "matchedSource"),
  ]));
  drawBars(byId("routeMixChart"), outboundCounts(normalizeRows(state.data.traces)));
}

function routeTraceRow(row) {
  return tr([
    valueOf(row, "Input", "input"),
    valueOf(row, "Protocol", "protocol"),
    valueOf(row, "NodeID", "nodeId"),
    valueOf(row, "Outbound", "outbound"),
    valueOf(row, "RuleID", "ruleId"),
    valueOf(row, "MatchedSource", "matchedSource"),
    valueOf(row, "Decision", "decision", "Reason", "reason"),
  ]);
}

function outboundCounts(rows) {
  const counts = {};
  rows.forEach(row => {
    const key = text(valueOf(row, "Outbound", "outbound"), "unknown");
    counts[key] = (counts[key] || 0) + 1;
  });
  return counts;
}

async function handleRouteProbe(event) {
  event.preventDefault();
  const input = byId("domainInput").value.trim();
  if (!input) return;
  const protocol = byId("protocolInput").value;
  const out = byId("domainResult");
  out.textContent = "Testing";
  try {
    let result;
    if (state.session && state.session.authMode === "bearer") {
      result = await apiFetch("/api/v1/routes/trace", {
        method: "POST",
        body: JSON.stringify({ input, protocol }),
      });
      state.data.traces = [result, ...normalizeRows(state.data.traces)];
    } else {
      result = await apiFetch(`/api/v1/rules/test-domain?input=${encodeURIComponent(input)}`);
    }
    const outbound = valueOf(result, "Outbound", "outbound");
    const reason = valueOf(result, "Decision", "decision", "Reason", "reason", "MatchedSource", "matchedSource");
    out.textContent = `${text(outbound)} · ${text(reason)}`;
    renderRoutes();
  } catch (err) {
    out.textContent = err.message;
  }
}

function renderSubscriptions() {
  const subs = normalizeRows(state.data.subscriptions);
  const conversions = normalizeRows(state.data.conversions);
  byId("subscriptionMetrics").replaceChildren(
    metricCard("Active subscriptions", compactNumber(subs.filter(row => !valueOf(row, "Revoked", "revoked")).length), [subs.length]),
    metricCard("Conversions", compactNumber(conversions.length), [conversions.length]),
    metricCard("Subscription p99", ms(valueOf(state.data.overview || {}, "Subscription99pMs", "subscription99pMs")), [number(valueOf(state.data.overview || {}, "Subscription99pMs", "subscription99pMs"))])
  );
  renderRows("subscriptionBody", subs, 8, row => tr([
    valueOf(row, "UserID", "userId"),
    valueOf(row, "DeviceID", "deviceId"),
    valueOf(row, "Region", "region"),
    valueOf(row, "Protocol", "protocol"),
    valueOf(row, "OutboundPolicy", "outboundPolicy"),
    valueOf(row, "ClientType", "clientType"),
    valueOf(row, "TokenKind", "tokenKind"),
    valueOf(row, "Revoked", "revoked") ? "revoked" : "active",
  ]));
  renderRows("conversionBody", conversions, 6, row => tr([
    valueOf(row, "name", "Name"),
    valueOf(row, "sourceClientType", "SourceClientType"),
    valueOf(row, "targetClientType", "TargetClientType"),
    valueOf(row, "region", "Region"),
    valueOf(row, "protocol", "Protocol"),
    valueOf(row, "status", "Status"),
  ]));
}

function renderWarp() {
  const profiles = normalizeRows(state.data.warp);
  renderRows("warpBody", profiles, 10, row => {
    const probe = valueOf(row, "LastProbe", "lastProbe") || {};
    return tr([
      valueOf(row, "Name", "name", "ID", "id"),
      badge(valueOf(row, "Status", "status"), warpTone(valueOf(row, "Status", "status"))),
      valueOf(row, "NodeID", "nodeId"),
      valueOf(probe, "ExitIP", "exitIP"),
      valueOf(probe, "ASN", "asn"),
      valueOf(probe, "DNSStatus", "dnsStatus"),
      valueOf(probe, "WireGuardStatus", "wireGuardStatus"),
      ms(valueOf(probe, "LatencyMs", "latencyMs")),
      percent(valueOf(probe, "Loss", "loss")),
      valueOf(probe, "HTTPSuccess", "httpSuccess") ? "ok" : "failed",
    ]);
  });
  drawBars(byId("warpScheduleChart"), statusCounts(profiles));
  const guard = state.data.scholarGuard || {};
  const outbound = valueOf(guard, "Outbound", "outbound");
  const ok = outbound && String(outbound).toLowerCase() !== "warp-pool" && !String(outbound).toLowerCase().includes("warp");
  setStatus(byId("scholarGuard"), guard.error ? guard.error : outbound ? `${outbound} via ${text(valueOf(guard, "MatchedSource", "matchedSource"))}` : "Not checked", guard.error ? "bad" : ok ? "ok" : "warn");
}

function statusCounts(rows) {
  const counts = {};
  rows.forEach(row => {
    const status = text(valueOf(row, "Status", "status"), "unknown");
    counts[status] = (counts[status] || 0) + 1;
  });
  return counts;
}

function renderProtocols() {
  const stats = normalizeRows(state.data.protocols);
  const total = stats.reduce((sum, row) => sum + number(valueOf(row, "Connections", "connections")), 0);
  const grid = byId("protocolGrid");
  grid.replaceChildren(...stats.map((row, index) => {
    const connections = number(valueOf(row, "Connections", "connections"));
    return metricCard(
      text(valueOf(row, "Protocol", "protocol")),
      total ? `${Math.round((connections / total) * 100)}%` : compactNumber(connections),
      [connections, number(valueOf(row, "RxBps", "rxBps")), number(valueOf(row, "TxBps", "txBps")) + index]
    );
  }));
  if (!stats.length) grid.appendChild(metricCard("Protocols", emptyText, [0]));
}

function renderTraffic() {
  const samples = normalizeRows(state.data.nodeSamples);
  drawLine(byId("trafficWideChart"), samples.map(sample => number(valueOf(sample, "RxBps", "rxBps")) + number(valueOf(sample, "TxBps", "txBps"))));
}

function renderObservability() {
  byId("logOutput").textContent = normalizeRows(state.data.logs).join("\n") || emptyText;
  renderRows("auditBody", state.data.audit, 4, row => tr([
    valueOf(row, "Action", "action"),
    `${text(valueOf(row, "ResourceType", "resourceType"))}:${text(valueOf(row, "ResourceID", "resourceId"))}`,
    valueOf(row, "ActorID", "actorId"),
    timeAgo(valueOf(row, "CreatedAt", "createdAt")),
  ]));
}

function renderSecurity() {
  renderRows("waiverBody", state.data.waivers, 5, row => tr([
    valueOf(row, "Gate", "gate"),
    valueOf(row, "Severity", "severity"),
    valueOf(row, "Owner", "owner"),
    timeAgo(valueOf(row, "ExpiresAt", "expiresAt")),
    valueOf(row, "RemediationPlan", "remediationPlan"),
  ]));
  const availability = state.data.dependencies || {};
  const body = byId("availabilityBody");
  body.replaceChildren(
    keyValue("Status", valueOf(availability, "Status", "status")),
    keyValue("Core APIs", valueOf(availability, "CoreAPIsAvailable", "coreAPIsAvailable") ? "available" : "unavailable"),
    keyValue("Write APIs", valueOf(availability, "WriteAPIsAvailable", "writeAPIsAvailable") ? "available" : "unavailable"),
    keyValue("Rate limit mode", valueOf(availability, "RateLimitMode", "rateLimitMode")),
    keyValue("Messages", normalizeRows(valueOf(availability, "Messages", "messages")).join("; "))
  );
}

function renderDeployments() {
  renderRows("deploymentBody", state.data.nodes, 4, row => tr([
    valueOf(row, "Name", "name", "ID", "id"),
    valueOf(row, "LastConfigVersion", "lastConfigVersion"),
    valueOf(row, "Status", "status"),
    timeAgo(valueOf(row, "LastSeenAt", "lastSeenAt")),
  ]));
  renderRows("argoBody", state.data.argo, 4, row => tr([
    valueOf(row, "name", "Name"),
    valueOf(row, "hostname", "Hostname"),
    valueOf(row, "serviceUrl", "ServiceURL"),
    valueOf(row, "status", "Status"),
  ]));
}

function renderIncidents() {
  renderRows("incidentBody", state.data.incidents, 4, row => tr([
    valueOf(row, "Severity", "severity"),
    valueOf(row, "Status", "status"),
    valueOf(row, "Title", "title"),
    timeAgo(valueOf(row, "StartedAt", "startedAt")),
  ]));
  renderRows("runbookBody", state.data.runbooks, 4, row => tr([
    valueOf(row, "severity", "Severity"),
    valueOf(row, "responseTarget", "ResponseTarget"),
    normalizeRows(valueOf(row, "runbookNames", "RunbookNames")).join(", "),
    valueOf(row, "primaryMitigate", "PrimaryMitigate"),
  ]));
}

function renderSettings() {
  const session = state.session || {};
  const failures = state.failures.length ? state.failures.join("; ") : "none";
  renderRows("settingsBody", [
    ["API base", apiBase() || location.origin],
    ["Auth mode", session.authMode],
    ["Tenant", session.tenantId || "token scoped"],
    ["Loaded endpoints", Object.keys(state.data).length],
    ["Endpoint failures", failures],
  ], 2, row => tr(row));
}

function healthTone(status) {
  const value = String(status || "").toLowerCase();
  if (value.includes("healthy") || value === "ok" || value === "available") return "ok";
  if (value.includes("degraded") || value.includes("cooldown")) return "warn";
  if (value.includes("offline") || value.includes("critical") || value.includes("unavailable") || value.includes("failed")) return "bad";
  return "";
}

function nodeTone(status) {
  const value = String(status || "").toLowerCase();
  if (value === "online") return "ok";
  if (value === "degraded") return "warn";
  if (value === "offline") return "bad";
  return "";
}

function warpTone(status) {
  const value = String(status || "").toLowerCase();
  if (value === "healthy" || value === "ok") return "ok";
  if (value === "cooldown") return "warn";
  if (value === "disabled" || value === "failed") return "bad";
  return "";
}

function drawLine(canvas, values) {
  if (!canvas) return;
  const series = normalizeSeries(values);
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = Math.max(1, Math.floor(rect.width * dpr));
  canvas.height = Math.max(1, Math.floor(rect.height * dpr));
  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, rect.width, rect.height);
  ctx.strokeStyle = "rgba(255,255,255,0.08)";
  ctx.lineWidth = 1;
  for (let i = 1; i < 4; i += 1) {
    const y = (rect.height / 4) * i;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(rect.width, y);
    ctx.stroke();
  }
  if (!series.length) return;
  const max = Math.max(...series, 1);
  const min = Math.min(...series, 0);
  const span = Math.max(max - min, 1);
  ctx.strokeStyle = palette[2];
  ctx.lineWidth = 2;
  ctx.beginPath();
  series.forEach((value, index) => {
    const x = series.length === 1 ? rect.width : (rect.width / (series.length - 1)) * index;
    const y = rect.height - 8 - ((value - min) / span) * (rect.height - 16);
    if (index === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();
}

function drawBars(canvas, counts) {
  if (!canvas) return;
  const entries = Object.entries(counts || {});
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = Math.max(1, Math.floor(rect.width * dpr));
  canvas.height = Math.max(1, Math.floor(rect.height * dpr));
  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, rect.width, rect.height);
  if (!entries.length) return;
  const max = Math.max(...entries.map(([, value]) => value), 1);
  const gap = 8;
  const barWidth = Math.max(10, (rect.width - gap * (entries.length - 1)) / entries.length);
  entries.forEach(([label, value], index) => {
    const h = (value / max) * (rect.height - 26);
    const x = index * (barWidth + gap);
    ctx.fillStyle = palette[index % palette.length];
    ctx.fillRect(x, rect.height - h - 18, barWidth, h);
    ctx.fillStyle = "#b7c0c4";
    ctx.font = "11px system-ui";
    ctx.fillText(label.slice(0, 10), x, rect.height - 4);
  });
}

function normalizeSeries(values) {
  return normalizeRows(values).map(number).filter(Number.isFinite);
}

function renderAll() {
  const hasSession = Boolean(state.session);
  document.body.classList.toggle("needs-session", !hasSession);
  fillSessionForm();
  setStatus(byId("sessionStatus"), hasSession ? "Credentials loaded" : "Credentials required", hasSession ? "ok" : "warn");
  renderMetrics();
  renderOverviewPanels();
  renderNodes();
  renderRoutes();
  renderSubscriptions();
  renderWarp();
  renderProtocols();
  renderTraffic();
  renderObservability();
  renderSecurity();
  renderDeployments();
  renderIncidents();
  renderSettings();
}

function fillSessionForm() {
  const session = state.session || {};
  byId("apiBaseInput").value = session.apiBase || "";
  byId("authModeInput").value = session.authMode || "bearer";
  byId("apiTokenInput").value = session.apiToken || "";
  byId("userIdInput").value = session.userId || "";
  byId("tenantIdInput").value = session.tenantId || "";
  byId("roleInput").value = session.role || "admin";
  byId("csrfInput").value = session.csrfToken || "";
  byId("confirmInput").value = session.confirmationToken || "";
  document.body.dataset.authMode = byId("authModeInput").value;
}

function handleSessionSubmit(event) {
  event.preventDefault();
  const authMode = byId("authModeInput").value;
  const session = {
    apiBase: byId("apiBaseInput").value.trim(),
    authMode,
    apiToken: authMode === "bearer" ? byId("apiTokenInput").value.trim() : "",
    userId: authMode === "gateway" ? byId("userIdInput").value.trim() : "",
    tenantId: authMode === "gateway" ? byId("tenantIdInput").value.trim() : "",
    role: authMode === "gateway" ? byId("roleInput").value.trim() : "",
    csrfToken: authMode === "gateway" ? byId("csrfInput").value.trim() : "",
    confirmationToken: authMode === "gateway" ? byId("confirmInput").value.trim() : "",
  };
  saveSession(session);
  refreshData();
}

function init() {
  loadSession();
  byId("sessionForm").addEventListener("submit", handleSessionSubmit);
  byId("authModeInput").addEventListener("change", () => {
    document.body.dataset.authMode = byId("authModeInput").value;
  });
  byId("refreshButton").addEventListener("click", refreshData);
  byId("disconnectButton").addEventListener("click", clearSession);
  byId("searchInput").addEventListener("input", event => {
    state.search = event.target.value.trim().toLowerCase();
    renderAll();
  });
  byId("routeProbeForm").addEventListener("submit", handleRouteProbe);
  renderAll();
  refreshData();
}

window.addEventListener("load", init);
window.addEventListener("resize", renderAll);
