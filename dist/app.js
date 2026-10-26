"use strict";

const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
const {
  escapeHtml: esc,
  normalizeTargets,
  flattenHosts,
  filterSortRows,
  compareReports,
  rowsToCSV,
  rowsToHTML,
  formatDuration,
  riskLabel,
} = StudioCore;

let current = "nmap";
let token = "";
let job = null;
let poll = null;
let jobsCache = [];
let installedScripts = [];
let tab = "Discovery";
let starting = false;
let refreshing = false;
let currentReport = {name: "Current scan", hosts: []};
let comparisonReport = {name: "Comparison scan", hosts: []};
let resultFilters = {query: "", service: "", state: "", sort: "address"};

const demoMode = new URLSearchParams(location.search).get("demo") === "1";
if (demoMode) {
  currentReport = {
    name: "Office baseline · 26 Oct 2026",
    hosts: [
      {address: "192.168.10.1", hostname: "gateway.local", state: "up", ports: [
        {port: "53", protocol: "tcp", state: "open", service: "domain", product: "dnsmasq", version: "2.90"},
        {port: "80", protocol: "tcp", state: "open", service: "http", product: "nginx", version: "1.26"},
        {port: "443", protocol: "tcp", state: "open", service: "https", product: "nginx", version: "1.26"},
      ]},
      {address: "192.168.10.24", hostname: "devbox.local", state: "up", ports: [
        {port: "22", protocol: "tcp", state: "open", service: "ssh", product: "OpenSSH", version: "9.8"},
        {port: "3000", protocol: "tcp", state: "open", service: "http", product: "Node.js", version: "22"},
      ]},
      {address: "192.168.10.40", hostname: "printer.local", state: "up", ports: [
        {port: "631", protocol: "tcp", state: "open", service: "ipp", product: "CUPS", version: "2.4"},
      ]},
    ],
  };
  comparisonReport = {
    name: "Office follow-up · 26 Oct 2026",
    hosts: [
      ...currentReport.hosts.slice(0, 2),
      {address: "192.168.10.40", hostname: "printer.local", state: "up", ports: [
        {port: "631", protocol: "tcp", state: "open", service: "ipp", product: "CUPS", version: "2.4"},
        {port: "9100", protocol: "tcp", state: "open", service: "jetdirect", product: "HP JetDirect", version: ""},
      ]},
    ],
  };
  jobsCache = [
    {id: "demo-3", name: "Office follow-up", project: "Office lab", tool: "nmap", state: "running", stage: "Service detection", elapsed: 42, progress: 70, done: false},
    {id: "demo-2", name: "Office baseline", project: "Office lab", tool: "nmap", state: "completed", stage: "Completed", elapsed: 31, progress: 100, done: true, reportSummary: {hosts: 3, openPorts: 6}},
    {id: "demo-1", name: "Local service check", project: "Development", tool: "nmap", state: "completed", stage: "Completed", elapsed: 8, progress: 100, done: true, reportSummary: {hosts: 1, openPorts: 2}},
  ];
}

const settings = readObject("studio-settings", {persistHistory: false, safeMode: true});
let history = settings.persistHistory ? readArray("studio-history") : [];
const state = {
  nmap: {
    name: "Network scan", project: "Default", target: "127.0.0.1",
    scan: "-sT", ports: "", timing: "3", version: true, os: false,
    defaultScripts: false, traceroute: false, discovery: "", dns: "",
    scripts: "", scriptArgs: "", scriptArgKey: "", scriptArgValue: "",
    exclude: "", extra: "[]",
  },
  ncat: {name: "Ncat session", project: "Default", target: "127.0.0.1", port: "8080", mode: "", udp: false, ssl: false, extra: "[]"},
  nping: {name: "Probe", project: "Default", target: "127.0.0.1", mode: "--tcp-connect", port: "80", count: "4", extra: "[]"},
  ndiff: {name: "Report comparison", project: "Default", first: "", second: "", xml: false, extra: "[]"},
};

const names = {
  nmap: "Scan builder", scans: "Scan manager", scripts: "Script library",
  results: "Results dashboard", ncat: "Ncat", nping: "Nping",
  ndiff: "Ndiff", reference: "Tool reference", settings: "Settings",
};
const icons = {
  nmap: "⌘", scans: "◷", scripts: "▧", results: "▦", ncat: "⇄",
  nping: "⌁", ndiff: "⊞", reference: "▤", settings: "⚙",
};

function readArray(key) {
  try {
    const value = JSON.parse(localStorage.getItem(key) || "[]");
    return Array.isArray(value) ? value : [];
  } catch { return []; }
}
function readObject(key, fallback) {
  try {
    const value = JSON.parse(localStorage.getItem(key) || "null");
    return value && typeof value === "object" && !Array.isArray(value) ? {...fallback, ...value} : fallback;
  } catch { return fallback; }
}
function toast(message) {
  $("#toast").textContent = message;
  $("#toast").style.display = "block";
  setTimeout(() => { $("#toast").style.display = "none"; }, 3200);
}
function download(name, text, type = "text/plain") {
  const anchor = document.createElement("a");
  anchor.href = URL.createObjectURL(new Blob([text], {type}));
  anchor.download = name;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(anchor.href), 1000);
}
const field = (id, label, value = "", placeholder = "") =>
  `<label for="${id}">${label}</label><input id="${id}" data-key="${id}" value="${esc(value)}" placeholder="${esc(placeholder)}">`;
const select = (id, label, options, value) =>
  `<label for="${id}">${label}</label><select id="${id}" data-key="${id}">${options.map(([option, text]) =>
    `<option value="${esc(option)}" ${option === value ? "selected" : ""}>${esc(text)}</option>`).join("")}</select>`;
const check = (key, label, values) =>
  `<label><input data-key="${key}" type="checkbox" ${values[key] ? "checked" : ""}>${esc(label)}</label>`;

function commandArgs() {
  const values = state[current];
  const args = [];
  if (!values) return args;
  if (current === "nmap") {
    args.push(values.scan, "-T" + values.timing);
    if (values.ports) args.push("-p", values.ports);
    for (const [key, flag] of Object.entries({version: "-sV", os: "-O", defaultScripts: "-sC", traceroute: "--traceroute"})) {
      if (values[key]) args.push(flag);
    }
    if (values.discovery) args.push(values.discovery);
    if (values.dns) args.push(values.dns);
    if (values.scripts) args.push("--script", values.scripts);
    if (values.scriptArgs) args.push("--script-args", values.scriptArgs);
    if (values.exclude) args.push("--exclude", values.exclude);
  } else if (current === "ncat") {
    if (values.mode) args.push(values.mode);
    if (values.udp) args.push("-u");
    if (values.ssl) args.push("--ssl");
  } else if (current === "nping") {
    args.push(values.mode, "-c", values.count);
    if (values.port && ["--tcp", "--tcp-connect", "--udp"].includes(values.mode)) args.push("-p", values.port);
  } else if (current === "ndiff" && values.xml) {
    args.push("--xml");
  }
  const extra = JSON.parse(values.extra || "[]");
  if (!Array.isArray(extra) || !extra.every(value => typeof value === "string")) {
    throw new Error("Advanced arguments must be a JSON array of strings");
  }
  args.push(...extra);
  if (current === "ndiff") {
    args.push(values.first, values.second);
  } else {
    const targets = normalizeTargets(values.target);
    if (targets.some(target => target.startsWith("-"))) throw new Error("Enter targets without option flags");
    args.push(...targets);
    if (current === "ncat") args.push(values.port);
  }
  return args.filter(Boolean);
}
function commandPreview() {
  return current + " " + commandArgs().map(value => /^[\w.,:/=-]+$/.test(value) ? value : JSON.stringify(value)).join(" ");
}
function updatePreview() {
  try {
    $("#command").textContent = commandPreview();
    $("#argError").textContent = "";
    $("#run").disabled = false;
  } catch (error) {
    $("#argError").textContent = error.message;
    $("#run").disabled = true;
  }
}

function advancedPanel(values) {
  return `<details ${settings.safeMode ? "" : "open"}><summary>Advanced command-line options</summary>
    <div class="mode-box"><label><input id="safeMode" type="checkbox" ${settings.safeMode ? "checked" : ""}> Safe mode</label>
    <p class="hint">Risky NSE categories and uncommon command options require Advanced mode.</p></div>
    <label for="extra">Additional argument array</label>
    <textarea id="extra" data-key="extra" spellcheck="false">${esc(values.extra)}</textarea>
    <p class="hint">Arguments are passed directly without a command shell.</p></details>`;
}

function outputCard() {
  const stateText = job ? job.state.toUpperCase() : "READY";
  const progress = job ? Math.max(0, Math.min(100, job.progress || 0)) : 0;
  const queue = job?.state === "queued" ? ` · queue #${job.queuePosition || "?"}` : "";
  return `<div class="card">
    <div class="card-head"><div><h2>Live output <span class="pill" id="jobStatus">${esc(stateText)}</span></h2>
    <p class="hint" id="jobMeta">${job ? esc(job.stage + " · " + formatDuration(job.elapsed) + queue) : "Ready to run locally"}</p></div>
    <div class="actions"><button class="primary" id="executeHere">▶ Execute</button><button id="stop">■ Stop</button><button id="export">↓ Output</button></div></div>
    <div class="progress-track"><div class="progress-fill width-${Math.round(progress / 10) * 10}" id="progressFill"></div></div>
    <pre class="terminal output" id="output">${esc(job?.output || "Configure a command and click Execute.\nLive output will appear here.")}</pre>
    <div class="pad"><div class="actions"><input class="grow" id="stdin" aria-label="Process input" placeholder="Send input to the process"><button id="send">Send ↵</button><button id="eof">Close input</button></div>
    <p class="hint">Raw packet scans and OS detection may need administrator/root privileges.</p></div></div>`;
}

function scriptBuilder(values) {
  const selected = values.scripts.split(",").filter(Boolean);
  const argumentsList = values.scriptArgs.split(",").filter(Boolean);
  return `<div class="selected-scripts"><div class="summary-line"><span>Selected scripts</span><b>${selected.length}</b></div>
    <div class="chip-list">${selected.length ? selected.map(name => `<button class="chip" data-remove-script="${esc(name)}">${esc(name)} ×</button>`).join("") : '<span class="hint">Add scripts from the Script library.</span>'}</div>
    <div class="row">${field("scriptArgKey", "Argument key", values.scriptArgKey, "e.g. http.useragent")}${field("scriptArgValue", "Argument value", values.scriptArgValue, "e.g. Nmap Studio")}</div>
    <button id="addScriptArg">＋ Add script argument</button>
    <div class="chip-list args-list">${argumentsList.map(value => `<button class="chip" data-remove-arg="${esc(value)}">${esc(value)} ×</button>`).join("")}</div>
    <p class="hint">Simple key/value arguments work in Safe mode. Complex tables, files, and expressions require Advanced mode.</p></div>`;
}

function nmapOptions() {
  const values = state.nmap;
  $("#options").innerHTML = tab === "Discovery"
    ? `<div class="row">${select("discovery", "Host discovery", [["", "Automatic"], ["-Pn", "Skip discovery"], ["-PE", "ICMP echo"], ["-PS", "TCP SYN ping"], ["-PA", "TCP ACK ping"], ["-PU", "UDP ping"]], values.discovery)}
       ${select("dns", "DNS resolution", [["", "Automatic"], ["-n", "Never resolve"], ["-R", "Always resolve"]], values.dns)}</div>
       ${field("exclude", "Exclude hosts or networks", values.exclude, "e.g. 192.168.1.1")}`
    : tab === "Timing"
      ? `${select("timing", "Timing template", [["0", "T0 · Paranoid"], ["1", "T1 · Sneaky"], ["2", "T2 · Polite"], ["3", "T3 · Normal"], ["4", "T4 · Aggressive"], ["5", "T5 · Insane"]], values.timing)}
         <p class="hint">Aggressive timing can reduce accuracy on slow or lossy networks.</p>`
      : scriptBuilder(values);
}

function builder() {
  const values = state[current];
  let body = "";
  if (current === "nmap") {
    body = `<div class="presets">${[["Quick scan", "Top 100 TCP ports"], ["Discovery", "Find active hosts"], ["Deep inspection", "Services, OS and default scripts"]].map(([name, description]) =>
      `<button class="preset" data-preset="${name}">${name}<span>${description}</span></button>`).join("")}</div>
      ${field("target", "Targets", values.target, "Website URL, hostname, IP, or CIDR")}
      <p class="hint">URLs become hostnames. Separate targets with spaces and scan only authorized systems.</p>
      <div class="row">${select("scan", "Scan technique", [["-sT", "TCP connect"], ["-sS", "TCP SYN"], ["-sU", "UDP"], ["-sn", "Host discovery only"], ["-sL", "List targets"], ["-sA", "TCP ACK"], ["-sW", "TCP Window"], ["-sM", "Maimon"], ["-sN", "TCP NULL"], ["-sF", "TCP FIN"], ["-sX", "TCP Xmas"], ["-sY", "SCTP INIT"], ["-sZ", "SCTP COOKIE ECHO"], ["-sO", "IP protocol"]], values.scan)}
      ${field("ports", "Ports", values.ports, "Default ports · e.g. 22,80,443")}</div>
      <div class="checks">${check("version", "Service detection", values)}${check("os", "OS detection", values)}${check("defaultScripts", "Default NSE scripts", values)}${check("traceroute", "Traceroute", values)}</div>`;
  } else if (current === "ncat") {
    body = `<p>Connect to and exchange data with network services.</p><div class="row">${field("target", "Host", values.target)}${field("port", "Port", values.port)}</div>
      ${select("mode", "Connection mode", [["", "Connect"], ["--listen", "Listen (Advanced)"], ["--broker", "Broker (Advanced)"]], values.mode)}
      <div class="checks">${check("udp", "UDP transport", values)}${check("ssl", "TLS / SSL", values)}</div>`;
  } else if (current === "nping") {
    body = `<p>Generate probes and measure responses.</p>${field("target", "Targets", values.target)}
      ${select("mode", "Probe protocol", [["--tcp-connect", "TCP connect"], ["--tcp", "TCP raw"], ["--udp", "UDP"], ["--icmp", "ICMP"], ["--arp", "ARP"]], values.mode)}
      <div class="row">${field("port", "Destination ports", values.port)}${field("count", "Probe rounds", values.count)}</div>`;
  } else {
    body = `<p>Compare two Nmap XML reports on the local runner.</p>${field("first", "Baseline XML path", values.first, "C:/scans/before.xml")}
      ${field("second", "Current XML path", values.second, "C:/scans/after.xml")}<div class="checks">${check("xml", "Produce XML diff", values)}</div>`;
  }
  $("#page").innerHTML = `<div class="grid"><div><div class="card"><div class="card-head"><h2><span class="step">01</span>Configure ${esc(current)}</h2><span class="hint">${current.toUpperCase()}</span></div>
    <div class="pad"><div class="row">${field("name", "Scan name", values.name)}${field("project", "Project", values.project)}</div>${body}</div>
    ${current === "nmap" ? `<div class="tabs">${["Discovery", "Timing", "Scripts"].map(name => `<button data-tab="${name}" class="${tab === name ? "active" : ""}">${name}</button>`).join("")}</div><div class="pad" id="options"></div>` : ""}
    <div class="pad topless">${advancedPanel(values)}</div></div>${outputCard()}</div>
    <div><div class="card"><div class="card-head"><h2><span class="step">02</span>Command preview</h2><span class="pill">${settings.safeMode ? "SAFE" : "ADVANCED"}</span></div>
    <pre class="terminal" id="command"></pre><div class="pad"><div class="summary-line"><span>Execution</span><b>${token ? "Local runner" : "Builder only"}</b></div>
    <div class="summary-line"><span>Queue</span><b>2 running · 32 waiting</b></div><div id="argError" class="danger"></div>
    <button class="primary run" id="run">▷ Run command</button><div class="actions"><button id="copy">Copy command</button><button id="copyArgs">Copy argv</button></div></div></div>
    <div class="card tip pad"><h3>Named scans and projects</h3><p>Every run appears in Scan manager with its state, stage, elapsed time, output, and structured report.</p></div>
    <div class="card pad"><h3>Saved profiles</h3><div id="profiles"></div></div></div></div>`;
  if (current === "nmap") nmapOptions();
  bindBuilder();
}

function bindBuilder() {
  $$("[data-key]").forEach(element => {
    element.oninput = () => {
      state[current][element.dataset.key] = element.type === "checkbox" ? element.checked : element.value;
      updatePreview();
    };
  });
  updatePreview();
  renderProfiles();
  $("#run").onclick = start;
  $("#executeHere").onclick = start;
  $("#safeMode").onchange = event => {
    settings.safeMode = event.target.checked;
    localStorage.setItem("studio-settings", JSON.stringify(settings));
    builder();
  };
  $("#copy").onclick = () => navigator.clipboard.writeText(commandPreview()).then(() => toast("Command copied"));
  $("#copyArgs").onclick = () => navigator.clipboard.writeText(JSON.stringify(commandArgs())).then(() => toast("Argument array copied"));
  $("#stop").onclick = () => job ? api("/api/stop", {id: job.id}).catch(showError) : toast("No active job");
  $("#export").onclick = () => download("nmap-studio-output.txt", $("#output").textContent);
  $("#send").onclick = () => sendInput(false);
  $("#eof").onclick = () => sendInput(true);
  $$("[data-preset]").forEach(button => button.onclick = () => {
    const preset = button.dataset.preset;
    Object.assign(state.nmap, {
      scan: preset === "Discovery" ? "-sn" : "-sT",
      version: preset !== "Discovery",
      os: preset === "Deep inspection",
      defaultScripts: preset === "Deep inspection",
      extra: preset === "Quick scan" ? '["--top-ports","100"]' : "[]",
    });
    builder();
  });
  $$("[data-tab]").forEach(button => button.onclick = () => { tab = button.dataset.tab; builder(); });
  $$("[data-remove-script]").forEach(button => button.onclick = () => {
    state.nmap.scripts = state.nmap.scripts.split(",").filter(name => name && name !== button.dataset.removeScript).join(",");
    builder();
  });
  $$("[data-remove-arg]").forEach(button => button.onclick = () => {
    state.nmap.scriptArgs = state.nmap.scriptArgs.split(",").filter(value => value && value !== button.dataset.removeArg).join(",");
    builder();
  });
  if ($("#addScriptArg")) $("#addScriptArg").onclick = addScriptArgument;
}

function addScriptArgument() {
  const key = state.nmap.scriptArgKey.trim();
  const value = state.nmap.scriptArgValue.trim();
  if (!/^[A-Za-z0-9_.-]+$/.test(key) || !value || /[{},'"\\]/.test(value)) {
    return toast("Use a simple key and value. Complex arguments require Advanced mode.");
  }
  const item = key + "=" + value;
  state.nmap.scriptArgs = [...new Set([...state.nmap.scriptArgs.split(",").filter(Boolean), item])].join(",");
  state.nmap.scriptArgKey = "";
  state.nmap.scriptArgValue = "";
  builder();
}

function executionMessage(snapshot, output) {
  if ($("#jobStatus")) $("#jobStatus").textContent = (snapshot?.state || "ready").toUpperCase();
  if ($("#jobMeta")) {
    const queue = snapshot?.state === "queued" ? ` · queue #${snapshot.queuePosition || "?"}` : "";
    $("#jobMeta").textContent = snapshot ? snapshot.stage + " · " + formatDuration(snapshot.elapsed) + queue : "Ready";
  }
  if ($("#progressFill")) $("#progressFill").className = "progress-fill width-" + Math.round(Math.max(0, Math.min(100, snapshot?.progress || 0)) / 10) * 10;
  if ($("#output")) $("#output").textContent = output;
  if ($("#run")) $("#run").disabled = starting || Boolean(snapshot && !snapshot.done);
  if ($("#executeHere")) $("#executeHere").disabled = starting || Boolean(snapshot && !snapshot.done);
}

async function api(path, data) {
  let response;
  try {
    response = await fetch(path, {
      method: data ? "POST" : "GET", cache: "no-store", signal: AbortSignal.timeout(10000),
      headers: {"Content-Type": "application/json", "X-Nmap-Studio-Token": token},
      body: data ? JSON.stringify(data) : undefined,
    });
  } catch (error) {
    throw new Error("Cannot reach the local runner. Start the app and try again. " + error.message);
  }
  let value;
  try { value = await response.json(); } catch { throw new Error("The runner returned an invalid response."); }
  if (!response.ok) {
    const error = new Error(value.error || "Request failed");
    error.status = response.status;
    throw error;
  }
  return value;
}
async function apiText(path) {
  const response = await fetch(path, {cache: "no-store", signal: AbortSignal.timeout(10000), headers: {"X-Nmap-Studio-Token": token}});
  if (!response.ok) throw new Error("Request failed: " + response.status);
  return response.text();
}
function showError(error) { toast(error.message || String(error)); }

async function start() {
  if (starting) return;
  if (job && !job.done) return toast("This view already has an active command. Open Scan manager to inspect the queue.");
  starting = true;
  executionMessage({state: "starting", stage: "Connecting", elapsed: 0, progress: 1}, "Connecting to the local runner…");
  try {
    const tool = current;
    const args = commandArgs();
    if (state[tool]?.target) {
      const normalized = normalizeTargets(state[tool].target).join(" ");
      state[tool].target = normalized;
      if ($("#target")) $("#target").value = normalized;
    }
    if (!await connectRunner()) throw new Error("Runner is offline. Double-click start.cmd and try again.");
    if (!settings.safeMode && !confirm("Advanced mode can run all options supported by the installed tool with your account permissions. Continue?")) {
      return executionMessage(null, "Advanced execution cancelled.");
    }
    const created = await api("/api/run", {
      tool, args, name: state[tool].name, project: state[tool].project,
      safeMode: settings.safeMode, confirmAdvanced: !settings.safeMode,
    });
    job = {id: created.id, state: created.state, output: "", done: false, progress: 0, stage: "Queued", elapsed: 0};
    executionMessage(job, created.state === "queued" ? "Added to the local scan queue…" : "Starting process…");
    clearInterval(poll);
    poll = setInterval(refreshJob, 700);
    await refreshJob();
  } catch (error) {
    executionMessage({state: "failed", stage: "Request failed", progress: 100, elapsed: 0}, error.message);
    showError(error);
  } finally {
    starting = false;
  }
}

async function refreshJob() {
  if (refreshing || !job) return;
  refreshing = true;
  try {
    job = await api("/api/jobs/" + job.id);
    executionMessage(job, job.output || (job.state === "queued" ? "Waiting for an execution slot…" : "Process is running…"));
    if ($("#output")) $("#output").scrollTop = $("#output").scrollHeight;
    if (job.done) {
      clearInterval(poll);
      if (job.report?.hosts) {
        currentReport = {name: job.name, hosts: job.report.hosts};
        toast("Structured results are ready.");
      }
      if (settings.persistHistory) {
        history.unshift({...job, time: new Date().toISOString()});
        history = history.slice(0, 20);
        localStorage.setItem("studio-history", JSON.stringify(history));
      }
      await syncJobs();
    }
  } catch (error) {
    if (error.status === 404) { clearInterval(poll); job = null; }
    showError(error);
  } finally { refreshing = false; }
}

async function sendInput(eof) {
  try {
    if (!job || job.state !== "running") throw new Error("Start a running command first");
    await api("/api/input", {id: job.id, data: eof ? "" : $("#stdin").value + "\n", eof});
    $("#stdin").value = "";
  } catch (error) { showError(error); }
}

async function syncJobs() {
  if (!token) return;
  try {
    jobsCache = (await api("/api/jobs")).jobs || [];
    if (current === "scans") renderScans();
  } catch {}
}

function renderScans() {
  const projects = [...new Set(jobsCache.map(item => item.project))].sort();
  const active = jobsCache.filter(item => !item.done).length;
  $("#page").innerHTML = `<div class="stat-grid"><div class="stat"><span>Active and queued</span><b>${active}</b></div>
    <div class="stat"><span>Completed</span><b>${jobsCache.filter(item => item.state === "completed").length}</b></div>
    <div class="stat"><span>Projects</span><b>${projects.length}</b></div></div>
    <div class="card pad"><div class="card-head"><div><h2>Scan queue and history</h2><p class="hint">Jobs remain in memory for 24 hours, up to 20 completed runs.</p></div>
    <div class="actions"><select id="projectFilter" aria-label="Filter project"><option value="">All projects</option>${projects.map(name => `<option>${esc(name)}</option>`).join("")}</select><button id="refreshScans">Refresh</button></div></div>
    <div id="scanList"></div></div>`;
  const draw = () => {
    const filter = $("#projectFilter").value;
    const visible = jobsCache.filter(item => !filter || item.project === filter);
    $("#scanList").innerHTML = visible.length ? visible.map(item => `<article class="scan-row">
      <div class="scan-main"><div><strong>${esc(item.name)}</strong><span class="status status-${esc(item.state)}">${esc(item.state)}</span></div>
      <p>${esc(item.project)} · ${esc(item.tool)} · ${esc(item.stage)} · ${formatDuration(item.elapsed)}${item.queuePosition ? " · queue #" + item.queuePosition : ""}</p>
      <div class="progress-track compact"><div class="progress-fill width-${Math.round((item.progress || 0) / 10) * 10}"></div></div></div>
      <div class="actions"><button data-view-job="${item.id}">View</button>${item.reportSummary ? `<button data-report-job="${item.id}">Results</button>` : ""}
      ${!item.done ? `<button data-stop-job="${item.id}">Stop</button>` : ""}</div></article>`).join("") : '<div class="empty">No scans in this project.</div>';
    $$("[data-view-job]").forEach(button => button.onclick = () => openJob(button.dataset.viewJob, false));
    $$("[data-report-job]").forEach(button => button.onclick = () => openJob(button.dataset.reportJob, true));
    $$("[data-stop-job]").forEach(button => button.onclick = async () => { await api("/api/stop", {id: button.dataset.stopJob}); await syncJobs(); });
  };
  $("#projectFilter").onchange = draw;
  $("#refreshScans").onclick = syncJobs;
  draw();
}

async function openJob(id, openResults) {
  try {
    const value = await api("/api/jobs/" + id);
    if (openResults && value.report?.hosts) {
      currentReport = {name: value.name, hosts: value.report.hosts};
      show("results");
    } else {
      job = value;
      const original = current;
      current = value.tool;
      if (!state[current]) current = "nmap";
      builder();
      executionMessage(job, job.output || "No output.");
      current = original === "scans" ? value.tool : original;
    }
  } catch (error) { showError(error); }
}

function parseXML(text) {
  const documentValue = new DOMParser().parseFromString(text, "text/xml");
  if (documentValue.querySelector("parsererror") || !documentValue.querySelector("nmaprun")) throw new Error("Choose a valid Nmap XML report");
  return [...documentValue.querySelectorAll("host")].map(host => ({
    address: host.querySelector("address")?.getAttribute("addr") || "Unknown",
    hostname: host.querySelector("hostname")?.getAttribute("name") || "",
    state: host.querySelector("status")?.getAttribute("state") || "unknown",
    ports: [...host.querySelectorAll("port")].map(port => {
      const service = port.querySelector("service");
      return {
        port: port.getAttribute("portid"), protocol: port.getAttribute("protocol"),
        state: port.querySelector("state")?.getAttribute("state") || "",
        service: service?.getAttribute("name") || "", product: service?.getAttribute("product") || "",
        version: service?.getAttribute("version") || "",
      };
    }),
  }));
}

function results() {
  const allRows = flattenHosts(currentReport.hosts);
  const services = [...new Set(allRows.map(row => row.service).filter(Boolean))].sort();
  const states = [...new Set(allRows.map(row => row.state).filter(Boolean))].sort();
  const reportJobs = jobsCache.filter(item => item.reportSummary);
  $("#page").innerHTML = `<div class="stat-grid"><div class="stat"><span>Hosts</span><b>${currentReport.hosts.length}</b></div>
    <div class="stat"><span>Online</span><b>${currentReport.hosts.filter(host => (host.state || host.status) === "up").length}</b></div>
    <div class="stat"><span>Open ports</span><b>${allRows.filter(row => row.state === "open").length}</b></div></div>
    <div class="card pad"><div class="card-head"><div><h2>${esc(currentReport.name)}</h2><p class="hint">Search, filter, sort, compare, and export structured Nmap results.</p></div>
    <div class="actions"><button id="importCurrent">Import XML</button><input id="currentFile" type="file" accept=".xml" hidden>
    <button id="exportJson">JSON</button><button id="exportCsv">CSV</button><button id="exportHtml">HTML</button></div></div>
    <div class="filter-grid"><input id="resultSearch" placeholder="Search address, hostname, service or product" value="${esc(resultFilters.query)}">
    <select id="serviceFilter"><option value="">All services</option>${services.map(value => `<option ${value === resultFilters.service ? "selected" : ""}>${esc(value)}</option>`).join("")}</select>
    <select id="stateFilter"><option value="">All port states</option>${states.map(value => `<option ${value === resultFilters.state ? "selected" : ""}>${esc(value)}</option>`).join("")}</select>
    <select id="sortResults"><option value="address">Sort by address</option><option value="port">Sort by port</option><option value="service">Sort by service</option><option value="state">Sort by state</option></select></div>
    <div class="table-wrap"><table><thead><tr><th>HOST</th><th>PORT</th><th>STATE</th><th>SERVICE</th><th>PRODUCT / VERSION</th></tr></thead><tbody id="resultRows"></tbody></table></div></div>
    <div class="card pad"><div class="card-head"><div><h2>Compare scans</h2><p class="hint">Find new, removed, and changed ports or services.</p></div></div>
    <div class="row"><div><label for="baselineJob">Baseline</label><select id="baselineJob"><option value="">Choose completed scan</option>${reportJobs.map(item => `<option value="${item.id}">${esc(item.project + " / " + item.name)}</option>`).join("")}</select></div>
    <div><label for="comparisonJob">Comparison</label><select id="comparisonJob"><option value="">Choose completed scan</option>${reportJobs.map(item => `<option value="${item.id}">${esc(item.project + " / " + item.name)}</option>`).join("")}</select></div></div>
    <div class="actions compare-actions"><button id="compareJobs">Compare selected scans</button><button id="importComparison">Import comparison XML</button><input id="comparisonFile" type="file" accept=".xml" hidden></div>
    <div id="comparisonResults"></div></div>`;
  $("#sortResults").value = resultFilters.sort;
  const drawRows = () => {
    resultFilters = {query: $("#resultSearch").value, service: $("#serviceFilter").value, state: $("#stateFilter").value, sort: $("#sortResults").value};
    const rows = filterSortRows(allRows, resultFilters);
    $("#resultRows").innerHTML = rows.length ? rows.map(row => `<tr><td><strong>${esc(row.address)}</strong><br><span class="hint">${esc(row.hostname)}</span></td>
      <td>${esc(row.port ? row.port + "/" + row.protocol : "—")}</td><td><span class="status status-${esc(row.state || row.hostState)}">${esc(row.state || row.hostState)}</span></td>
      <td>${esc(row.service || "—")}</td><td>${esc([row.product, row.version].filter(Boolean).join(" ") || "—")}</td></tr>`).join("")
      : '<tr><td colspan="5" class="empty">No matching results.</td></tr>';
  };
  ["resultSearch", "serviceFilter", "stateFilter", "sortResults"].forEach(id => $("#" + id).oninput = drawRows);
  drawRows();
  $("#importCurrent").onclick = () => $("#currentFile").click();
  $("#currentFile").onchange = event => importReport(event, false);
  $("#importComparison").onclick = () => $("#comparisonFile").click();
  $("#comparisonFile").onchange = event => importReport(event, true);
  $("#exportJson").onclick = () => download("nmap-studio-results.json", JSON.stringify(currentReport, null, 2), "application/json");
  $("#exportCsv").onclick = () => download("nmap-studio-results.csv", rowsToCSV(filterSortRows(allRows, resultFilters)), "text/csv");
  $("#exportHtml").onclick = () => download("nmap-studio-report.html", rowsToHTML(filterSortRows(allRows, resultFilters), currentReport.name), "text/html");
  $("#compareJobs").onclick = compareSelectedJobs;
  renderComparison();
}

async function importReport(event, comparison) {
  try {
    const file = event.target.files[0];
    if (!file || file.size > 10 * 1024 * 1024) throw new Error("XML files must be 10 MB or smaller.");
    const hosts = parseXML(await file.text());
    if (hosts.length > 2000 || hosts.reduce((total, host) => total + host.ports.length, 0) > 50000) throw new Error("Report exceeds the import limit.");
    if (comparison) comparisonReport = {name: file.name, hosts};
    else currentReport = {name: file.name, hosts};
    results();
  } catch (error) { showError(error); }
}
async function compareSelectedJobs() {
  try {
    const baseline = $("#baselineJob").value;
    const comparison = $("#comparisonJob").value;
    if (!baseline || !comparison) throw new Error("Choose two completed scans.");
    const [before, after] = await Promise.all([api("/api/jobs/" + baseline), api("/api/jobs/" + comparison)]);
    currentReport = {name: before.name, hosts: before.report?.hosts || []};
    comparisonReport = {name: after.name, hosts: after.report?.hosts || []};
    results();
  } catch (error) { showError(error); }
}
function renderComparison() {
  const container = $("#comparisonResults");
  if (!container || !comparisonReport.hosts.length) {
    if (container) container.innerHTML = '<div class="empty">Choose two scans or import a comparison report.</div>';
    return;
  }
  const changes = compareReports(currentReport.hosts, comparisonReport.hosts);
  container.innerHTML = `<h3>${esc(currentReport.name)} → ${esc(comparisonReport.name)}</h3>
    <div class="change-summary"><span class="status status-new">${changes.filter(item => item.change === "new").length} new</span>
    <span class="status status-changed">${changes.filter(item => item.change === "changed").length} changed</span>
    <span class="status status-removed">${changes.filter(item => item.change === "removed").length} removed</span></div>
    ${changes.length ? `<div class="table-wrap"><table><thead><tr><th>CHANGE</th><th>HOST</th><th>PORT</th><th>BEFORE</th><th>AFTER</th></tr></thead><tbody>
    ${changes.map(item => { const before = item.before, after = item.after, row = after || before; return `<tr><td><span class="status status-${item.change}">${item.change}</span></td>
      <td>${esc(row.address)}</td><td>${esc(row.port + "/" + row.protocol)}</td>
      <td>${esc(before ? [before.state, before.service, before.product, before.version].filter(Boolean).join(" · ") : "—")}</td>
      <td>${esc(after ? [after.state, after.service, after.product, after.version].filter(Boolean).join(" · ") : "—")}</td></tr>`; }).join("")}</tbody></table></div>`
      : '<div class="empty">No port or service changes detected.</div>'}`;
}

function scripts() {
  const catalog = CATALOG.scripts || [];
  const detail = new Map(catalog.map(item => [item.name, item]));
  const riskyCategories = new Set(["auth", "brute", "dos", "exploit", "external", "fuzzer", "intrusive", "malware", "vuln"]);
  const source = installedScripts.length ? installedScripts : catalog.map(item => ({
    name: item.name,
    categories: item.categories || [],
    risk: (item.categories || []).some(category => riskyCategories.has(category)) ? "advanced" : "safe",
  }));
  const list = source.map(item => ({...item, description: detail.get(item.name)?.description || "Installed NSE script"}));
  $("#page").innerHTML = `<div class="card pad"><div class="card-head"><div><h2>NSE safety library</h2><p class="hint">Scripts are classified from their installed Nmap categories.</p></div><span class="pill">${list.length} installed</span></div>
    <div class="filter-grid three"><input id="scriptSearch" placeholder="Search scripts, descriptions, or categories">
    <select id="riskFilter"><option value="">All safety levels</option><option value="safe">Safe mode</option><option value="advanced">Advanced only</option></select>
    <select id="categoryFilter"><option value="">All categories</option>${[...new Set(list.flatMap(item => item.categories || []))].sort().map(value => `<option>${esc(value)}</option>`).join("")}</select></div>
    <div class="script-list" id="scriptList"></div></div>`;
  const draw = () => {
    const query = $("#scriptSearch").value.toLowerCase();
    const risk = $("#riskFilter").value;
    const category = $("#categoryFilter").value;
    const visible = list.filter(item => (!query || (item.name + " " + item.description + " " + item.categories.join(" ")).toLowerCase().includes(query))
      && (!risk || item.risk === risk) && (!category || item.categories.includes(category)));
    $("#scriptList").innerHTML = visible.length ? visible.slice(0, 500).map(item => {
      const badge = riskLabel(item);
      return `<article class="script"><div><div><strong>${esc(item.name)}</strong><span class="risk ${badge.className}">${badge.label}</span></div>
        <p>${esc(item.description.slice(0, 280))}</p><div class="tag">${esc((item.categories || []).join(" · ") || "uncategorized")}</div>
        ${item.risk === "advanced" ? '<p class="risk-note">May authenticate, brute-force, exploit, contact external systems, or alter the target. Review the script before use.</p>' : ""}</div>
        <button data-add-script="${esc(item.name)}" data-risk="${esc(item.risk)}">＋ Add</button></article>`;
    }).join("") : '<div class="empty">No matching scripts.</div>';
    $$("[data-add-script]").forEach(button => button.onclick = () => {
      state.nmap.scripts = [...new Set([...state.nmap.scripts.split(",").filter(Boolean), button.dataset.addScript])].join(",");
      if (button.dataset.risk === "advanced") toast("Added. This script requires Advanced mode and execution confirmation.");
      else toast("Added to the scan builder.");
    });
  };
  ["scriptSearch", "riskFilter", "categoryFilter"].forEach(id => $("#" + id).oninput = draw);
  draw();
}

function reference() {
  $("#page").innerHTML = `<div class="card pad"><h2>Installed command reference</h2>
    ${select("refTool", "Tool", [["nmap", "Nmap"], ["ncat", "Ncat"], ["nping", "Nping"], ["ndiff", "Ndiff"]], "nmap")}
    <label for="helpSearch">Filter help</label><input id="helpSearch" placeholder="Search options"><pre class="help" id="help">Loading…</pre>
    <a href="https://nmap.org/book/man.html" target="_blank" rel="noreferrer">Full Nmap manual ↗</a></div>`;
  let help = "";
  const render = () => { $("#help").textContent = help.split("\n").filter(line => line.toLowerCase().includes($("#helpSearch").value.toLowerCase())).join("\n"); };
  const load = async () => {
    try { help = await apiText("/api/help/" + $("#refTool").value); }
    catch { help = CATALOG.help[$("#refTool").value] || "Tool is not installed."; }
    render();
  };
  $("#refTool").onchange = load;
  $("#helpSearch").oninput = render;
  load();
}

function renderProfiles() {
  const profiles = readArray("studio-profiles");
  $("#profiles").innerHTML = profiles.length ? profiles.map((profile, index) =>
    `<div class="summary-line"><button data-profile="${index}">${esc(profile.name)}</button><button data-delete-profile="${index}" aria-label="Delete profile">×</button></div>`).join("")
    : '<p class="hint">Save a configuration to reuse it.</p>';
  $$("[data-profile]").forEach(button => button.onclick = () => {
    const profile = profiles[Number(button.dataset.profile)];
    state[profile.tool] = profile.state;
    show(profile.tool);
  });
  $$("[data-delete-profile]").forEach(button => button.onclick = () => {
    profiles.splice(Number(button.dataset.deleteProfile), 1);
    localStorage.setItem("studio-profiles", JSON.stringify(profiles));
    renderProfiles();
  });
}

function settingsPage() {
  $("#page").innerHTML = `<div class="grid"><div class="card pad"><h2>Privacy and execution</h2>
    <div class="checks"><label><input id="persistHistory" type="checkbox" ${settings.persistHistory ? "checked" : ""}> Save completed output in this browser</label>
    <label><input id="defaultSafe" type="checkbox" ${settings.safeMode ? "checked" : ""}> Use Safe mode by default</label></div>
    <div class="actions"><button id="clearHistory">Clear browser history</button><button id="exportProfiles">Export profiles</button><button id="importProfiles">Import profiles</button>
    <input id="profileFile" type="file" accept=".json" hidden><button id="diagnostics">Download diagnostics</button><button class="danger-button" id="shutdown">Stop runner</button></div></div>
    <div class="card pad"><h2>Security boundaries</h2><p>The runner accepts loopback requests only, requires a session token, validates options, limits its queue and memory, and never invokes a shell.</p>
    <p>Advanced NSE scripts can be intrusive. Review their source and scan only authorized systems.</p></div></div>`;
  $("#persistHistory").onchange = event => {
    settings.persistHistory = event.target.checked;
    if (!settings.persistHistory) { history = []; localStorage.removeItem("studio-history"); }
    localStorage.setItem("studio-settings", JSON.stringify(settings));
  };
  $("#defaultSafe").onchange = event => { settings.safeMode = event.target.checked; localStorage.setItem("studio-settings", JSON.stringify(settings)); };
  $("#clearHistory").onclick = () => { history = []; localStorage.removeItem("studio-history"); toast("Browser history cleared"); };
  $("#exportProfiles").onclick = () => download("nmap-studio-profiles.json", JSON.stringify(readArray("studio-profiles"), null, 2), "application/json");
  $("#importProfiles").onclick = () => $("#profileFile").click();
  $("#profileFile").onchange = async event => {
    try {
      const file = event.target.files[0];
      if (!file || file.size > 1024 * 1024) throw new Error("Profile file must be 1 MB or smaller.");
      const value = JSON.parse(await file.text());
      if (!Array.isArray(value) || value.length > 100 || !value.every(item => item && typeof item.name === "string" && Object.hasOwn(state, item.tool) && item.state)) throw new Error("Invalid profile file.");
      localStorage.setItem("studio-profiles", JSON.stringify(value));
      toast("Profiles imported");
    } catch (error) { showError(error); }
  };
  $("#diagnostics").onclick = async () => { try { download("nmap-studio-diagnostics.log", await apiText("/api/diagnostics")); } catch (error) { showError(error); } };
  $("#shutdown").onclick = async () => { try { await api("/api/shutdown", {}); token = ""; toast("Runner stopped"); } catch (error) { showError(error); } };
}

$("#saveProfile").onclick = () => {
  if (!state[current]) return toast("Open a tool to save its configuration.");
  const name = prompt("Profile name");
  if (!name) return;
  const profiles = readArray("studio-profiles");
  profiles.push({name: name.slice(0, 100), tool: current, state: structuredClone(state[current])});
  localStorage.setItem("studio-profiles", JSON.stringify(profiles));
  renderProfiles();
  toast("Profile saved");
};

function show(page) {
  current = page;
  $("#title").textContent = names[page];
  $("#breadcrumb").textContent = names[page];
  $("#subtitle").textContent = {
    nmap: "Build precise, authorized network scans.", scans: "Track queued, running, and completed work.",
    scripts: "Choose NSE scripts with clear safety classifications.", results: "Search, compare, and export network findings.",
    ncat: "Use Ncat from the local workspace.", nping: "Measure how a network responds.",
    ndiff: "Compare Nmap XML reports.", reference: "Read help from installed tools.",
    settings: "Control privacy, execution, and the local runner.",
  }[page];
  $("#saveProfile").style.display = state[page] ? "" : "none";
  $("#nav").innerHTML = Object.entries(names).map(([key, value]) =>
    `<button data-page="${key}" class="${key === page ? "active" : ""}"><em>${icons[key]}</em>${value}</button>`).join("");
  $$("[data-page]").forEach(button => button.onclick = () => {
    window.history.replaceState(null, "", "#" + button.dataset.page);
    show(button.dataset.page);
  });
  if (state[page]) builder();
  else ({scans: renderScans, scripts, results, reference, settings: settingsPage}[page])();
}

async function connectRunner() {
  try {
    const response = await fetch("/api/status", {signal: AbortSignal.timeout(3000), cache: "no-store"});
    if (!response.ok) throw new Error("Runner offline");
    const value = await response.json();
    if (!value.token) throw new Error("Runner offline");
    const changed = token !== value.token;
    token = value.token;
    $("#connection").textContent = "Local runner connected";
    $("#dot").className = "on";
    $("#version").textContent = value.version || "local";
    $("#notice").textContent = "Local-only runner · Authorized targets only · "
      + Object.entries(value.tools).map(([name, status]) => name + (status.installed ? " ✓" : " unavailable")).join(" · ");
    if (changed) {
      api("/api/scripts").then(result => { installedScripts = result.scripts || []; }).catch(() => {});
      await syncJobs();
    }
    if (changed && state[current] && !starting) builder();
    return true;
  } catch {
    token = "";
    $("#dot").className = "";
    $("#connection").textContent = "Runner disconnected";
    $("#notice").textContent = "Start the local runner with start.cmd or python server.py.";
    return false;
  }
}

const initialPage = Object.hasOwn(names, location.hash.slice(1)) ? location.hash.slice(1) : "nmap";
show(initialPage);
window.addEventListener("hashchange", () => {
  const page = location.hash.slice(1);
  if (Object.hasOwn(names, page) && page !== current) show(page);
});
connectRunner();
setInterval(connectRunner, 5000);
setInterval(syncJobs, 2000);
