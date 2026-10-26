(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.StudioCore = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";
  const escapeHtml = value => String(value ?? "").replace(
    /[&<>"']/g,
    character => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[character]),
  );
  function normalizeTargets(value) {
    return String(value).trim().split(/\s+/).filter(Boolean).map(target => {
      if (/^https?:\/\//i.test(target)) {
        let url;
        try { url = new URL(target); } catch { throw new Error("Invalid website URL: " + target); }
        if (!url.hostname) throw new Error("The website URL needs a hostname.");
        return url.hostname.replace(/^\[|\]$/g, "");
      }
      if (target.includes("://")) throw new Error("Use an HTTP/HTTPS URL, hostname, IP address, or CIDR range.");
      return /^[a-z0-9.-]+\/$/i.test(target) ? target.slice(0, -1) : target;
    });
  }
  function flattenHosts(hosts) {
    const rows = [];
    for (const host of hosts || []) {
      const ports = host.ports || [];
      if (!ports.length) rows.push({
        address: host.address || "", hostname: host.hostname || host.name || "",
        hostState: host.state || host.status || "", port: "", protocol: "",
        state: "", service: "", product: "", version: "",
      });
      for (const port of ports) rows.push({
        address: host.address || "", hostname: host.hostname || host.name || "",
        hostState: host.state || host.status || "", port: port.port || "",
        protocol: port.protocol || "", state: port.state || "", service: port.service || "",
        product: port.product || "", version: port.version || "",
      });
    }
    return rows;
  }
  function filterSortRows(rows, filters = {}) {
    const query = String(filters.query || "").toLowerCase();
    const service = String(filters.service || "");
    const state = String(filters.state || "");
    const sort = String(filters.sort || "address");
    const filtered = rows.filter(row => {
      const haystack = Object.values(row).join(" ").toLowerCase();
      return (!query || haystack.includes(query)) && (!service || row.service === service) && (!state || row.state === state);
    });
    const value = row => sort === "port" ? Number(row.port || 0) : String(row[sort] || "").toLowerCase();
    return filtered.sort((left, right) => {
      const a = value(left), b = value(right);
      return typeof a === "number" ? a - b : a.localeCompare(b, undefined, {numeric: true});
    });
  }
  function compareReports(beforeHosts, afterHosts) {
    const key = row => [row.address, row.protocol, row.port].join("|");
    const before = new Map(flattenHosts(beforeHosts).filter(row => row.port).map(row => [key(row), row]));
    const after = new Map(flattenHosts(afterHosts).filter(row => row.port).map(row => [key(row), row]));
    const changes = [];
    for (const [id, row] of after) {
      const old = before.get(id);
      if (!old) changes.push({change: "new", before: null, after: row});
      else if ([old.state, old.service, old.product, old.version].join("|") !== [row.state, row.service, row.product, row.version].join("|")) {
        changes.push({change: "changed", before: old, after: row});
      }
    }
    for (const [id, row] of before) if (!after.has(id)) changes.push({change: "removed", before: row, after: null});
    return changes.sort((a, b) => key(a.after || a.before).localeCompare(key(b.after || b.before), undefined, {numeric: true}));
  }
  const csvCell = value => '"' + String(value ?? "").replaceAll('"', '""') + '"';
  function rowsToCSV(rows) {
    const columns = ["address", "hostname", "hostState", "port", "protocol", "state", "service", "product", "version"];
    return [columns.join(","), ...rows.map(row => columns.map(column => csvCell(row[column])).join(","))].join("\n");
  }
  function rowsToHTML(rows, title = "Nmap Studio report") {
    const body = rows.map(row => "<tr>" + [row.address, row.hostname, row.hostState, row.port, row.protocol, row.state, row.service, row.product, row.version].map(value => "<td>" + escapeHtml(value) + "</td>").join("") + "</tr>").join("");
    return "<!doctype html><html><head><meta charset=\"utf-8\"><title>" + escapeHtml(title)
      + "</title><style>body{font:14px system-ui;margin:32px;color:#24332e}table{border-collapse:collapse;width:100%}th,td{border:1px solid #dfe6e1;padding:8px;text-align:left}th{background:#edf5ee}</style></head><body><h1>"
      + escapeHtml(title) + "</h1><table><thead><tr><th>Address</th><th>Hostname</th><th>Host state</th><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Product</th><th>Version</th></tr></thead><tbody>"
      + body + "</tbody></table></body></html>";
  }
  function formatDuration(seconds) {
    const total = Math.max(0, Math.floor(Number(seconds) || 0));
    const minutes = Math.floor(total / 60), remaining = total % 60;
    return minutes ? minutes + "m " + remaining + "s" : remaining + "s";
  }
  function riskLabel(script) {
    return script && script.risk === "advanced"
      ? {label: "ADVANCED", className: "risk-high"}
      : {label: "SAFE MODE", className: "risk-safe"};
  }
  return {escapeHtml, normalizeTargets, flattenHosts, filterSortRows, compareReports, rowsToCSV, rowsToHTML, formatDuration, riskLabel};
});
