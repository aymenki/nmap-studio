"use strict";
const assert = require("node:assert/strict");
const core = require("../dist/core.js");

const before = [{address: "10.0.0.1", state: "up", ports: [
  {port: "22", protocol: "tcp", state: "open", service: "ssh", product: "OpenSSH", version: "8"},
]}];
const after = [{address: "10.0.0.1", state: "up", ports: [
  {port: "22", protocol: "tcp", state: "open", service: "ssh", product: "OpenSSH", version: "9"},
  {port: "443", protocol: "tcp", state: "open", service: "https", product: "nginx", version: "1"},
]}];
const changes = core.compareReports(before, after);
assert.equal(changes.filter(item => item.change === "new").length, 1);
assert.equal(changes.filter(item => item.change === "changed").length, 1);

const rows = core.flattenHosts(after);
assert.equal(core.filterSortRows(rows, {service: "https"}).length, 1);
assert.match(core.rowsToCSV(rows), /10\.0\.0\.1/);
assert.match(core.rowsToHTML(rows, "Lab report"), /Lab report/);
assert.deepEqual(core.normalizeTargets("https://example.com/path"), ["example.com"]);
assert.equal(core.formatDuration(65), "1m 5s");
console.log("core frontend tests passed");
