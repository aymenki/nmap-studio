"""Persistent local security workspace for Nmap Studio."""
from __future__ import annotations

import csv
import contextlib
import datetime as dt
import fnmatch
import hashlib
import io
import ipaddress
import json
import pathlib
import sqlite3
import threading
import time
from typing import Any


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY, project TEXT NOT NULL, address TEXT NOT NULL,
  hostname TEXT NOT NULL DEFAULT '', mac TEXT NOT NULL DEFAULT '', state TEXT NOT NULL DEFAULT '',
  owner TEXT NOT NULL DEFAULT '', criticality TEXT NOT NULL DEFAULT 'medium', tags TEXT NOT NULL DEFAULT '[]',
  first_seen REAL NOT NULL, last_seen REAL NOT NULL, last_scan_id INTEGER,
  UNIQUE(project, address)
);
CREATE TABLE IF NOT EXISTS services (
  id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  protocol TEXT NOT NULL, port INTEGER NOT NULL, state TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL DEFAULT '', product TEXT NOT NULL DEFAULT '', version TEXT NOT NULL DEFAULT '',
  confidence INTEGER, cpes TEXT NOT NULL DEFAULT '[]', first_seen REAL NOT NULL, last_seen REAL NOT NULL,
  UNIQUE(asset_id, protocol, port)
);
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY, job_id TEXT UNIQUE NOT NULL, schedule_id INTEGER,
  name TEXT NOT NULL, project TEXT NOT NULL, created REAL NOT NULL, report_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS drift_alerts (
  id INTEGER PRIMARY KEY, scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, address TEXT NOT NULL, port TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL, created REAL NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY, fingerprint TEXT UNIQUE NOT NULL, asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
  service_id INTEGER REFERENCES services(id) ON DELETE CASCADE, title TEXT NOT NULL, cve TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL DEFAULT 'unknown', status TEXT NOT NULL DEFAULT 'open', kev INTEGER NOT NULL DEFAULT 0,
  epss REAL, confidence TEXT NOT NULL DEFAULT 'possible', source TEXT NOT NULL DEFAULT 'scan',
  description TEXT NOT NULL DEFAULT '', assignee TEXT NOT NULL DEFAULT '', due_date TEXT NOT NULL DEFAULT '',
  notes TEXT NOT NULL DEFAULT '', first_seen REAL NOT NULL, last_seen REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS intelligence (
  cve TEXT PRIMARY KEY, severity TEXT NOT NULL DEFAULT 'unknown', kev INTEGER NOT NULL DEFAULT 0,
  epss REAL, description TEXT NOT NULL DEFAULT '', url TEXT NOT NULL DEFAULT '', updated REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS schedules (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, project TEXT NOT NULL, tool TEXT NOT NULL,
  args_json TEXT NOT NULL, safe_mode INTEGER NOT NULL DEFAULT 1, interval_minutes INTEGER NOT NULL,
  next_run REAL NOT NULL, last_run REAL, enabled INTEGER NOT NULL DEFAULT 1, created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS scope_rules (
  id INTEGER PRIMARY KEY, project TEXT NOT NULL, pattern TEXT NOT NULL, action TEXT NOT NULL,
  authorization_ref TEXT NOT NULL DEFAULT '', expires TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1,
  created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY, at REAL NOT NULL, event TEXT NOT NULL, actor TEXT NOT NULL,
  details_json TEXT NOT NULL, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL UNIQUE
);
"""


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class Workspace:
    """Thread-safe SQLite-backed inventory and workflow store."""

    def __init__(self, path: pathlib.Path):
        self.path = pathlib.Path(path)
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(SCHEMA)

    @contextlib.contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _rows(cursor: sqlite3.Cursor) -> list[dict]:
        return [dict(row) for row in cursor.fetchall()]

    def audit(self, event: str, details: dict | None = None, actor: str = "local-user") -> dict:
        now = time.time()
        details_json = _json(details or {})
        with self._lock, self._connect() as connection:
            previous = connection.execute("SELECT entry_hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
            prev_hash = previous[0] if previous else "0" * 64
            entry_hash = hashlib.sha256(f"{prev_hash}|{now:.6f}|{event}|{actor}|{details_json}".encode()).hexdigest()
            cursor = connection.execute(
                "INSERT INTO audit(at,event,actor,details_json,prev_hash,entry_hash) VALUES(?,?,?,?,?,?)",
                (now, event[:80], actor[:80], details_json[:50_000], prev_hash, entry_hash),
            )
            return {"id": cursor.lastrowid, "at": now, "event": event, "entryHash": entry_hash}

    def audit_entries(self, limit: int = 250) -> list[dict]:
        with self._connect() as connection:
            rows = self._rows(connection.execute(
                "SELECT id,at,event,actor,details_json,prev_hash,entry_hash FROM audit ORDER BY id DESC LIMIT ?",
                (max(1, min(limit, 1000)),),
            ))
        for row in rows:
            row["details"] = json.loads(row.pop("details_json"))
        return rows

    def verify_audit(self) -> dict:
        previous = "0" * 64
        checked = 0
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM audit ORDER BY id")
            for row in rows:
                expected = hashlib.sha256(
                    f"{previous}|{row['at']:.6f}|{row['event']}|{row['actor']}|{row['details_json']}".encode()
                ).hexdigest()
                if row["prev_hash"] != previous or row["entry_hash"] != expected:
                    return {"valid": False, "checked": checked, "failedId": row["id"]}
                previous = row["entry_hash"]
                checked += 1
        return {"valid": True, "checked": checked, "head": previous}

    def add_scope_rule(self, project: str, pattern: str, action: str, authorization_ref: str, expires: str) -> dict:
        if action not in {"allow", "deny"}:
            raise ValueError("Scope action must be allow or deny")
        if not project.strip() or not pattern.strip() or len(pattern) > 255:
            raise ValueError("Project and target pattern are required")
        expires = self._normalize_expiry(expires)
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT INTO scope_rules(project,pattern,action,authorization_ref,expires,created) VALUES(?,?,?,?,?,?)",
                (project.strip()[:80], pattern.strip().lower(), action, authorization_ref.strip()[:200], expires, time.time()),
            )
            rule_id = cursor.lastrowid
        self.audit("scope.created", {"id": rule_id, "project": project, "pattern": pattern, "action": action, "authorizationRef": authorization_ref})
        return {"id": rule_id}

    @staticmethod
    def _normalize_expiry(value: str) -> str:
        value = value.strip()
        if not value:
            return ""
        try:
            timestamp = float(value)
        except ValueError:
            try:
                parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError("Expiry must be an ISO date/time or Unix timestamp") from exc
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            timestamp = parsed.timestamp()
        if timestamp <= time.time():
            raise ValueError("Scope expiry must be in the future")
        return str(timestamp)

    def scopes(self) -> list[dict]:
        with self._connect() as connection:
            return self._rows(connection.execute("SELECT * FROM scope_rules ORDER BY active DESC,id DESC"))

    def deactivate_scope(self, rule_id: int) -> None:
        with self._connect() as connection:
            connection.execute("UPDATE scope_rules SET active=0 WHERE id=?", (rule_id,))
        self.audit("scope.deactivated", {"id": rule_id})

    @staticmethod
    def _matches(target: str, pattern: str) -> bool:
        target = target.strip().strip("[]").lower()
        try:
            network = ipaddress.ip_network(pattern, strict=False)
            return ipaddress.ip_address(target) in network
        except ValueError:
            return fnmatch.fnmatchcase(target, pattern)

    def check_scope(self, project: str, targets: list[str]) -> dict:
        now = time.time()
        rules = [row for row in self.scopes() if row["active"] and row["project"] == project]
        valid_rules = []
        for rule in rules:
            expires = rule["expires"]
            try:
                expired = bool(expires) and float(expires) < now
            except ValueError:
                expired = False
            if not expired:
                valid_rules.append(rule)
        allow = [rule for rule in valid_rules if rule["action"] == "allow"]
        deny = [rule for rule in valid_rules if rule["action"] == "deny"]
        rejected = []
        for target in targets:
            if any(self._matches(target, rule["pattern"]) for rule in deny):
                rejected.append(target)
            elif allow and not any(self._matches(target, rule["pattern"]) for rule in allow):
                rejected.append(target)
        return {"allowed": not rejected, "rejected": rejected, "enforced": bool(allow), "ruleCount": len(valid_rules)}

    @staticmethod
    def _service_map(report: dict) -> dict[str, dict]:
        result = {}
        for host in report.get("hosts", []):
            for service in host.get("ports", []):
                if not str(service.get("state", "")).startswith("open"):
                    continue
                key = f"{host.get('address','')}|{service.get('protocol','')}|{service.get('port','')}"
                result[key] = service
        return result

    def persist_scan(self, job: Any) -> dict:
        report = job.report or {"hosts": []}
        now = job.finished or time.time()
        with self._lock, self._connect() as connection:
            previous_row = connection.execute(
                "SELECT report_json FROM scans WHERE project=? AND name=? ORDER BY id DESC LIMIT 1",
                (job.project, job.name),
            ).fetchone()
            previous = json.loads(previous_row[0]) if previous_row else {"hosts": []}
            cursor = connection.execute(
                "INSERT OR REPLACE INTO scans(job_id,schedule_id,name,project,created,report_json) VALUES(?,?,?,?,?,?)",
                (job.id, getattr(job, "schedule_id", None), job.name, job.project, now, _json(report)),
            )
            scan_id = cursor.lastrowid
            for host in report.get("hosts", []):
                address = str(host.get("address", ""))[:255]
                if not address:
                    continue
                mac = str(host.get("mac", ""))[:64]
                connection.execute(
                    "INSERT INTO assets(project,address,hostname,mac,state,first_seen,last_seen,last_scan_id) VALUES(?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(project,address) DO UPDATE SET hostname=excluded.hostname,mac=excluded.mac,state=excluded.state,last_seen=excluded.last_seen,last_scan_id=excluded.last_scan_id",
                    (job.project, address, str(host.get("hostname", ""))[:255], mac, str(host.get("state", ""))[:40], now, now, scan_id),
                )
                asset_id = connection.execute("SELECT id FROM assets WHERE project=? AND address=?", (job.project, address)).fetchone()[0]
                connection.execute("UPDATE services SET state='not-seen' WHERE asset_id=?", (asset_id,))
                for service in host.get("ports", []):
                    try:
                        port = int(service.get("port", 0))
                    except (TypeError, ValueError):
                        continue
                    connection.execute(
                        "INSERT INTO services(asset_id,protocol,port,state,name,product,version,confidence,cpes,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?) "
                        "ON CONFLICT(asset_id,protocol,port) DO UPDATE SET state=excluded.state,name=excluded.name,product=excluded.product,version=excluded.version,confidence=excluded.confidence,cpes=excluded.cpes,last_seen=excluded.last_seen",
                        (asset_id, str(service.get("protocol", ""))[:20], port, str(service.get("state", ""))[:40],
                         str(service.get("service", ""))[:120], str(service.get("product", ""))[:255], str(service.get("version", ""))[:120],
                         service.get("confidence"), _json(service.get("cpes", [])), now, now),
                    )
                    service_id = connection.execute(
                        "SELECT id FROM services WHERE asset_id=? AND protocol=? AND port=?",
                        (asset_id, str(service.get("protocol", ""))[:20], port),
                    ).fetchone()[0]
                    for cve in service.get("cves", []):
                        self._upsert_finding(connection, asset_id, service_id, cve, now, source="nse")
            self._record_drift(connection, scan_id, previous, report, now)
        self.audit("scan.persisted", {"jobId": job.id, "scanId": scan_id, "project": job.project, "name": job.name, "hosts": report.get("hostCount", 0)})
        return {"scanId": scan_id}

    def _record_drift(self, connection: sqlite3.Connection, scan_id: int, before: dict, after: dict, now: float) -> None:
        before_hosts = {host.get("address", "") for host in before.get("hosts", [])}
        after_hosts = {host.get("address", "") for host in after.get("hosts", [])}
        for address in sorted(after_hosts - before_hosts):
            connection.execute("INSERT INTO drift_alerts(scan_id,kind,address,detail,created) VALUES(?,?,?,?,?)", (scan_id, "new-host", address, "New asset discovered", now))
        for address in sorted(before_hosts - after_hosts):
            connection.execute("INSERT INTO drift_alerts(scan_id,kind,address,detail,created) VALUES(?,?,?,?,?)", (scan_id, "missing-host", address, "Previously seen asset was not observed", now))
        old, new = self._service_map(before), self._service_map(after)
        for key in sorted(new.keys() - old.keys()):
            address, protocol, port = key.split("|", 2)
            connection.execute("INSERT INTO drift_alerts(scan_id,kind,address,port,detail,created) VALUES(?,?,?,?,?,?)", (scan_id, "new-service", address, f"{port}/{protocol}", f"New {new[key].get('service') or 'service'}", now))
        for key in sorted(old.keys() - new.keys()):
            address, protocol, port = key.split("|", 2)
            connection.execute("INSERT INTO drift_alerts(scan_id,kind,address,port,detail,created) VALUES(?,?,?,?,?,?)", (scan_id, "removed-service", address, f"{port}/{protocol}", "Service no longer observed", now))
        for key in sorted(old.keys() & new.keys()):
            fields = ("state", "service", "product", "version")
            if any(old[key].get(field) != new[key].get(field) for field in fields):
                address, protocol, port = key.split("|", 2)
                connection.execute("INSERT INTO drift_alerts(scan_id,kind,address,port,detail,created) VALUES(?,?,?,?,?,?)", (scan_id, "changed-service", address, f"{port}/{protocol}", "Service fingerprint changed", now))

    def _upsert_finding(self, connection: sqlite3.Connection, asset_id: int, service_id: int, cve: str, now: float, source: str, confidence: str = "reported") -> None:
        intel = connection.execute("SELECT * FROM intelligence WHERE cve=?", (cve,)).fetchone()
        severity = intel["severity"] if intel else "unknown"
        kev = intel["kev"] if intel else 0
        epss = intel["epss"] if intel else None
        description = intel["description"] if intel else "Detected in scan output; validate before remediation."
        fingerprint = hashlib.sha256(f"{asset_id}|{service_id}|{cve}".encode()).hexdigest()
        connection.execute(
            "INSERT INTO findings(fingerprint,asset_id,service_id,title,cve,severity,kev,epss,confidence,source,description,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(fingerprint) DO UPDATE SET severity=excluded.severity,kev=excluded.kev,epss=excluded.epss,description=excluded.description,last_seen=excluded.last_seen",
            (fingerprint, asset_id, service_id, cve, cve, severity, kev, epss, confidence, source, description[:4000], now, now),
        )

    def assets(self, query: str = "") -> list[dict]:
        query = f"%{query.strip()}%"
        with self._connect() as connection:
            rows = self._rows(connection.execute(
                "SELECT a.*,COUNT(s.id) service_count,SUM(CASE WHEN s.state='open' THEN 1 ELSE 0 END) open_ports "
                "FROM assets a LEFT JOIN services s ON s.asset_id=a.id WHERE a.address LIKE ? OR a.hostname LIKE ? OR a.project LIKE ? "
                "GROUP BY a.id ORDER BY a.last_seen DESC LIMIT 2000", (query, query, query),
            ))
        for row in rows:
            row["tags"] = json.loads(row["tags"])
        return rows

    def update_asset(self, asset_id: int, owner: str, criticality: str, tags: list[str]) -> None:
        if criticality not in {"low", "medium", "high", "critical"}:
            raise ValueError("Invalid criticality")
        clean_tags = [str(tag).strip()[:40] for tag in tags[:20] if str(tag).strip()]
        with self._connect() as connection:
            connection.execute("UPDATE assets SET owner=?,criticality=?,tags=? WHERE id=?", (owner.strip()[:120], criticality, _json(clean_tags), asset_id))
        self.audit("asset.updated", {"id": asset_id, "owner": owner, "criticality": criticality, "tags": clean_tags})

    def findings(self) -> list[dict]:
        with self._connect() as connection:
            return self._rows(connection.execute(
                "SELECT f.*,a.address,a.hostname,a.project,s.port,s.protocol,s.name service,s.product,s.version "
                "FROM findings f LEFT JOIN assets a ON a.id=f.asset_id LEFT JOIN services s ON s.id=f.service_id "
                "ORDER BY f.kev DESC,CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,f.last_seen DESC LIMIT 5000"
            ))

    def update_finding(self, finding_id: int, status: str, assignee: str, due_date: str, notes: str) -> None:
        if status not in {"open", "investigating", "accepted", "false-positive", "resolved"}:
            raise ValueError("Invalid finding status")
        with self._connect() as connection:
            connection.execute("UPDATE findings SET status=?,assignee=?,due_date=?,notes=? WHERE id=?", (status, assignee.strip()[:120], due_date.strip()[:40], notes.strip()[:4000], finding_id))
        self.audit("finding.updated", {"id": finding_id, "status": status, "assignee": assignee, "dueDate": due_date})

    def alerts(self) -> list[dict]:
        with self._connect() as connection:
            return self._rows(connection.execute("SELECT * FROM drift_alerts ORDER BY acknowledged,created DESC LIMIT 1000"))

    def acknowledge_alert(self, alert_id: int) -> None:
        with self._connect() as connection:
            connection.execute("UPDATE drift_alerts SET acknowledged=1 WHERE id=?", (alert_id,))
        self.audit("alert.acknowledged", {"id": alert_id})

    def add_schedule(self, name: str, project: str, tool: str, args: list[str], interval_minutes: int, safe_mode: bool = True) -> dict:
        if interval_minutes < 5 or interval_minutes > 525600:
            raise ValueError("Schedule interval must be between 5 minutes and one year")
        now = time.time()
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT INTO schedules(name,project,tool,args_json,safe_mode,interval_minutes,next_run,created) VALUES(?,?,?,?,?,?,?,?)",
                (name.strip()[:80] or "Scheduled scan", project.strip()[:80] or "Default", tool, _json(args), int(safe_mode), interval_minutes, now + interval_minutes * 60, now),
            )
            schedule_id = cursor.lastrowid
        self.audit("schedule.created", {"id": schedule_id, "name": name, "project": project, "intervalMinutes": interval_minutes})
        return {"id": schedule_id}

    def schedules(self, due_only: bool = False) -> list[dict]:
        sql = "SELECT * FROM schedules"
        parameters: tuple = ()
        if due_only:
            sql += " WHERE enabled=1 AND next_run<=?"
            parameters = (time.time(),)
        sql += " ORDER BY enabled DESC,next_run"
        with self._connect() as connection:
            rows = self._rows(connection.execute(sql, parameters))
        for row in rows:
            row["args"] = json.loads(row.pop("args_json"))
        return rows

    def schedule_ran(self, schedule_id: int) -> None:
        now = time.time()
        with self._connect() as connection:
            connection.execute("UPDATE schedules SET last_run=?,next_run=?+interval_minutes*60 WHERE id=?", (now, now, schedule_id))

    def set_schedule(self, schedule_id: int, enabled: bool) -> None:
        with self._connect() as connection:
            connection.execute("UPDATE schedules SET enabled=?,next_run=CASE WHEN ? THEN ? ELSE next_run END WHERE id=?", (int(enabled), int(enabled), time.time() + 60, schedule_id))
        self.audit("schedule.enabled" if enabled else "schedule.disabled", {"id": schedule_id})

    def upsert_intelligence(self, items: list[dict]) -> int:
        now = time.time()
        with self._connect() as connection:
            for item in items:
                cve = str(item.get("cve", "")).upper()
                if not cve.startswith("CVE-"):
                    continue
                current = connection.execute("SELECT * FROM intelligence WHERE cve=?", (cve,)).fetchone()
                severity = str(item.get("severity", current["severity"] if current else "unknown")).lower()
                kev = int(bool(item["kev"])) if "kev" in item else (current["kev"] if current else 0)
                epss = item["epss"] if "epss" in item else (current["epss"] if current else None)
                description = str(item.get("description", current["description"] if current else ""))[:4000]
                url = str(item.get("url", current["url"] if current else ""))[:500]
                connection.execute(
                    "INSERT INTO intelligence(cve,severity,kev,epss,description,url,updated) VALUES(?,?,?,?,?,?,?) "
                    "ON CONFLICT(cve) DO UPDATE SET severity=excluded.severity,kev=excluded.kev,epss=excluded.epss,description=excluded.description,url=excluded.url,updated=excluded.updated",
                    (cve, severity, kev, epss, description, url, now),
                )
            findings = connection.execute("SELECT id,cve FROM findings WHERE cve<>''").fetchall()
            for finding in findings:
                intel = connection.execute("SELECT * FROM intelligence WHERE cve=?", (finding["cve"],)).fetchone()
                if intel:
                    connection.execute("UPDATE findings SET severity=?,kev=?,epss=?,description=? WHERE id=?", (intel["severity"], intel["kev"], intel["epss"], intel["description"], finding["id"]))
        self.audit("intelligence.updated", {"records": len(items)})
        return len(items)

    def cves(self) -> list[str]:
        with self._connect() as connection:
            return [row[0] for row in connection.execute("SELECT DISTINCT cve FROM findings WHERE cve<>'' ORDER BY cve LIMIT 1000")]

    def services_for_enrichment(self) -> list[dict]:
        with self._connect() as connection:
            rows = self._rows(connection.execute(
                "SELECT s.*,a.address,a.project FROM services s JOIN assets a ON a.id=s.asset_id WHERE s.state='open' AND s.product<>'' ORDER BY s.last_seen DESC LIMIT 50"
            ))
        for row in rows:
            row["cpes"] = json.loads(row["cpes"])
        return rows

    def add_candidate(self, service_id: int, cve: str, severity: str, description: str, url: str) -> None:
        with self._connect() as connection:
            row = connection.execute("SELECT asset_id FROM services WHERE id=?", (service_id,)).fetchone()
            if not row:
                return
            connection.execute(
                "INSERT INTO intelligence(cve,severity,description,url,updated) VALUES(?,?,?,?,?) "
                "ON CONFLICT(cve) DO UPDATE SET severity=excluded.severity,description=excluded.description,url=excluded.url,updated=excluded.updated",
                (cve, severity, description[:4000], url[:500], time.time()),
            )
            self._upsert_finding(connection, row[0], service_id, cve, time.time(), "nvd-keyword", confidence="possible")

    def export(self, format_name: str) -> tuple[str, str]:
        assets = self.assets()
        findings = self.findings()
        if format_name == "splunk":
            lines = [_json({"type": "asset", **item}) for item in assets] + [_json({"type": "finding", **item}) for item in findings]
            return "application/x-ndjson", "\n".join(lines) + ("\n" if lines else "")
        if format_name == "defectdojo":
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            writer.writerow(["Date", "Title", "Severity", "Description", "Mitigation", "Impact", "References", "Active", "Verified", "False Positive", "Duplicate"])
            for item in findings:
                writer.writerow([time.strftime("%Y-%m-%d", time.gmtime(item["last_seen"])), item["title"], item["severity"].title(), item["description"], "Validate and remediate the affected service.", item["address"], item["cve"], "True", "False", str(item["status"] == "false-positive"), "False"])
            return "text/csv", buffer.getvalue()
        if format_name == "sarif":
            rules = {item["cve"] or item["title"]: {"id": item["cve"] or item["title"], "shortDescription": {"text": item["title"]}} for item in findings}
            results = [{"ruleId": item["cve"] or item["title"], "level": "error" if item["severity"] in {"critical", "high"} else "warning", "message": {"text": f"{item['title']} on {item.get('address','')}:{item.get('port','')} ({item['confidence']} match)"}, "properties": {"status": item["status"], "kev": bool(item["kev"]), "epss": item["epss"]}} for item in findings]
            return "application/sarif+json", json.dumps({"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "Nmap Studio", "rules": list(rules.values())}}, "results": results}]}, indent=2)
        return "application/json", json.dumps({"assets": assets, "findings": findings, "alerts": self.alerts()}, ensure_ascii=False, indent=2)

    def summary(self) -> dict:
        with self._connect() as connection:
            return {
                "assets": connection.execute("SELECT COUNT(*) FROM assets").fetchone()[0],
                "openServices": connection.execute("SELECT COUNT(*) FROM services WHERE state='open'").fetchone()[0],
                "openFindings": connection.execute("SELECT COUNT(*) FROM findings WHERE status NOT IN ('resolved','false-positive')").fetchone()[0],
                "kev": connection.execute("SELECT COUNT(*) FROM findings WHERE kev=1 AND status NOT IN ('resolved','false-positive')").fetchone()[0],
                "unacknowledgedAlerts": connection.execute("SELECT COUNT(*) FROM drift_alerts WHERE acknowledged=0").fetchone()[0],
                "schedules": connection.execute("SELECT COUNT(*) FROM schedules WHERE enabled=1").fetchone()[0],
            }
