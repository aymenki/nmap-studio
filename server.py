"""Secure, local-only HTTP runner for Nmap Studio."""
from __future__ import annotations

import codecs
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import pathlib
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
import xml.etree.ElementTree as ET
from collections import OrderedDict, deque
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

from intelligence import refresh as refresh_intelligence
from workspace import Workspace

VERSION = "0.4.2"
ROOT = pathlib.Path(__file__).resolve().parent
DATA_DIR = pathlib.Path(os.environ.get("NMAP_STUDIO_DATA_DIR", ROOT / ".nmap-studio"))
REPORT_DIR = DATA_DIR / "reports"
LOG_DIR = DATA_DIR / "logs"
LOG_FILE = LOG_DIR / "nmap-studio.log"
DEFAULT_PORT = int(os.environ.get("NMAP_STUDIO_PORT", "8765"))
MAX_BODY_BYTES = 128 * 1024
MAX_ARGS = 128
MAX_ARG_BYTES = 4096
MAX_TOTAL_ARG_BYTES = 65536
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_COMPLETED_JOBS = 20
JOB_TTL_SECONDS = 24 * 60 * 60
MAX_RUNNING_JOBS = 2
MAX_QUEUED_JOBS = 32
MAX_XML_BYTES = 10 * 1024 * 1024
MAX_XML_HOSTS = 2000
MAX_XML_PORTS = 50000
TOOLS = ("nmap", "ncat", "nping", "ndiff")
COMMAND_OVERRIDES: dict[str, list[str]] = {}
TOOL_CACHE: dict[str, dict] = {}
TOOL_CACHE_TIME = 0.0
TOOL_CACHE_LOCK = threading.Lock()
SCRIPT_CACHE: list[dict] = []
SCRIPT_CACHE_TIME = 0.0
SCRIPT_CACHE_LOCK = threading.Lock()
RISKY_NSE_CATEGORIES = {"auth", "brute", "dos", "exploit", "external", "fuzzer", "intrusive", "malware", "vuln"}
INTELLIGENCE_STATE: dict = {"state": "idle", "stage": "Not started", "completed": 0, "total": 3, "error": ""}
INTELLIGENCE_LOCK = threading.Lock()

PLAIN_SAFE_FLAGS = {
    "nmap": {
        "-sS", "-sT", "-sU", "-sA", "-sW", "-sM", "-sN", "-sF", "-sX",
        "-sV", "-sC", "-O", "-Pn", "-n", "-R", "--traceroute", "--reason", "--open",
        "-sL", "-sY", "-sZ", "-sO", "-PE", "-PS", "-PA", "-PU",
        "-T0", "-T1", "-T2", "-T3", "-T4", "-T5", "-4", "-6", "-sn",
    },
    "ncat": {"-u", "--udp", "--ssl", "-v", "--verbose", "-z"},
    "nping": {"--tcp-connect", "--udp", "--icmp", "-v"},
    "ndiff": {"--xml", "-v"},
}
VALUE_SAFE_FLAGS = {
    "nmap": {"-p", "--top-ports", "--exclude", "--max-retries", "--host-timeout"},
    "ncat": {"-w", "--wait", "-i", "--idle-timeout"},
    "nping": {"-c", "--count", "-p", "--dest-port", "--delay"},
    "ndiff": set(),
}
OUTPUT_FLAGS = ("-oX", "-oA", "-oN", "-oG", "-oS")


class ValidationError(ValueError):
    """An error suitable for returning as a 400 response."""


def configure_logging() -> logging.Logger:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("nmap-studio")
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
    return logger


LOGGER = configure_logging()
WORKSPACE = Workspace(DATA_DIR / "studio.db")


def resolve_command(tool: str) -> list[str]:
    if tool not in TOOLS:
        raise ValidationError("Unknown tool")
    if tool in COMMAND_OVERRIDES:
        return list(COMMAND_OVERRIDES[tool])
    if tool == "ndiff":
        nmap_path = shutil.which("nmap")
        if nmap_path:
            candidate = pathlib.Path(nmap_path).parent / "ndiff.py"
            if candidate.exists():
                return [sys.executable, str(candidate)]
    path = shutil.which(tool)
    if not path:
        raise ValidationError(f"{tool} is not installed or is not on PATH")
    return [path]


def validate_args(tool: str, args: object, safe_mode: object, confirm_advanced: object) -> list[str]:
    if tool not in TOOLS:
        raise ValidationError("Unknown tool")
    if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
        raise ValidationError("args must be an array of strings")
    if len(args) > MAX_ARGS:
        raise ValidationError(f"Too many arguments; maximum is {MAX_ARGS}")
    total = 0
    for arg in args:
        size = len(arg.encode("utf-8"))
        if not arg or "\x00" in arg or size > MAX_ARG_BYTES:
            raise ValidationError("An argument is empty, invalid, or too long")
        total += size
    if total > MAX_TOTAL_ARG_BYTES:
        raise ValidationError("Command is too large")
    if safe_mode is not False:
        validate_safe_args(tool, args)
    elif confirm_advanced is not True:
        raise ValidationError("Advanced mode must be explicitly confirmed")
    return args


def validate_safe_args(tool: str, args: list[str]) -> None:
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            raise ValidationError("The -- separator requires Advanced mode")
        if not arg.startswith("-") or arg == "-":
            index += 1
            continue
        if arg in PLAIN_SAFE_FLAGS[tool]:
            index += 1
            continue
        if tool == "nmap" and arg == "--script":
            if index + 1 >= len(args):
                raise ValidationError("--script requires a value")
            validate_safe_scripts(args[index + 1])
            index += 2
            continue
        if tool == "nmap" and arg == "--script-args":
            if index + 1 >= len(args) or not re.fullmatch(
                r"[A-Za-z0-9_.-]+=[A-Za-z0-9_./:@+ -]+(?:,[A-Za-z0-9_.-]+=[A-Za-z0-9_./:@+ -]+)*",
                args[index + 1],
            ):
                raise ValidationError("Complex NSE arguments require Advanced mode")
            index += 2
            continue
        if arg in VALUE_SAFE_FLAGS[tool]:
            if index + 1 >= len(args) or args[index + 1].startswith("-"):
                raise ValidationError(f"{arg} requires a value")
            index += 2
            continue
        if any(arg.startswith(flag + "=") for flag in VALUE_SAFE_FLAGS[tool]):
            index += 1
            continue
        if tool == "nmap" and arg.startswith("-p") and len(arg) > 2:
            index += 1
            continue
        raise ValidationError(f"{arg} requires Advanced mode")


def validate_safe_scripts(value: str) -> None:
    names = [name.strip() for name in value.split(",") if name.strip()]
    if not names or any(not re.fullmatch(r"[A-Za-z0-9_.-]+", name) for name in names):
        raise ValidationError("Safe mode accepts exact installed NSE script names only")
    index = {item["name"]: item for item in discover_scripts()}
    unavailable = [name for name in names if name not in index]
    risky = [name for name in names if index.get(name, {}).get("risk") == "advanced"]
    if unavailable:
        raise ValidationError("Unknown NSE script: " + ", ".join(unavailable[:5]))
    if risky:
        raise ValidationError("These NSE scripts require Advanced mode: " + ", ".join(risky[:5]))


def extract_targets(tool: str, args: list[str]) -> list[str]:
    """Extract scan targets without treating option values as targets."""
    if tool == "ndiff":
        return []
    values = set(VALUE_SAFE_FLAGS.get(tool, set()))
    if tool == "nmap":
        values.update({"--script", "--script-args", "-oX", "-oN", "-oG", "-oA", "-oS", "--stylesheet"})
    targets = []
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg in values:
            skip = True
            continue
        if arg.startswith("-"):
            continue
        targets.append(arg)
    if tool in {"ncat", "nping"} and targets and targets[-1].isdigit():
        targets.pop()
    return targets


def scope_preview(project: str, tool: str, args: list[str]) -> dict:
    targets = extract_targets(tool, args)
    result = WORKSPACE.check_scope(project, targets)
    result["targets"] = targets
    result["targetCount"] = len(targets)
    risky = [arg for arg in args if arg in {"-sU", "-O", "-A", "-T5", "--script"}]
    result["intensity"] = "high" if risky else ("medium" if "-sV" in args else "low")
    return result


def parse_nmap_report(path: pathlib.Path) -> dict | None:
    if not path.exists() or path.stat().st_size > MAX_XML_BYTES:
        return None
    header = path.read_bytes()[:4096].upper()
    if b"<!DOCTYPE" in header and b"<!DOCTYPE NMAPRUN>" not in header:
        raise ValidationError("Only the standard Nmap XML document type is accepted")
    root = ET.parse(path).getroot()
    hosts: list[dict] = []
    port_count = 0
    for host_element in root.findall("host"):
        if len(hosts) >= MAX_XML_HOSTS:
            break
        addresses = host_element.findall("address")
        address = next((item for item in addresses if item.get("addrtype") in {"ipv4", "ipv6"}), addresses[0] if addresses else None)
        mac_element = next((item for item in addresses if item.get("addrtype") == "mac"), None)
        status = host_element.find("status")
        hostname = host_element.find("hostnames/hostname")
        ports: list[dict] = []
        for port_element in host_element.findall("ports/port"):
            if port_count >= MAX_XML_PORTS:
                break
            state = port_element.find("state")
            service = port_element.find("service")
            scripts = [{"id": item.get("id", ""), "output": item.get("output", "")} for item in port_element.findall("script")]
            script_text = " ".join(item["id"] + " " + item["output"] for item in scripts)
            ports.append({
                "port": port_element.get("portid", ""),
                "protocol": port_element.get("protocol", ""),
                "state": state.get("state", "") if state is not None else "",
                "service": service.get("name", "") if service is not None else "",
                "product": service.get("product", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
                "confidence": int(service.get("conf", "0") or 0) if service is not None else 0,
                "cpes": [item.text or "" for item in service.findall("cpe")] if service is not None else [],
                "scripts": scripts,
                "cves": sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", script_text, re.IGNORECASE))),
            })
            port_count += 1
        hosts.append({
            "address": address.get("addr", "") if address is not None else "",
            "hostname": hostname.get("name", "") if hostname is not None else "",
            "mac": mac_element.get("addr", "") if mac_element is not None else "",
            "state": status.get("state", "") if status is not None else "",
            "ports": ports,
        })
    runstats = root.find("runstats/finished")
    return {
        "hosts": hosts,
        "hostCount": len(hosts),
        "portCount": port_count,
        "summary": runstats.get("summary", "") if runstats is not None else "",
    }


class Job:
    def __init__(self, tool: str, args: list[str], safe_mode: bool, name: str = "", project: str = "", schedule_id: int | None = None):
        self.id = uuid.uuid4().hex
        self.tool = tool
        self.args = args
        self.safe_mode = safe_mode
        self.name = name or f"{tool} scan"
        self.project = project or "Default"
        self.schedule_id = schedule_id
        self.created = time.time()
        self.started: float | None = None
        self.finished: float | None = None
        self.code: int | None = None
        self.done = False
        self.cancelled = False
        self.state = "queued"
        self.stage = "Waiting in queue"
        self.progress = 0
        self.report: dict | None = None
        self.process: subprocess.Popen | None = None
        self._chunks: deque[bytes] = deque()
        self._output_bytes = 0
        self._lock = threading.RLock()

    def append(self, data: bytes) -> None:
        if not data:
            return
        if len(data) > MAX_OUTPUT_BYTES:
            data = data[-MAX_OUTPUT_BYTES:]
        with self._lock:
            self._chunks.append(data)
            self._output_bytes += len(data)
            while self._output_bytes > MAX_OUTPUT_BYTES and self._chunks:
                overflow = self._output_bytes - MAX_OUTPUT_BYTES
                first = self._chunks[0]
                if len(first) <= overflow:
                    self._chunks.popleft()
                    self._output_bytes -= len(first)
                else:
                    self._chunks[0] = first[overflow:]
                    self._output_bytes -= overflow
            text = data.decode("utf-8", errors="ignore").lower()
            if "nse:" in text or "script scan" in text:
                self.stage, self.progress = "Running NSE scripts", max(self.progress, 82)
            elif "service scan" in text or "service detection" in text:
                self.stage, self.progress = "Detecting services", max(self.progress, 68)
            elif "syn stealth scan" in text or "connect scan" in text or "udp scan" in text:
                self.stage, self.progress = "Scanning ports", max(self.progress, 42)
            elif "ping scan" in text or "host discovery" in text:
                self.stage, self.progress = "Discovering hosts", max(self.progress, 20)
            elif "starting nmap" in text:
                self.stage, self.progress = "Starting Nmap", max(self.progress, 10)

    def set_process(self, process: subprocess.Popen) -> None:
        with self._lock:
            self.process = process
            self.state = "running"
            self.stage = "Running"
            self.progress = max(self.progress, 5)
            self.started = self.started or time.time()

    def finish(self, code: int, report: dict | None = None) -> None:
        with self._lock:
            self.code = code
            self.report = report
            self.done = True
            self.finished = time.time()
            self.process = None
            self.progress = 100
            if self.cancelled:
                self.state, self.stage = "cancelled", "Cancelled"
            elif code == 0:
                self.state, self.stage = "completed", "Completed"
            else:
                self.state, self.stage = "failed", "Failed"

    def snapshot(self, queue_position: int | None = None, include_output: bool = True) -> dict:
        with self._lock:
            now = self.finished or time.time()
            result = {
                "id": self.id, "tool": self.tool, "args": self.args,
                "name": self.name, "project": self.project,
                "scheduleId": self.schedule_id,
                "safeMode": self.safe_mode, "created": self.created,
                "started": self.started, "finished": self.finished, "done": self.done,
                "cancelled": self.cancelled, "code": self.code,
                "state": self.state, "stage": self.stage, "progress": self.progress,
                "queuePosition": queue_position,
                "elapsed": max(0, now - (self.started or self.created)),
                "reportSummary": {
                    "hostCount": self.report.get("hostCount", 0),
                    "portCount": self.report.get("portCount", 0),
                    "summary": self.report.get("summary", ""),
                } if self.report else None,
            }
            if include_output:
                result["output"] = b"".join(self._chunks).decode("utf-8", errors="replace")
                result["report"] = self.report
            return result


class JobStore:
    def __init__(self) -> None:
        self._jobs: OrderedDict[str, Job] = OrderedDict()
        self._lock = threading.RLock()

    def add(self, job: Job) -> None:
        with self._lock:
            self._prune_locked()
            pending = sum(not existing.done for existing in self._jobs.values())
            if pending >= MAX_RUNNING_JOBS + MAX_QUEUED_JOBS:
                raise ValidationError("The scan queue is full")
            self._jobs[job.id] = job
            self._dispatch_locked()

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            self._prune_locked()
            return self._jobs.get(job_id)

    def running(self) -> list[Job]:
        with self._lock:
            return [job for job in self._jobs.values() if job.state == "running"]

    def active(self) -> list[Job]:
        with self._lock:
            return [job for job in self._jobs.values() if not job.done]

    def list(self) -> list[dict]:
        with self._lock:
            self._prune_locked()
            queued = [job.id for job in self._jobs.values() if job.state == "queued"]
            return [
                job.snapshot(
                    queued.index(job.id) + 1 if job.id in queued else None,
                    include_output=False,
                )
                for job in reversed(self._jobs.values())
            ]

    def finished(self, job: Job) -> None:
        with self._lock:
            self._dispatch_locked()

    def cancel(self, job: Job) -> None:
        with self._lock:
            if job.state == "queued":
                job.cancelled = True
                job.finish(-1)
                self._dispatch_locked()
                return
        stop_job(job)

    def _dispatch_locked(self) -> None:
        running = sum(job.state == "running" for job in self._jobs.values())
        for job in self._jobs.values():
            if running >= MAX_RUNNING_JOBS:
                break
            if job.state == "queued" and not job.done:
                job.state = "running"
                job.stage = "Starting"
                job.progress = 2
                job.started = time.time()
                threading.Thread(
                    target=run_job, args=(job,), daemon=True, name=f"job-{job.id[:8]}"
                ).start()
                running += 1

    def _prune_locked(self) -> None:
        now = time.time()
        for job_id, job in list(self._jobs.items()):
            if job.done and job.finished and now - job.finished > JOB_TTL_SECONDS:
                self._jobs.pop(job_id, None)
        completed = [job_id for job_id, job in self._jobs.items() if job.done]
        while len(completed) > MAX_COMPLETED_JOBS:
            self._jobs.pop(completed.pop(0), None)


JOBS = JobStore()


class ScheduleRunner:
    def __init__(self) -> None:
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, daemon=True, name="schedule-runner")
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.wait(15):
            self.run_due()

    def run_due(self) -> None:
        for schedule in WORKSPACE.schedules(due_only=True):
            try:
                args = validate_args(schedule["tool"], schedule["args"], True, False)
                preview = scope_preview(schedule["project"], schedule["tool"], args)
                if not preview["allowed"]:
                    raise ValidationError("Scheduled targets are outside the active scope")
                job = Job(schedule["tool"], args, True, schedule["name"], schedule["project"], int(schedule["id"]))
                JOBS.add(job)
                WORKSPACE.schedule_ran(int(schedule["id"]))
                WORKSPACE.audit("schedule.queued", {"scheduleId": schedule["id"], "jobId": job.id, "targets": preview["targets"]})
            except Exception as exc:
                WORKSPACE.schedule_ran(int(schedule["id"]))
                WORKSPACE.audit("schedule.failed", {"scheduleId": schedule["id"], "error": str(exc)[:500]})
                LOGGER.exception("schedule=%s could not be queued", schedule["id"])


SCHEDULER = ScheduleRunner()


def terminate_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5, check=False,
            )
        else:
            os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=3)
    except Exception:
        try:
            if os.name == "nt":
                process.kill()
            else:
                os.killpg(process.pid, signal.SIGKILL)
        except Exception:
            LOGGER.exception("Unable to terminate process %s", process.pid)


def run_job(job: Job) -> None:
    report_path = REPORT_DIR / f"{job.id}.xml"
    args = list(job.args)
    if job.tool == "nmap" and not any(
        arg == flag or arg.startswith(flag) for arg in args for flag in OUTPUT_FLAGS
    ):
        args.extend(["-oX", str(report_path)])
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    if os.name == "nt":
        creation_flags |= getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    try:
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        process = subprocess.Popen(
            resolve_command(job.tool) + args,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE,
            cwd=ROOT, creationflags=creation_flags, start_new_session=os.name != "nt",
        )
        job.set_process(process)
        if job.cancelled:
            terminate_process(process)
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        assert process.stdout is not None
        reader = getattr(process.stdout, "read1", process.stdout.read)
        while True:
            chunk = reader(4096)
            if not chunk:
                break
            job.append(decoder.decode(chunk).encode("utf-8"))
        tail = decoder.decode(b"", final=True)
        if tail:
            job.append(tail.encode("utf-8"))
        code = process.wait()
        report = parse_nmap_report(report_path) if job.tool == "nmap" and code == 0 and not job.cancelled else None
        process.stdout.close()
        if process.stdin and not process.stdin.closed:
            process.stdin.close()
        job.finish(code, report)
        if report:
            try:
                WORKSPACE.persist_scan(job)
            except Exception:
                LOGGER.exception("job=%s could not be persisted", job.id)
        else:
            WORKSPACE.audit("scan.finished", {"jobId": job.id, "state": job.state, "code": code, "project": job.project})
        LOGGER.info("job=%s tool=%s code=%s cancelled=%s", job.id, job.tool, code, job.cancelled)
    except Exception as exc:
        LOGGER.exception("job=%s failed", job.id)
        job.append((str(exc) + "\n").encode("utf-8"))
        job.finish(-1)
        WORKSPACE.audit("scan.failed", {"jobId": job.id, "project": job.project, "error": type(exc).__name__})
    finally:
        JOBS.finished(job)


def stop_job(job: Job) -> None:
    with job._lock:
        job.cancelled = True
        process = job.process
    if process is not None:
        terminate_process(process)


def tool_status(tool: str) -> dict:
    try:
        command = resolve_command(tool)
        completed = subprocess.run(command + ["--version"], capture_output=True, text=True, timeout=4, cwd=ROOT)
        first_line = (completed.stdout or completed.stderr).strip().splitlines()
        return {"installed": True, "path": command[-1], "version": first_line[0] if first_line else "Installed"}
    except Exception as exc:
        return {"installed": False, "path": "", "version": str(exc)}


def all_tool_status() -> dict[str, dict]:
    global TOOL_CACHE, TOOL_CACHE_TIME
    with TOOL_CACHE_LOCK:
        if time.time() - TOOL_CACHE_TIME > 30:
            TOOL_CACHE = {tool: tool_status(tool) for tool in TOOLS}
            TOOL_CACHE_TIME = time.time()
        return dict(TOOL_CACHE)


def script_metadata(path: pathlib.Path) -> dict:
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")[:24_000]
    except OSError:
        source = ""
    match = re.search(r"categories\s*=\s*\{([^}]*)\}", source, re.IGNORECASE | re.DOTALL)
    categories = sorted(set(re.findall(r'["\']([A-Za-z0-9_-]+)["\']', match.group(1)))) if match else []
    risk = "advanced" if RISKY_NSE_CATEGORIES.intersection(category.lower() for category in categories) else "safe"
    return {"name": path.stem, "categories": categories, "risk": risk}


def discover_scripts() -> list[dict]:
    global SCRIPT_CACHE, SCRIPT_CACHE_TIME
    with SCRIPT_CACHE_LOCK:
        if SCRIPT_CACHE and time.time() - SCRIPT_CACHE_TIME < 60:
            return list(SCRIPT_CACHE)
    candidates: list[pathlib.Path] = []
    nmap_path = shutil.which("nmap")
    if nmap_path:
        candidates.append(pathlib.Path(nmap_path).parent / "scripts")
    candidates.extend([
        pathlib.Path("/usr/share/nmap/scripts"),
        pathlib.Path("/usr/local/share/nmap/scripts"),
        pathlib.Path(os.environ.get("ProgramFiles(x86)", "")) / "Nmap" / "scripts",
        pathlib.Path(os.environ.get("ProgramFiles", "")) / "Nmap" / "scripts",
    ])
    scripts: dict[str, dict] = {}
    for directory in candidates:
        if directory.is_dir():
            for item in directory.glob("*.nse"):
                scripts.setdefault(item.stem, script_metadata(item))
    SCRIPT_CACHE = [scripts[name] for name in sorted(scripts)[:5000]]
    SCRIPT_CACHE_TIME = time.time()
    return list(SCRIPT_CACHE)


def log_tail(max_bytes: int = 200_000) -> str:
    if not LOG_FILE.exists():
        return "No diagnostics have been recorded yet."
    with LOG_FILE.open("rb") as handle:
        handle.seek(max(0, LOG_FILE.stat().st_size - max_bytes))
        return handle.read().decode("utf-8", errors="replace")


def start_intelligence_refresh() -> None:
    with INTELLIGENCE_LOCK:
        if INTELLIGENCE_STATE.get("state") == "running":
            raise ValidationError("Intelligence refresh is already running")
        INTELLIGENCE_STATE.update({"state": "starting", "stage": "Starting", "completed": 0, "total": 3, "error": ""})

    def worker() -> None:
        try:
            refresh_intelligence(WORKSPACE, INTELLIGENCE_STATE)
        except Exception as exc:
            LOGGER.exception("Intelligence refresh failed")
            INTELLIGENCE_STATE.update({"state": "failed", "stage": "Failed", "error": str(exc)[:500]})
            WORKSPACE.audit("intelligence.failed", {"error": str(exc)[:500]})

    threading.Thread(target=worker, daemon=True, name="intelligence-refresh").start()


class StudioServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int]):
        self.token = secrets.token_urlsafe(32)
        self.shutdown_requested = False
        super().__init__(address, Handler)

    def handle_error(self, request, client_address) -> None:
        LOGGER.debug("Client disconnected during response: %s", client_address, exc_info=True)


class Handler(SimpleHTTPRequestHandler):
    server: StudioServer

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT / "dist"), **kwargs)

    def log_message(self, fmt: str, *args) -> None:
        LOGGER.info("http %s", fmt % args)

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        super().end_headers()

    def valid_host(self) -> bool:
        host = self.headers.get("Host", "").lower()
        port = self.server.server_address[1]
        return host in {f"127.0.0.1:{port}", f"localhost:{port}"}

    def valid_origin(self) -> bool:
        origin = self.headers.get("Origin", "").lower()
        port = self.server.server_address[1]
        return origin in {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}

    def authorized(self) -> bool:
        return secrets.compare_digest(self.headers.get("X-Nmap-Studio-Token", ""), self.server.token)

    def send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, status: int, payload: str, content_type: str = "text/plain; charset=utf-8") -> None:
        body = payload.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise ValidationError("Content-Type must be application/json")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValidationError("Invalid Content-Length") from exc
        if length <= 0 or length > MAX_BODY_BYTES:
            raise ValidationError("Request body is empty or too large")
        try:
            value = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError("Invalid JSON") from exc
        if not isinstance(value, dict):
            raise ValidationError("JSON body must be an object")
        return value

    def do_GET(self) -> None:
        if not self.valid_host():
            self.send_json(403, {"error": "Invalid Host header"})
            return
        parsed = urlsplit(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if path == "/api/status":
            tools = all_tool_status()
            self.send_json(200, {"ok": True, "version": VERSION, "token": self.server.token, "tools": tools, "safeModeDefault": True})
            return
        if path == "/api/jobs":
            if not self.authorized():
                self.send_json(403, {"error": "Invalid session token"})
                return
            self.send_json(200, {"jobs": JOBS.list()})
            return
        if path.startswith("/api/workspace/") or path in {"/api/enrichment/status", "/api/export"}:
            if not self.authorized():
                self.send_json(403, {"error": "Invalid session token"})
                return
            if path == "/api/workspace/summary":
                self.send_json(200, WORKSPACE.summary())
            elif path == "/api/workspace/assets":
                self.send_json(200, {"assets": WORKSPACE.assets((query.get("q") or [""])[0])})
            elif path == "/api/workspace/findings":
                self.send_json(200, {"findings": WORKSPACE.findings()})
            elif path == "/api/workspace/alerts":
                self.send_json(200, {"alerts": WORKSPACE.alerts()})
            elif path == "/api/workspace/schedules":
                self.send_json(200, {"schedules": WORKSPACE.schedules()})
            elif path == "/api/workspace/scopes":
                self.send_json(200, {"scopes": WORKSPACE.scopes()})
            elif path == "/api/workspace/audit":
                self.send_json(200, {"entries": WORKSPACE.audit_entries(), "verification": WORKSPACE.verify_audit()})
            elif path == "/api/enrichment/status":
                self.send_json(200, dict(INTELLIGENCE_STATE))
            elif path == "/api/export":
                format_name = (query.get("format") or ["json"])[0]
                if format_name not in {"json", "sarif", "splunk", "defectdojo"}:
                    self.send_json(400, {"error": "Unknown export format"})
                    return
                content_type, payload = WORKSPACE.export(format_name)
                WORKSPACE.audit("integration.export", {"format": format_name})
                self.send_text(200, payload, content_type + "; charset=utf-8")
            else:
                self.send_json(404, {"error": "Not found"})
            return
        if path.startswith("/api/jobs/"):
            if not self.authorized():
                self.send_json(403, {"error": "Invalid session token"})
                return
            job = JOBS.get(path.rsplit("/", 1)[-1])
            self.send_json(200, job.snapshot()) if job else self.send_json(404, {"error": "Job not found"})
            return
        if path.startswith("/api/help/"):
            if not self.authorized():
                self.send_json(403, {"error": "Invalid session token"})
                return
            tool = unquote(path.rsplit("/", 1)[-1])
            try:
                completed = subprocess.run(resolve_command(tool) + ["--help"], capture_output=True, text=True, timeout=8, cwd=ROOT)
                self.send_text(200, (completed.stdout or completed.stderr)[:500_000])
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        if path == "/api/scripts":
            if not self.authorized():
                self.send_json(403, {"error": "Invalid session token"})
                return
            self.send_json(200, {"scripts": discover_scripts()})
            return
        if path == "/api/diagnostics":
            if not self.authorized():
                self.send_json(403, {"error": "Invalid session token"})
                return
            self.send_text(200, log_tail())
            return
        super().do_GET()

    def do_POST(self) -> None:
        if not self.valid_host() or not self.valid_origin() or not self.authorized():
            self.send_json(403, {"error": "Request origin or session token was rejected"})
            return
        try:
            body = self.read_json()
            path = urlsplit(self.path).path
            if path == "/api/run":
                tool = body.get("tool")
                safe_mode = body.get("safeMode", True)
                args = validate_args(tool, body.get("args"), safe_mode, body.get("confirmAdvanced"))
                name = body.get("name", "")
                project = body.get("project", "")
                if not isinstance(name, str) or len(name.strip()) > 80:
                    raise ValidationError("Scan name must be 80 characters or fewer")
                if not isinstance(project, str) or len(project.strip()) > 80:
                    raise ValidationError("Project name must be 80 characters or fewer")
                project = project.strip() or "Default"
                preview = scope_preview(project, tool, args)
                if not preview["allowed"]:
                    WORKSPACE.audit("scope.rejected", {"project": project, "targets": preview["rejected"], "tool": tool})
                    raise ValidationError("Targets outside the active project scope: " + ", ".join(preview["rejected"][:5]))
                job = Job(tool, args, safe_mode is not False, name.strip(), project)
                JOBS.add(job)
                WORKSPACE.audit("scan.queued", {"jobId": job.id, "name": job.name, "project": project, "tool": tool, "safeMode": job.safe_mode, "targets": preview["targets"], "intensity": preview["intensity"]})
                self.send_json(202, {"id": job.id, "state": job.state})
                return
            if path == "/api/scope/preview":
                tool = body.get("tool")
                args = validate_args(tool, body.get("args"), body.get("safeMode", True), body.get("confirmAdvanced"))
                project = str(body.get("project", "Default"))[:80] or "Default"
                self.send_json(200, scope_preview(project, tool, args))
                return
            if path == "/api/workspace/asset":
                WORKSPACE.update_asset(int(body.get("id")), str(body.get("owner", "")), str(body.get("criticality", "medium")), body.get("tags") if isinstance(body.get("tags"), list) else [])
                self.send_json(200, {"ok": True})
                return
            if path == "/api/workspace/finding":
                WORKSPACE.update_finding(int(body.get("id")), str(body.get("status", "open")), str(body.get("assignee", "")), str(body.get("dueDate", "")), str(body.get("notes", "")))
                self.send_json(200, {"ok": True})
                return
            if path == "/api/workspace/alert":
                WORKSPACE.acknowledge_alert(int(body.get("id")))
                self.send_json(200, {"ok": True})
                return
            if path == "/api/workspace/schedule":
                tool = body.get("tool")
                args = validate_args(tool, body.get("args"), True, False)
                project = str(body.get("project", "Default"))[:80] or "Default"
                preview = scope_preview(project, tool, args)
                if not preview["allowed"]:
                    raise ValidationError("Scheduled targets are outside the active project scope")
                result = WORKSPACE.add_schedule(str(body.get("name", "Scheduled scan")), project, tool, args, int(body.get("intervalMinutes", 1440)), True)
                self.send_json(201, result)
                return
            if path == "/api/workspace/schedule-state":
                WORKSPACE.set_schedule(int(body.get("id")), bool(body.get("enabled")))
                self.send_json(200, {"ok": True})
                return
            if path == "/api/workspace/scope":
                result = WORKSPACE.add_scope_rule(str(body.get("project", "")), str(body.get("pattern", "")), str(body.get("action", "allow")), str(body.get("authorizationRef", "")), str(body.get("expires", "")))
                self.send_json(201, result)
                return
            if path == "/api/workspace/scope-state":
                WORKSPACE.deactivate_scope(int(body.get("id")))
                self.send_json(200, {"ok": True})
                return
            if path == "/api/enrichment/refresh":
                if body.get("confirmExternal") is not True:
                    raise ValidationError("External intelligence lookup must be explicitly confirmed")
                start_intelligence_refresh()
                self.send_json(202, dict(INTELLIGENCE_STATE))
                return
            if path == "/api/stop":
                job_id = body.get("id")
                if not isinstance(job_id, str):
                    raise ValidationError("id is required")
                job = JOBS.get(job_id)
                if not job:
                    self.send_json(404, {"error": "Job not found"})
                    return
                JOBS.cancel(job)
                WORKSPACE.audit("scan.cancelled", {"jobId": job.id, "project": job.project})
                self.send_json(200, {"ok": True})
                return
            if path == "/api/input":
                job = JOBS.get(body.get("id", ""))
                value = body.get("data")
                if not job or not isinstance(value, str) or len(value.encode("utf-8")) > 65536:
                    raise ValidationError("Invalid job or input")
                with job._lock:
                    if not job.process or not job.process.stdin:
                        raise ValidationError("The process is not accepting input")
                    if body.get("eof") is True:
                        job.process.stdin.close()
                    else:
                        job.process.stdin.write(value.encode("utf-8"))
                        job.process.stdin.flush()
                self.send_json(200, {"ok": True})
                return
            if path == "/api/shutdown":
                self.server.shutdown_requested = True
                WORKSPACE.audit("runner.shutdown", {})
                self.send_json(200, {"ok": True})
                def shutdown_runner() -> None:
                    for active_job in JOBS.active():
                        JOBS.cancel(active_job)
                    self.server.shutdown()
                threading.Thread(target=shutdown_runner, daemon=True).start()
                return
            self.send_json(404, {"error": "Not found"})
        except (ValidationError, ValueError, TypeError) as exc:
            self.send_json(400, {"error": str(exc)})
        except Exception:
            LOGGER.exception("Unhandled request failure")
            self.send_json(500, {"error": "Internal server error; download diagnostics for details"})


def create_server(port: int = DEFAULT_PORT) -> StudioServer:
    return StudioServer(("127.0.0.1", port))


def main() -> None:
    no_browser = "--no-browser" in sys.argv
    server = create_server(DEFAULT_PORT)
    SCHEDULER.start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    LOGGER.info("Nmap Studio %s starting at %s", VERSION, url)
    print(f"Nmap Studio {VERSION} is running at {url}")
    if not no_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        SCHEDULER.stop()
        for active_job in JOBS.active():
            JOBS.cancel(active_job)
        server.server_close()
        LOGGER.info("Nmap Studio stopped")


if __name__ == "__main__":
    main()
