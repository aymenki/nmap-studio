"""Start or stop Nmap Studio without hiding startup errors."""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser

ROOT = pathlib.Path(__file__).resolve().parent
DATA_DIR = ROOT / ".nmap-studio"
LOG_DIR = DATA_DIR / "logs"
PORT = int(os.environ.get("NMAP_STUDIO_PORT", "8765"))
URL = f"http://127.0.0.1:{PORT}"


def status() -> dict | None:
    try:
        request = urllib.request.Request(URL + "/api/status")
        with urllib.request.urlopen(request, timeout=2) as response:
            return json.load(response)
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        return None


def stop() -> int:
    current = status()
    if not current:
        print("Nmap Studio is not running.")
        return 0
    token = current.get("token", "")
    request = urllib.request.Request(
        URL + "/api/shutdown",
        data=b"{}",
        headers={
            "Content-Type": "application/json",
            "Origin": URL,
            "X-Nmap-Studio-Token": token,
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=4):
        pass
    print("Nmap Studio stopped.")
    return 0


def start() -> int:
    current = status()
    if not current:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_path = LOG_DIR / "launcher.log"
        executable = pathlib.Path(sys.executable)
        if os.name == "nt" and executable.with_name("pythonw.exe").exists():
            executable = executable.with_name("pythonw.exe")
        log_handle = log_path.open("a", encoding="utf-8")
        subprocess.Popen(
            [str(executable), str(ROOT / "server.py"), "--no-browser"],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=log_handle,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            start_new_session=os.name != "nt",
        )
        for _ in range(40):
            time.sleep(0.25)
            current = status()
            if current:
                break
        if not current:
            print(f"Nmap Studio did not start. Check {log_path}", file=sys.stderr)
            return 1
    webbrowser.open(URL)
    print(f"Nmap Studio is ready at {URL}")
    return 0


if __name__ == "__main__":
    raise SystemExit(stop() if "--stop" in sys.argv else start())
