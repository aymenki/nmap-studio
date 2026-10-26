# Nmap Studio

Nmap Studio is a local browser interface for Nmap, Ncat, Nping, and Ndiff. It turns common network tasks into guided forms, manages concurrent scans, and converts Nmap XML into searchable, comparable results.

![Nmap Studio product demo](docs/demo.gif)

> Use Nmap Studio only on systems you own or have explicit permission to test.

## Highlights

- Run all four Nmap suite tools inside the UI.
- Organize named scans by project and follow queue position, stage, elapsed time, and progress.
- Normalize website URLs to hostnames before scanning.
- Stream output, send process input, cancel a process tree, and stop the runner.
- Search and sort structured results, compare scans, and export JSON, CSV, or HTML.
- Discover installed NSE scripts and classify higher-risk categories before execution.
- Build simple NSE arguments as guided key/value fields.
- Discover installed tool versions, executable paths, and CLI help.
- Start in Safe mode with a server-side option allowlist. Advanced mode requires explicit confirmation.
- Save reusable profiles and import/export them as JSON.
- Keep scan history off by default; enable it locally or clear it at any time.
- Download rotating diagnostic logs from Settings.
- Use a dependency-free Python server on Windows, macOS, or Linux.

## Install and run

Requirements:

- Python 3.10 or newer
- The [official Nmap suite](https://nmap.org/download.html), with its executables on PATH

Clone or download this repository, then run:

~~~bash
python server.py
~~~

The app opens at http://127.0.0.1:8765. Keep the terminal open and press Ctrl+C to stop it. On Windows, double-click start.cmd; use stop.cmd or Settings → Stop local runner when finished.

Set NMAP_STUDIO_PORT before starting if port 8765 is already in use.

## Execution modes

Safe mode accepts common scan, discovery, timing, service, OS, connection, and probe options. It rejects listeners, output path overrides, higher-risk NSE categories, complex script arguments, and uncommon raw options.

For NSE, Safe mode accepts exact installed script names from lower-risk categories and simple `key=value` arguments. Scripts in categories such as `brute`, `dos`, `exploit`, `external`, `fuzzer`, `intrusive`, `malware`, or `vuln` require Advanced mode. The classification is a guardrail, not a guarantee: read each script's documentation and obtain permission before running it.

Turn off Safe mode to use the complete installed command line. The UI asks for confirmation and the server also requires an explicit advanced-mode flag. Commands are created as argument arrays and launched without a shell, so shell operators and expansion are never evaluated.

Raw packet scans, OS detection, and some probe modes may need administrator or root privileges. Start with ordinary user permissions and elevate only for a task that requires it.

## Privacy and data

The runner binds only to loopback. It validates Host and Origin, requires a random session token, sends no CORS headers, applies a strict Content Security Policy, limits requests and output, and retains at most 20 completed jobs for 24 hours in memory.

Nmap Studio does not send scan data to a hosted service. Browser history persistence is disabled by default. Profiles and enabled history are stored in the browser. Reports and rotating diagnostic logs are stored under .nmap-studio/, which Git ignores.

Imported XML is limited to 10 MB, 2,000 hosts, and 50,000 ports. Automatic report parsing rejects XML document types.

## Development

Run the checks with:

~~~bash
python -m unittest discover -s tests -v
python -m py_compile server.py launch.py
node --check dist/app.js
node --check dist/core.js
node tests/test_core.js
~~~

Build the release archive and checksum with:

~~~bash
python scripts/build_release.py
~~~

See the [architecture](docs/ARCHITECTURE.md), [roadmap](docs/ROADMAP.md), [contribution guide](CONTRIBUTING.md), and [security policy](SECURITY.md).

## How it is built

The Python runner binds to loopback, validates and queues requests, then starts Nmap suite processes without a command shell. The browser receives live job state and structured reports through a token-protected local API. See the [architecture diagram](docs/ARCHITECTURE.md) for the trust boundaries and data flow.

## Project scope

Nmap Studio is an independent interface and is not an official Nmap project. Nmap and its related tools remain subject to their own license; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and [NMAP-LICENSE.txt](NMAP-LICENSE.txt). Nmap Studio's original code is released under the [MIT License](LICENSE).
