# Architecture

Nmap Studio is deliberately local-first. The browser interface and Python runner share the loopback boundary; scan processes inherit only the permissions of the account that started the runner.

![Nmap Studio architecture](architecture.svg)

## Request flow

1. The browser builds a command as an argument array, never as a shell string.
2. The runner validates the session token, Host, Origin, request size, tool, and arguments.
3. Safe mode applies an option allowlist and checks NSE scripts against installed metadata. Advanced mode requires an explicit browser confirmation and API flag.
4. The queue permits two running jobs and keeps additional jobs bounded.
5. The runner launches the selected Nmap suite executable without a command shell.
6. Output, progress, and parsed Nmap XML are retained in memory within fixed limits and returned to the local browser.

## Trust boundaries

- **Browser storage:** profiles and optional history stay in the browser. History is off by default.
- **Loopback API:** the server binds to `127.0.0.1`, rejects untrusted Host and Origin values, requires a random session token for mutations, and emits a restrictive Content Security Policy.
- **Process boundary:** arguments are passed as an array with `shell=False`. Process cancellation terminates the process tree where the operating system supports it.
- **Filesystem:** reports and rotating diagnostics are local under `.nmap-studio/`; Git ignores that directory.
- **Network:** Nmap traffic goes directly from the local process to targets selected by the operator. Nmap Studio has no hosted scan service.

## Main modules

| Module | Responsibility |
| --- | --- |
| `server.py` | Local HTTP API, validation, job queue, process lifecycle, XML parsing, diagnostics |
| `dist/app.js` | UI state, tool builders, scan manager, results dashboard, NSE library |
| `dist/core.js` | Pure result filtering, comparison, and export functions |
| `dist/catalog.js` | Human-readable tool and script descriptions |
| `tests/` | API security, lifecycle, frontend policy, comparison, and export tests |

## Limits

This architecture reduces accidental command injection and unsafe defaults; it does not make an unauthorized scan acceptable or remove the risks of powerful Nmap options. Do not expose the runner through a reverse proxy, port forward, or public host.
