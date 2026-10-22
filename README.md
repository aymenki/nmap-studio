# Nmap Studio

**Prototype release:** local-only execution. Do not expose this runner on a public interface. Advanced arguments run with your account permissions. This version has not completed the proposed release-hardening review.

A local browser interface for Nmap, Ncat, Nping, and Ndiff. Includes scan presets, live output and process input, cancellation, browser-local profiles/history, XML host/port inspection, 612 indexed NSE scripts, and CLI help captured from Nmap 7.99.

## Run

Install Python 3.10+ and the official Nmap suite (https://nmap.org/download.html). Put the Nmap executables on PATH. From this folder run:

```powershell
python server.py
```

On Windows, double-click start.cmd to launch the runner in the background and open the UI. Closing the browser does not stop that background runner; it remains available until its Python process exits or Windows restarts. The page automatically reconnects after a runner restart.

When using python server.py directly, the UI opens at http://127.0.0.1:8765. Keep the terminal running. Press Ctrl+C to stop the server and its jobs. Set NMAP_STUDIO_PORT to use another port. No Python packages are required.

The hosted site is a command builder and report viewer. It cannot execute raw network tools; download and run this local app for execution. It does not connect remotely to your local runner.

## Features and scope

- Common Nmap options have form controls. The Advanced JSON argument array accepts all CLI arguments supported by the installed tools, including options without dedicated controls. The UI launches argument lists directly, without a command shell.
- The Script library adds script names to the builder; scripts execute from your Nmap installation. The bundled catalog is a snapshot of 612 scripts, not an auto-updating feed.
- For XML reports add ["-oX", "C:/scans/report.xml"] under Advanced. Import the resulting report in Scan results. That viewer shows host state and port/service inventory; full NSE and OS details remain in the exported report/output.
- Ncat supports stdin messages and EOF from the output panel. Advanced arguments cover proxy, TLS, listener, and other options.
- Nping supports common protocols plus all other CLI arguments. Raw probes and some Nmap scan modes require administrator/root privileges and appropriate capture drivers. Start the runner with those privileges only when needed.
- Ndiff uses two local XML paths. On Windows the runner uses the installed ndiff.py with Python; platforms with an ndiff executable use PATH.
- Profiles and the last 20 completed outputs persist in this browser. They may contain sensitive network data. Output is capped at the most recent 2 MB per process. Jobs do not resume after a server restart.
- This is an independent interface, not an official Nmap product or a complete replacement for Zenmap's topology and every specialized visualization. All four command-line tools are accessible, while uncommon options use the advanced editor.

The server binds only to loopback, checks Host and Origin on mutations, requires a per-session token, and does not enable CORS. Keep it local. Commands run with your operating-system account's permissions and may write files specified in arguments. Use only on authorized systems.

Reference: https://github.com/nmap/nmap and https://nmap.org/book/man.html
