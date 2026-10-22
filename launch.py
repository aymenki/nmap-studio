"""Start the local runner in the background and open its UI."""
import json, os, pathlib, subprocess, sys, time, urllib.request, webbrowser
ROOT = pathlib.Path(__file__).resolve().parent
URL = 'http://127.0.0.1:' + os.environ.get('NMAP_STUDIO_PORT', '8765')
def ready():
    try:
        with urllib.request.urlopen(URL + '/api/status', timeout=1) as r:
            return bool(json.load(r).get('token'))
    except Exception:
        return False
if not ready():
    executable = pathlib.Path(sys.executable)
    if os.name == 'nt' and executable.with_name('pythonw.exe').exists():
        executable = executable.with_name('pythonw.exe')
    subprocess.Popen([str(executable), str(ROOT / 'server.py'), '--no-browser'],
                     cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL,
                     creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
                     start_new_session=os.name != 'nt')
    for _ in range(30):
        if ready(): break
        time.sleep(.2)
if not ready():
    raise SystemExit('Could not start the runner. Run python server.py for details.')
print('Local execution ready: ' + URL)
if '--no-browser' not in sys.argv: webbrowser.open(URL)
