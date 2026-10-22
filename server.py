"""Local-only Nmap Studio runner. Python 3.10+, no dependencies."""
import json, os, pathlib, secrets, shutil, subprocess, sys, threading, uuid, webbrowser
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
ROOT = pathlib.Path(__file__).resolve().parent
TOKEN = secrets.token_urlsafe(32)
JOBS = {}
PORT = int(os.environ.get('NMAP_STUDIO_PORT', '8765'))
def command(tool):
    if tool not in ('nmap', 'ncat', 'nping', 'ndiff'): raise ValueError('Unknown tool')
    if tool == 'ndiff':
        base = pathlib.Path(shutil.which('nmap') or '').parent
        if (base / 'ndiff.py').exists(): return [sys.executable, str(base / 'ndiff.py')]
    p = shutil.which(tool)
    if not p: raise ValueError(f'{tool} is not installed or not on PATH')
    return [p]
def run(job, tool, args):
    try:
        p = subprocess.Popen(command(tool) + args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, cwd=ROOT, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        job['process'] = p
        if job.get('cancelled'): p.terminate()
        while True:
            b = p.stdout.read1(4096)
            if not b: break
            job['output'] = (job['output'] + b.decode('utf-8', errors='replace'))[-2000000:]
        job['code'] = p.wait()
    except Exception as e: job['output'] += str(e); job['code'] = -1
    job['done'] = True
class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw): super().__init__(*a, directory=str(ROOT / 'dist'), **kw)
    def log_message(self, *a): pass
    def send_json(self, data, code=200):
        body = json.dumps(data).encode(); self.send_response(code); self.send_header('Content-Type', 'application/json'); self.send_header('Cache-Control', 'no-store'); self.end_headers(); self.wfile.write(body)
    def valid_host(self): return self.headers.get('Host') in (f'127.0.0.1:{PORT}', f'localhost:{PORT}')
    def do_GET(self):
        if not self.valid_host(): return self.send_json({'error':'Invalid host'},403)
        if self.path == '/api/status':
            tools = {}
            for t in ('nmap','ncat','nping','ndiff'):
                try: command(t); tools[t] = True
                except ValueError: tools[t] = False
            return self.send_json({'token':TOKEN, 'tools':tools})
        if self.path.startswith('/api/jobs/'):
            if self.headers.get('X-Studio-Token') != TOKEN: return self.send_json({'error':'Unauthorized'},403)
            j = JOBS.get(self.path.split('/')[-1])
            return self.send_json({k:v for k,v in j.items() if k != 'process'} if j else {'error':'Job not found'},200 if j else 404)
        return super().do_GET()
    def do_POST(self):
        if not self.valid_host() or self.headers.get('X-Studio-Token') != TOKEN or self.headers.get('Origin') not in (None,f'http://127.0.0.1:{PORT}',f'http://localhost:{PORT}'):
            return self.send_json({'error':'Unauthorized origin or token'},403)
        try:
            size = int(self.headers.get('Content-Length','0'))
            if size > 100000: raise ValueError('Request too large')
            data = json.loads(self.rfile.read(size))
            if self.path == '/api/run':
                tool, args = data['tool'], data['args']; command(tool)
                if not isinstance(args,list) or not all(isinstance(a,str) and '\0' not in a for a in args): raise ValueError('Arguments must be a string array')
                if sum(not j['done'] for j in JOBS.values()) >= 4: raise ValueError('Stop a running job first (4 job limit)')
                ident = uuid.uuid4().hex; job = {'id':ident,'tool':tool,'args':args,'output':'','done':False,'code':None}; JOBS[ident] = job
                threading.Thread(target=run,args=(job,tool,args),daemon=True).start()
                return self.send_json({'id':ident})
            job = JOBS.get(data.get('id'))
            if not job: raise ValueError('Job not found')
            p = job.get('process')
            if self.path == '/api/stop':
                job['cancelled'] = True
                if p and p.poll() is None: p.terminate()
            elif self.path == '/api/input':
                if not p or p.poll() is not None: raise ValueError('Process is not running')
                if data.get('eof'): p.stdin.close()
                else: p.stdin.write(data.get('text','').encode()); p.stdin.flush()
            else: raise ValueError('Unknown endpoint')
            self.send_json({'ok':True})
        except Exception as e: self.send_json({'error':str(e)},400)
if __name__ == '__main__':
    server = ThreadingHTTPServer(('127.0.0.1',PORT),Handler)
    print(f'Nmap Studio: http://127.0.0.1:{PORT}',flush=True)
    if '--no-browser' not in sys.argv: webbrowser.open(f'http://127.0.0.1:{PORT}')
    try: server.serve_forever()
    finally:
        for job in JOBS.values():
            p=job.get('process')
            if p and p.poll() is None: p.terminate()
