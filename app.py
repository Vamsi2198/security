"""Hosted wrapper around run_demo.py.

Serves a single page where a visitor can start the demo and watch the
transcript appear. The demo itself is unchanged — this is only a remote
control over the same runner used locally. Binds 0.0.0.0:$PORT (Render).
"""
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
PORT = int(os.environ.get("PORT", "10000"))

_state = {"running": False, "started": None, "finished": None,
          "output": "", "error": ""}
_run_lock = threading.Lock()

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Risk-Gate Demo</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; color: #222; }
  pre { background: #111; color: #0d0; padding: 1rem; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; min-height: 200px; }
  button { font-size: 1rem; padding: .6rem 1.2rem; border-radius: 6px; border: 0; background: #146eb4; color: #fff; cursor: pointer; }
  button:disabled { background: #999; cursor: default; }
  #status { margin-left: 1rem; color: #666; }
  h1 { font-size: 1.4rem; } p.sub { color: #666; }
</style>
</head>
<body>
<h1>Risk-Gate: when the safety check is too slow, who decides what the gate does?</h1>
<p class="sub">Synthetic, no-API-keys demo. Runs the real Portkey OSS gateway
with a degraded mock guardrail. Takes about a minute.</p>
<button id="run" onclick="startDemo()">Run demo</button><span id="status"></span>
<pre id="out">Press &quot;Run demo&quot; to start.</pre>
<script>
let timer = null;
async function startDemo() {
  document.getElementById('run').disabled = true;
  document.getElementById('status').textContent = 'starting...';
  await fetch('/run', {method: 'POST'});
  timer = setInterval(poll, 2000);
  poll();
}
async function poll() {
  const s = await (await fetch('/status')).json();
  document.getElementById('out').textContent =
    s.output || '(demo is starting — the gateway and mocks take a few seconds to come up)';
  document.getElementById('status').textContent = s.running ? 'running...' : '';
  if (!s.running && s.finished) {
    clearInterval(timer);
    document.getElementById('run').disabled = false;
    document.getElementById('status').textContent = s.error ? 'finished with errors' : 'finished';
    if (s.error) document.getElementById('out').textContent += '\n\n[errors]\n' + s.error;
  }
}
</script>
</body>
</html>"""


def run_demo():
    with _run_lock:
        _state.update(running=True, started=time.time(), finished=None,
                      output="", error="")
        try:
            p = subprocess.run([sys.executable, str(HERE / "run_demo.py")],
                               capture_output=True, text=True, timeout=900)
            t = HERE / "transcript.txt"
            _state["output"] = t.read_text() if t.exists() else p.stdout
            if p.returncode != 0:
                _state["error"] = p.stderr[-3000:]
        except Exception as e:
            _state["error"] = str(e)
        finally:
            _state.update(running=False, finished=time.time())


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
        elif self.path == "/status":
            body = json.dumps(_state).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        elif self.path == "/transcript.txt":
            t = HERE / "transcript.txt"
            body = t.read_bytes() if t.exists() else b""
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
        else:
            self.send_response(404)
            body = b"not found"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == "/run":
            if not _state["running"]:
                threading.Thread(target=run_demo, daemon=True).start()
            self.send_response(202)
            body = b"started"
        else:
            self.send_response(404)
            body = b"not found"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"demo page -> http://0.0.0.0:{PORT}")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
