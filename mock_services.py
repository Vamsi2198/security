"""Mock services for the demo. All synthetic, no real data, no external calls.

- MockLLM (port 9100): OpenAI-compatible /v1/chat/completions, canned reply.
- SafetyWebhook (port 9200): guardrail webhook.
    mode=slow  -> sleeps longer than the gateway's webhook timeout (simulates
                  an overloaded / degraded custom safety check)
    mode=fast  -> returns verdict:true immediately
  Every call appends a receipt line to webhook_receipts.jsonl next to this file.
"""
import json
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

RECEIPTS = Path(__file__).resolve().parent / "webhook_receipts.jsonl"
_lock = threading.Lock()


def write_receipt(entry):
    entry["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with _lock:
        with open(RECEIPTS, "a") as f:
            f.write(json.dumps(entry) + "\n")


class LLMHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try:
            req = json.loads(body or b"{}")
        except json.JSONDecodeError:
            req = {}
        user_msg = ""
        for m in req.get("messages", []):
            if m.get("role") == "user":
                user_msg = m.get("content", "")
        reply = {
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": req.get("model", "mock-llm"),
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": f"[MOCK LLM] Executed request: {user_msg[:80]}",
                },
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20},
        }
        payload = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):
        pass


class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        q = parse_qs(urlparse(self.path).query)
        mode = q.get("mode", ["fast"])[0]
        action_class = q.get("action_class", ["unknown"])[0]
        source = q.get("source", ["gateway"])[0]
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))

        if mode == "slow":
            # Gateway webhook timeout is set to 1000ms; sleep well past it.
            time.sleep(5)
            verdict = True
            note = "responded AFTER gateway already timed out"
        else:
            verdict = True
            note = "responded within timeout"

        write_receipt({
            "component": "safety_webhook",
            "source": source,
            "mode": mode,
            "action_class": action_class,
            "verdict_returned": verdict,
            "note": note,
        })

        payload = json.dumps({"verdict": verdict, "data": {"mode": mode}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    llm = ThreadingHTTPServer(("127.0.0.1", 9100), LLMHandler)
    hook = ThreadingHTTPServer(("127.0.0.1", 9200), WebhookHandler)
    threading.Thread(target=llm.serve_forever, daemon=True).start()
    threading.Thread(target=hook.serve_forever, daemon=True).start()
    print("mock-llm    -> http://127.0.0.1:9100")
    print("safety-hook -> http://127.0.0.1:9200  (?mode=slow|fast)")
    threading.Event().wait()
