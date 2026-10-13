"""
Dashboard server.

Deliberately built on Python's standard library only, so the prototype starts
on any machine with `python run.py` and nothing else. The single external
dependency of the project is the post-quantum library itself.
"""

from __future__ import annotations

import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import benchmarks, crypto, experiment, ledger
from .simulation import SIM

STATIC = Path(__file__).parent / "static"

# background job slots
JOBS: dict[str, dict] = {
    "benchmark": {"status": "idle", "result": None},
    "experiment": {"status": "idle", "result": None},
}


def _run_job(name: str, fn, *args, **kwargs):
    JOBS[name] = {"status": "running", "result": None}

    def worker():
        try:
            JOBS[name] = {"status": "done", "result": fn(*args, **kwargs)}
        except Exception as e:  # surfaced in the UI rather than swallowed
            JOBS[name] = {"status": "error", "result": {"error": str(e)}}

    threading.Thread(target=worker, daemon=True).start()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):  # keep the console readable during a demo
        pass

    # ---------------- helpers ----------------
    def _send(self, obj, code=200, ctype="application/json"):
        body = json.dumps(obj).encode() if ctype == "application/json" else obj
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    # ---------------- routes ----------------
    def do_GET(self):
        try:
            return self._get()
        except Exception as e:
            return self._send({"error": f"{type(e).__name__}: {e}"}, 500)

    def do_POST(self):
        try:
            return self._post()
        except Exception as e:
            # A failing action must report itself, not kill the request thread
            # and leave a button looking dead.
            return self._send({"error": f"{type(e).__name__}: {e}"}, 500)

    def _get(self):
        if self.path in ("/", "/index.html"):
            html = (STATIC / "index.html").read_bytes()
            return self._send(html, ctype="text/html; charset=utf-8")
        if self.path == "/api/backend":
            return self._send(crypto.backend_info())
        if self.path == "/api/state":
            return self._send(SIM.snapshot())
        if self.path == "/api/ft-table":
            return self._send({
                "min_nodes": ledger.MIN_NODES, "max_nodes": ledger.MAX_NODES,
                "rows": [
                    {"lo": max(lo, ledger.MIN_NODES), "hi": hi, "ft": ft,
                     "band": band, "paper_range": pr}
                    for lo, hi, ft, band, pr in ledger.FT_TABLE
                ],
                "paper_rows": [
                    {"lo": lo, "hi": hi, "ft": ft, "band": band}
                    for lo, hi, ft, band in ledger.PAPER_FT_TABLE
                ],
            })
        if self.path.startswith("/api/job/"):
            return self._send(JOBS.get(self.path.rsplit("/", 1)[-1],
                                       {"status": "unknown"}))
        return self._send({"error": "not found"}, 404)

    def _post(self):
        try:
            b = self._body()
        except Exception:
            b = {}

        if self.path == "/api/build":
            # No "ft" here on purpose: the finalisation threshold is derived
            # from network size (Table III), not accepted from the client.
            return self._send(SIM.build(
                n_gateways=int(b.get("gateways", 3)),
                sensors_per_gateway=int(b.get("sensors_per_gateway", 4)),
                difficulty=int(b.get("difficulty", 13)),
                t=int(b.get("t", 3)),
                # Registration mode IS the client's to choose - unlike FT, it is
                # a deployment decision rather than a value the paper derives.
                batch_registration=bool(b.get("batch_registration", False)),
            ))
        if self.path == "/api/reading":
            return self._send(SIM.submit_reading(b["sensor"], float(b["value"])))
        if self.path == "/api/publish":
            gid = b.get("gateway")
            return self._send({"results": SIM.publish_all()} if not gid
                              else SIM.publish(gid))
        if self.path == "/api/traffic":
            return self._send(SIM.set_traffic(bool(b.get("on")),
                                              float(b.get("rate", 2.0))))
        if self.path == "/api/security":
            return self._send({"checks": SIM.run_security_checks()})
        if self.path == "/api/benchmark":
            _run_job("benchmark", benchmarks.run, int(b.get("repeats", 15)))
            return self._send({"status": "running"})
        if self.path == "/api/experiment":
            _run_job("experiment", experiment.run,
                     n_gateways=int(b.get("gateways", 4)),
                     tx_per_gateway=int(b.get("tx_per_gateway", 6)),
                     difficulty=int(b.get("difficulty", 14)),
                     t=int(b.get("t", 3)))
            return self._send({"status": "running"})
        return self._send({"error": "not found"}, 404)


def serve(port: int = 8000, open_browser: bool = True):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    info = crypto.backend_info()
    print("=" * 68)
    print("  Post-Quantum DAG Blockchain for VSN - Proof of Concept")
    print("=" * 68)
    print(f"  Crypto backend : {info['backend']}")
    print(f"  KEM            : {info['kem_name']}  "
          f"(pk {info['kem_public_bytes']} B, ct {info['kem_ciphertext_bytes']} B)")
    print(f"  Signature      : {info['sig_name']}  "
          f"(sig {info['signature_bytes']} B)")
    print(f"  Symmetric      : {info['symmetric']}")
    if not info["post_quantum"]:
        print("  !! WARNING: running the CLASSICAL fallback - not post-quantum.")
        print("  !! Install requirements.txt for real post-quantum results.")
    print("-" * 68)
    print(f"  Dashboard      : http://127.0.0.1:{port}")
    print("  Press Ctrl+C to stop.")
    print("=" * 68)
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(f"http://127.0.0.1:{port}")).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        SIM.stop()
