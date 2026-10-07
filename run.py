#!/usr/bin/env python3
"""
Post-Quantum DAG Blockchain for Vehicular Sensor Networks
Proposal-stage proof of concept.

    python run.py                 # start the dashboard on http://127.0.0.1:8000
    python run.py --port 8080
    python run.py --no-browser
    python run.py --headless      # run every experiment and write evidence/report.json

Only dependency: a post-quantum library (see requirements.txt). Without one the
prototype still runs, on a clearly-labelled classical fallback.
"""

import argparse
import json
import sys
from pathlib import Path


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--headless", action="store_true",
                    help="run all experiments in the terminal and save a report")
    args = ap.parse_args()

    from pqdag import benchmarks, crypto, experiment
    from pqdag.simulation import SIM

    if not args.headless:
        from pqdag.webapp import serve
        serve(port=args.port, open_browser=not args.no_browser)
        return

    # ---------------- headless evidence run ----------------
    import time

    info = crypto.backend_info()
    print(f"\nBackend: {info['backend']}  ({info['kem_name']} / {info['sig_name']})")
    if not info["post_quantum"]:
        print("WARNING: classical fallback - results are not post-quantum.")

    print("\n[1/4] Building network and running the pipeline...")
    setup = SIM.build(n_gateways=3, sensors_per_gateway=4, difficulty=13, t=3)
    SIM.set_traffic(True, 3.0)
    time.sleep(15)
    SIM.set_traffic(False)
    time.sleep(1)
    pipeline = SIM.snapshot()["stats"]
    print(f"      {pipeline['total']} transactions, {pipeline['finalized']} finalised, "
          f"{pipeline['rejected']} rejected")

    print("[2/4] Adversarial checks...")
    checks = SIM.run_security_checks()
    print(f"      {sum(1 for c in checks if c['pass'])}/{len(checks)} rejected as designed")

    print("[3/4] Cryptographic benchmark...")
    bench = benchmarks.run(15)
    s = bench["summary"]
    print(f"      handshake {s['pq_handshake_wire_bytes']} B post-quantum vs "
          f"{s['classical_handshake_wire_bytes']} B classical "
          f"({s['wire_overhead_factor']}x)")

    print("[4/4] DAG versus linear chain...")
    exp = experiment.run(n_gateways=4, tx_per_gateway=6, difficulty=14, t=3)
    print(f"      DAG {exp['dag']['entries_per_s']}/s vs linear "
          f"{exp['linear']['entries_per_s']}/s  ->  {exp['speedup']}x "
          f"on {exp['parameters']['cpu_cores']} cores")

    SIM.stop()

    out = Path(__file__).parent / "evidence" / "report.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({
        "backend": info, "setup": setup, "pipeline": pipeline,
        "security_checks": checks, "benchmark": bench, "experiment": exp,
    }, indent=2))
    print(f"\nEvidence written to {out}\n")


if __name__ == "__main__":
    sys.exit(main())
