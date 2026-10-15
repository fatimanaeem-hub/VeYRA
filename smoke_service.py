#!/usr/bin/env python3
"""
CI smoke test: start gateway_service.py, drive it, and check the result.

    python ci/smoke_service.py fake  --duration 150
    python ci/smoke_service.py sumo  --duration 150 --sumocfg veins_veyra/simulations/erlangen.sumo.cfg

"fake" drives the service with fake_omnet.py (a straight road, no SUMO needed).
"sumo" drives it with sumo_driver.py (real Erlangen traffic, headless SUMO).

The test fails (exit code 1) if:
  * the service does not start, crashes, or does not shut down by itself,
  * the driver reports a failed attack check (exit code != 0),
  * the service did not write summary.json,
  * bc_id.json exists (iterations from 3b-bcid on) and its hash chain or
    inclusion proofs do not verify.

A short report is appended to the GitHub job summary when run in Actions.
Works on Linux and Windows.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


def summary(lines: list[str]) -> None:
    """Append Markdown to the GitHub Actions job summary (no-op elsewhere)."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("driver", choices=["fake", "sumo"])
    ap.add_argument("--duration", type=float, default=150.0, help="simulated seconds (default 150)")
    ap.add_argument("--vehicles", type=int, default=None,
                    help="vehicles (default: 12 for fake, 20 for sumo)")
    ap.add_argument("--ports", default="9001,9002,9003")
    ap.add_argument("--sumocfg", default=None, help="SUMO config for the sumo driver")
    ap.add_argument("--out", default="results/ci", help="where the service writes its run folder")
    ap.add_argument("--timeout", type=float, default=1200.0, help="wall-clock limit for the driver (s)")
    args = ap.parse_args()

    vehicles = args.vehicles or (12 if args.driver == "fake" else 20)
    ports = [int(p) for p in args.ports.split(",")]
    out = (ROOT / args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    busy = [p for p in ports if port_open(p)]
    if busy:
        print(f"Port(s) {busy} already in use.")
        return 1

    before = set(out.glob("run-*"))
    py = sys.executable
    env = {**os.environ, "PYTHONUNBUFFERED": "1", "PYTHONIOENCODING": "utf-8"}

    svc_log_path = out / f"service-{args.driver}.log"
    svc_log = open(svc_log_path, "w", encoding="utf-8")
    svc_cmd = [py, "gateway_service.py", "--quiet", "--vehicles", str(vehicles),
               "--ports", args.ports, "--out", str(out)]
    if '"--seed"' in (ROOT / "gateway_service.py").read_text(encoding="utf-8"):
        svc_cmd += ["--seed", "1"]              # iterations before 3a have no --seed
    svc = subprocess.Popen(svc_cmd,
                           cwd=ROOT, stdout=svc_log, stderr=subprocess.STDOUT, env=env)
    t_end = time.time() + 90
    while time.time() < t_end and not all(port_open(p) for p in ports):
        if svc.poll() is not None:
            break
        time.sleep(0.3)
    if not all(port_open(p) for p in ports):
        svc.kill()
        svc_log.close()
        print(svc_log_path.read_text(encoding="utf-8")[-3000:])
        print("FAIL: the gateway service did not start")
        return 1
    print(f"Gateway service up on ports {args.ports} ({vehicles} vehicles)", flush=True)

    if args.driver == "fake":
        cmd = [py, "fake_omnet.py", "--duration", str(args.duration), "--vehicles", str(vehicles),
               "--ports", args.ports]
    else:
        cmd = [py, "sumo_driver.py", "--duration", str(args.duration), "--max-vehicles", str(vehicles),
               "--ports", args.ports, "--out", str(out)]
        if args.sumocfg:
            cmd += ["--sumocfg", str(Path(args.sumocfg).resolve())]
    print("Driver:", " ".join(cmd), flush=True)

    t0 = time.time()
    try:
        drv = subprocess.run(cmd, cwd=ROOT, env=env, timeout=args.timeout,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                             encoding="utf-8", errors="replace")
        drv_out, rc = drv.stdout, drv.returncode
    except subprocess.TimeoutExpired as e:
        drv_out, rc = (e.stdout or b"").decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or ""), -1
        drv_out += f"\nDriver timed out after {args.timeout:.0f} s"
    wall = time.time() - t0
    print(drv_out)
    (out / f"driver-{args.driver}.log").write_text(drv_out, encoding="utf-8")

    try:
        svc_rc = svc.wait(timeout=120)
    except subprocess.TimeoutExpired:
        svc.kill()
        svc_rc = "did not stop"
    svc_log.close()

    failures = []
    if rc != 0:
        failures.append(f"driver exit code {rc} (an attack check failed or it crashed)")
    if svc_rc != 0:
        failures.append(f"gateway service exit code {svc_rc}")
        print(svc_log_path.read_text(encoding="utf-8")[-3000:])

    new = sorted(set(out.glob("run-*")) - before)
    run = new[-1] if new else None
    if not run or not (run / "summary.json").exists():
        failures.append("the service did not write summary.json")

    reg_line = "not exported by this iteration"
    if run and (run / "bc_id.json").exists():
        reg = json.loads((run / "bc_id.json").read_text(encoding="utf-8"))
        n = len(reg.get("identities", []))
        valid = reg.get("chain_valid")
        proofs = reg.get("inclusion_proofs_valid")
        reg_line = f"{n} identities, chain_valid={valid}, inclusion proofs {proofs}"
        if valid is not True:
            failures.append("bc_id.json: hash chain does not verify")
        if isinstance(proofs, str) and "/" in proofs:
            ok, total = proofs.split("/")
            if ok != total:
                failures.append(f"bc_id.json: only {proofs} inclusion proofs verify")

    checks = [ln.strip() for ln in drv_out.splitlines()
              if ln.rstrip().endswith(")") and (" PASS " in ln or " FAIL " in ln or " SKIP " in ln)]
    malicious = next((ln.strip() for ln in drv_out.splitlines() if "Malicious readings" in ln), "")

    print("=" * 70)
    print(f"  Smoke test ({args.driver}): {args.duration:.0f} sim s in {wall:.0f} s wall clock")
    print(f"  Registration record: {reg_line}")
    print(f"  Run folder: {run}")
    for f in failures:
        print(f"  FAIL: {f}")
    print("  RESULT:", "PASS" if not failures else "FAIL")
    print("=" * 70)

    summary([f"### Gateway service + {'fake_omnet.py' if args.driver == 'fake' else 'sumo_driver.py (SUMO)'}"
             f" — {'✅ pass' if not failures else '❌ fail'}",
             f"{args.duration:.0f} simulated s, {vehicles} vehicles, {wall:.0f} s wall clock", "",
             "```", *checks, malicious, f"Registration record: {reg_line}", "```",
             *[f"- ❌ {f}" for f in failures], ""])
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
