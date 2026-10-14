#!/usr/bin/env python3
"""
Run Phase 3a configurations several times and compare them.

For every configuration and seed it starts gateway_service.py, runs the
OMNeT++ scenario without GUI, waits for both to finish, then prints the
averages per configuration.

Run it from the OMNeT++ shell (so opp_run is found), in the VEYRA folder,
with veins_launchd already running in another window:

    python run_experiments.py --configs Default ClassicalSizes --seeds 3

On Windows the OMNeT++ shell has its own Python without VEYRA's packages,
so point --python at the Python you installed requirements.txt into
(in a normal Command Prompt, `where python` shows it):

    python run_experiments.py --python C:/Users/<you>/AppData/Local/Programs/Python/Python312/python.exe

Results: results/batch-<time>/summary.csv, plus the usual omnet-run-* and
run-* folders for every single run.
"""

from __future__ import annotations

import argparse
import csv
import os
import shutil
import socket
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from analyze_omnet import analyse, load_run  # noqa: E402

# Configurations whose omnetpp.ini sets a different number of cars.
CONFIG_VEHICLES = {"AllCars": 60}

METRICS = [
    ("delivery ratio %", lambda a: (a["network"]["delivery_ratio"] or 0) * 100),
    ("handshake requests sent", lambda a: a["network"]["handshake_requests_sent"]),
    ("handshake retries", lambda a: a["network"]["handshake_retries"]),
    ("readings lost to handovers", lambda a: a["network"]["readings_not_sent_during_handover"]),
    ("time to session p50 ms", lambda a: a["network"]["time_to_session_ms"]["p50"]),
    ("time to session p95 ms", lambda a: a["network"]["time_to_session_ms"]["p95"]),
    ("air delay p95 ms", lambda a: a["network"]["air_delay_ms"]["p95"]),
    ("reading end-to-end p50 ms", lambda a: a["network"]["reading_end_to_end_ms"]["p50"]),
    ("reading end-to-end p95 ms", lambda a: a["network"]["reading_end_to_end_ms"]["p95"]),
    ("gateway tick p95 ms", lambda a: a["network"]["tick_proc_ms"]["p95"]),
    ("finality p50 s", lambda a: (a["blockchain"]["finality_s"] or {}).get("p50")),
    ("finality p95 s", lambda a: (a["blockchain"]["finality_s"] or {}).get("p95")),
    ("false readings finalised", lambda a: (a["blockchain"]["malicious_readings"] or {}).get("finalised")),
    ("attack checks passed", lambda a: sum(1 for c in a["attack_checks"] if c["result"].startswith("PASS"))),
]


def port_open(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def wait_for_ports(ports: list[int], proc: subprocess.Popen, timeout: float = 60) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return False
        if all(port_open(p) for p in ports):
            return True
        time.sleep(0.3)
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--configs", nargs="+", default=["Default", "ClassicalSizes"])
    ap.add_argument("--seeds", type=int, default=3, help="runs per configuration (seed-set 1..N)")
    ap.add_argument("--vehicles", type=int, default=20,
                    help="gateway_service.py --vehicles (default 20; AllCars uses 60)")
    ap.add_argument("--rsus", type=int, default=3, help="number of RSUs/gateways (default 3)")
    ap.add_argument("--python", default=sys.executable,
                    help="Python that has VEYRA's requirements installed (default: this one)")
    ap.add_argument("--project", default=str(HERE / "veins_veyra"))
    args = ap.parse_args()

    project = Path(args.project)
    if not (project / "out" / "veins_path").exists():
        sys.exit(f"{project} is not built yet: run ./configure and make there first.")
    if not port_open(9999):
        sys.exit("veins_launchd is not running (nothing on port 9999). Start it in another window first.")

    # Full path from PATH: on Windows a bare "bash" could start WSL's bash.exe
    # from System32 instead of the OMNeT++ shell's.
    bash = shutil.which("bash")
    if not bash:
        sys.exit("bash not found: run this from the OMNeT++ shell.")

    ports = [9001 + i for i in range(args.rsus)]
    busy = [p for p in ports if port_open(p)]
    if busy:
        sys.exit(f"Port(s) {busy} already in use: stop the gateway service that is running.")

    stamp = time.strftime("%Y%m%d-%H%M%S")
    batch = HERE / "results" / f"batch-{stamp}"
    batch.mkdir(parents=True, exist_ok=True)
    print(f"Batch folder: {batch}")

    rows = []
    by_config: dict[str, list[dict]] = {c: [] for c in args.configs}
    total = len(args.configs) * args.seeds
    n = 0
    for seed in range(1, args.seeds + 1):
        for cfg in args.configs:
            n += 1
            vehicles = CONFIG_VEHICLES.get(cfg, args.vehicles)
            tag = f"{cfg}-seed{seed}"
            print(f"[{n}/{total}] {tag}: starting gateway service ({vehicles} vehicles) ...", flush=True)
            before = set((HERE / "results").glob("omnet-run-*"))

            svc_log = open(batch / f"service-{tag}.log", "w")
            svc = subprocess.Popen([args.python, "gateway_service.py", "--vehicles", str(vehicles), "--quiet",
                                    "--ports", ",".join(map(str, ports))],
                                   cwd=HERE, stdout=svc_log, stderr=subprocess.STDOUT)
            if not wait_for_ports(ports, svc):
                svc.kill()
                svc_log.close()
                print((batch / f"service-{tag}.log").read_text()[-2000:])
                sys.exit("The gateway service did not start (log above). On Windows, pass "
                         "--python with the Python that has requirements.txt installed.")

            t0 = time.time()
            with open(batch / f"omnet-{tag}.log", "w") as olog:
                rc = subprocess.call([bash, "run", "-u", "Cmdenv", "-c", cfg, f"--seed-set={seed}"],
                                     cwd=project, stdout=olog, stderr=subprocess.STDOUT)
            try:
                svc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                svc.terminate()
                svc.wait(timeout=10)
            svc_log.close()

            new = sorted(set((HERE / "results").glob("omnet-run-*")) - before)
            if rc != 0 or not new:
                print(f"    OMNeT++ failed (exit {rc}); see {batch / f'omnet-{tag}.log'}")
                continue
            a = analyse(load_run(new[-1]))
            by_config[cfg].append(a)
            row = {"config": cfg, "seed": seed, "run": new[-1].name, "wall_s": round(time.time() - t0, 1)}
            row.update({label: fn(a) for label, fn in METRICS})
            rows.append(row)
            print(f"    done in {row['wall_s']} s -> {new[-1].name}   "
                  f"checks {row['attack checks passed']}/6, finality p50 {row['finality p50 s']} s")

    if not rows:
        return 1
    with open(batch / "runs.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    # Mean (min-max) per configuration
    print()
    print("=" * 78)
    print(f"  Mean over seeds (min - max)   [{args.seeds} seed(s) per configuration]")
    print("=" * 78)
    cfgs = [c for c in args.configs if by_config[c]]
    width = 24
    print(f"  {'':28}" + "".join(f"{c:>{width}}" for c in cfgs))
    summary = []
    for label, fn in METRICS:
        line = f"  {label:28}"
        srow = {"metric": label}
        for c in cfgs:
            vals = [fn(a) for a in by_config[c] if fn(a) is not None]
            if not vals:
                cell = "-"
            else:
                m = statistics.mean(vals)
                d = 0 if all(float(v).is_integer() for v in vals) and len(vals) == 1 else (2 if abs(m) < 10 else 1)
                cell = (f"{m:.{d}f} ({min(vals):.{d}f}-{max(vals):.{d}f})" if len(vals) > 1
                        else f"{m:.{d}f}")
                srow[c] = round(m, 3)
            line += f"{cell:>{width}}"
        print(line)
        summary.append(srow)
    with open(batch / "summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["metric"] + cfgs)
        w.writeheader()
        w.writerows(summary)
    print(f"\n  Per-run rows: {batch / 'runs.csv'}\n  Summary:      {batch / 'summary.csv'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
