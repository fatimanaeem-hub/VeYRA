#!/usr/bin/env python3
"""
Summarise a Phase 3a run (OMNeT++/Veins + gateway_service.py).

    python analyze_omnet.py                      latest results/omnet-run-*
    python analyze_omnet.py results/omnet-run-X  a specific run
    python analyze_omnet.py RUN_A RUN_B ...      side-by-side comparison

Reads, from each run folder:
    messages.csv          one row per message an RSU handled (written by OMNeT++)
    vehicles.csv          one row per car (written by OMNeT++)
    gateway_summary.json  the gateway service's own summary at the end
    run_info.json         which omnetpp.ini configuration produced it

Prints the attack checks (same six as fake_omnet.py), the network numbers
and the blockchain numbers, and writes analysis.json into the run folder.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    v = sorted(values)
    k = (len(v) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(v) - 1)
    return v[lo] + (v[hi] - v[lo]) * (k - lo)


def stats(values: list[float]) -> dict:
    if not values:
        return {"n": 0, "p50": None, "p95": None, "max": None}
    return {"n": len(values), "p50": round(pct(values, 0.5), 3),
            "p95": round(pct(values, 0.95), 3), "max": round(max(values), 3)}


def fnum(v, unit="", digits=1) -> str:
    if v is None:
        return "-"
    if isinstance(v, float):
        return f"{v:.{digits}f}{unit}"
    return f"{v}{unit}"


def load_run(run: Path) -> dict:
    msgs_path = run / "messages.csv"
    if not msgs_path.exists():
        sys.exit(f"{run} has no messages.csv - is this an omnet-run folder?")
    msgs = list(csv.DictReader(open(msgs_path, newline="")))
    vehicles = []
    if (run / "vehicles.csv").exists():
        vehicles = list(csv.DictReader(open(run / "vehicles.csv", newline="")))
    gw = {}
    if (run / "gateway_summary.json").exists():
        try:
            gw = json.loads((run / "gateway_summary.json").read_text())
        except json.JSONDecodeError:
            gw = {}
    info = {}
    if (run / "run_info.json").exists():
        info = json.loads((run / "run_info.json").read_text())
    return {"run": run, "msgs": msgs, "vehicles": vehicles, "gw": gw, "info": info}


def analyse(d: dict) -> dict:
    msgs, vehicles, gw = d["msgs"], d["vehicles"], d["gw"]
    readings = [m for m in msgs if m["type"] == "READING"]
    handshakes = [m for m in msgs if m["type"] == "HANDSHAKE"]
    ticks = [m for m in msgs if m["type"] == "TICK"]

    def isum(key):
        return sum(int(float(v[key] or 0)) for v in vehicles)

    sent = isum("readings_sent")
    from_cars = [m for m in readings if m["mode"] in ("normal", "compromised")
                 and not m["vehicle"].startswith("intruder")]
    hs_cars = [m for m in handshakes if m["mode"] == "normal"]
    acked = [m for m in readings if m["reply"] == "ack" and m["mode"] in ("normal", "compromised")]

    net = {
        "cars": len(vehicles),
        "readings_sent": sent,
        "readings_received": len(from_cars),
        "delivery_ratio": round(len(from_cars) / sent, 4) if sent else None,
        "readings_not_sent_no_coverage": isum("not_sent_no_session"),
        "readings_not_sent_during_handover": isum("not_sent_during_handshake"),
        "handshake_requests_sent": isum("handshakes_sent"),
        "handshake_requests_received": len(hs_cars),
        "handshake_retries": isum("handshake_retries"),
        "sessions": isum("sessions"),
        "handovers": isum("handovers"),
        "handshake_latency_ms": stats([float(v["handshake_latency_mean_ms"]) for v in vehicles
                                       if int(v["sessions"] or 0) > 0]),
        "handshake_latency_max_ms": max([float(v["handshake_latency_max_ms"]) for v in vehicles] or [0]),
        "time_to_session_ms": stats([float(v.get("time_to_session_mean_ms") or 0) for v in vehicles
                                     if int(v["sessions"] or 0) > 0]),
        "time_to_session_max_ms": max([float(v.get("time_to_session_max_ms") or 0) for v in vehicles] or [0]),
        "air_delay_ms": stats([float(m["air_ms"]) for m in readings if m["air_ms"]]),
        "gateway_queue_ms": stats([float(m["queue_ms"]) for m in acked]),
        "reading_end_to_end_ms": stats([float(m["end_to_end_ms"]) for m in acked if m["end_to_end_ms"]]),
        "tick_proc_ms": stats([float(m["proc_ms"]) for m in ticks]),
        "handshake_proc_ms": stats([float(m["proc_ms"]) for m in hs_cars if m["reply"] == "ok"]),
    }

    led = gw.get("ledger", {})
    chain = {
        "tx_published": led.get("total"),
        "tx_finalised": led.get("finalized"),
        "tx_pending_at_end": led.get("pending"),
        "tx_rejected": led.get("rejected"),
        "finality_s": gw.get("finality_latency_sim_s", {}),
        "server_opened": gw.get("server_opened_aggregates", {}),
        "honest_readings": gw.get("honest_readings", {}),
        "malicious_readings": gw.get("malicious_readings", {}),
        "crypto_backend": gw.get("config", {}).get("crypto_backend"),
        "FT": gw.get("config", {}).get("FT"),
    }

    # --- the six attack checks -------------------------------------------------
    def first(pred):
        return next((m for m in msgs if pred(m)), None)

    checks = []

    def check(name, expect, row, ok_reply, stage_has=None, gap=False):
        if row is None:
            checks.append({"attack": name, "expected": expect,
                           "observed": "no such message reached an RSU (attack switched off, or lost on the air)",
                           "result": "NOT SEEN"})
            return
        ok = row["reply"] == ok_reply and (stage_has is None or stage_has in row["stage"])
        observed = f"{row['reply'].upper()} {row['stage']}".strip()
        checks.append({"attack": name, "expected": expect, "observed": observed,
                       "at_s": round(float(row["sim_s"]), 1),
                       "result": ("PASS (paper gap)" if gap else "PASS") if ok else "FAIL"})

    check("Unregistered vehicle handshakes", "REJECT at Alg.2 line 10",
          first(lambda m: m["type"] == "HANDSHAKE" and m["mode"] == "unregistered"),
          "reject", "Alg.2")
    check("Unregistered vehicle sends a reading", "REJECT at session lookup",
          first(lambda m: m["type"] == "READING" and m["vehicle"].startswith("intruder")),
          "reject", "session")
    check("Reading with one flipped bit", "REJECT at AEAD",
          first(lambda m: m["type"] == "READING" and m["mode"] == "tamper"), "reject", "AEAD")
    check("Captured reading replayed inside window", "ACCEPTED (no duplicate check)",
          first(lambda m: m["type"] == "READING" and m["mode"] == "replay_fresh"), "ack", gap=True)
    check("Captured reading replayed >120 s later", "REJECT at freshness",
          first(lambda m: m["type"] == "READING" and m["mode"] == "replay_old"), "reject", "freshness")

    bad = gw.get("malicious_readings", {})
    comp = [m for m in readings if m["mode"] == "compromised"]
    if not comp:
        checks.append({"attack": "Compromised vehicle reports 250+ km/h",
                       "expected": "ACCEPTED and finalised", "observed": "no false readings sent",
                       "result": "NOT RUN"})
    else:
        acc = sum(1 for m in comp if m["reply"] == "ack")
        fin = bad.get("finalised", 0)
        checks.append({"attack": "Compromised vehicle reports 250+ km/h",
                       "expected": "ACCEPTED and finalised",
                       "observed": f"{acc}/{len(comp)} accepted, {fin} finalised",
                       "at_s": round(float(comp[0]["sim_s"]), 1),
                       "result": "PASS (the gap)" if acc and fin else "FAIL"})

    return {"run": d["run"].name, "config": d["info"].get("config", "?"), "network": net,
            "blockchain": chain, "attack_checks": checks}


def print_one(a: dict) -> None:
    n, c = a["network"], a["blockchain"]
    print("=" * 78)
    print(f"  {a['run']}   (config: {a['config']}, crypto: {c['crypto_backend']}, FT {c['FT']})")
    print("=" * 78)

    print("\n  Attack checks")
    print(f"  {'Attack':42} {'Expected':30} Result")
    for ch in a["attack_checks"]:
        print(f"  {ch['attack']:42} {ch['expected']:30} {ch['result']}")
        print(f"  {'':42} {'-> ' + ch['observed']}")

    print("\n  Radio (802.11p, Veins)")
    dr = n["delivery_ratio"]
    print(f"  Readings sent / received        {n['readings_sent']} / {n['readings_received']}"
          f"   (delivery {dr * 100:.1f}%)" if dr is not None else "")
    print(f"  Readings not sent               {n['readings_not_sent_no_coverage']} out of coverage, "
          f"{n['readings_not_sent_during_handover']} during a handover")
    print(f"  Handshake requests sent / recv  {n['handshake_requests_sent']} / "
          f"{n['handshake_requests_received']}   ({n['handshake_retries']} retries)")
    print(f"  Sessions / handovers            {n['sessions']} / {n['handovers']}")
    h = n["handshake_latency_ms"]
    print(f"  Handshake, last attempt (car avg) p50 {fnum(h['p50'], ' ms')}  p95 {fnum(h['p95'], ' ms')}"
          f"  worst {fnum(n['handshake_latency_max_ms'], ' ms')}")
    t = n["time_to_session_ms"]
    print(f"  Time to session incl. retries   p50 {fnum(t['p50'], ' ms')}  p95 {fnum(t['p95'], ' ms')}"
          f"  worst {fnum(n['time_to_session_max_ms'], ' ms')}")
    for label, key in (("Air delay per reading", "air_delay_ms"),
                       ("Wait for gateway CPU", "gateway_queue_ms"),
                       ("Reading end-to-end", "reading_end_to_end_ms"),
                       ("Gateway handshake work", "handshake_proc_ms"),
                       ("Gateway tick work", "tick_proc_ms")):
        s = n[key]
        print(f"  {label:31} p50 {fnum(s['p50'], ' ms', 2)}  p95 {fnum(s['p95'], ' ms', 2)}"
              f"  max {fnum(s['max'], ' ms', 2)}")

    print("\n  Blockchain (gateway service)")
    f = c["finality_s"] or {}
    print(f"  Transactions published / final  {c['tx_published']} / {c['tx_finalised']}"
          f"   (pending at end {c['tx_pending_at_end']}, rejected {c['tx_rejected']})")
    print(f"  Time to finality                p50 {fnum(f.get('p50'), ' s')}  p95 {fnum(f.get('p95'), ' s')}")
    so = c["server_opened"] or {}
    print(f"  Server opened C_j               {so.get('ok', '-')} ok, {so.get('failed', '-')} failed")
    hr, mr = c["honest_readings"] or {}, c["malicious_readings"] or {}
    print(f"  Honest readings                 accepted {hr.get('accepted', '-')}, "
          f"finalised {hr.get('finalised', '-')}")
    print(f"  False readings (ground truth)   accepted {mr.get('accepted', '-')}, "
          f"finalised {mr.get('finalised', '-')}   <- the gap VEYRA targets")
    print()


def print_compare(items: list[dict]) -> None:
    rows = [
        ("config", lambda a: a["config"]),
        ("delivery ratio %", lambda a: fnum((a["network"]["delivery_ratio"] or 0) * 100)),
        ("handshake requests sent", lambda a: a["network"]["handshake_requests_sent"]),
        ("handshake requests received", lambda a: a["network"]["handshake_requests_received"]),
        ("handshake retries", lambda a: a["network"]["handshake_retries"]),
        ("readings lost to handovers", lambda a: a["network"]["readings_not_sent_during_handover"]),
        ("time to session p50 ms", lambda a: fnum(a["network"]["time_to_session_ms"]["p50"])),
        ("time to session p95 ms", lambda a: fnum(a["network"]["time_to_session_ms"]["p95"])),
        ("air delay p50 ms", lambda a: fnum(a["network"]["air_delay_ms"]["p50"], digits=3)),
        ("reading end-to-end p95 ms", lambda a: fnum(a["network"]["reading_end_to_end_ms"]["p95"])),
        ("finality p50 s", lambda a: fnum((a["blockchain"]["finality_s"] or {}).get("p50"))),
        ("finality p95 s", lambda a: fnum((a["blockchain"]["finality_s"] or {}).get("p95"))),
        ("false readings finalised", lambda a: (a["blockchain"]["malicious_readings"] or {}).get("finalised")),
    ]
    w = 18
    print(f"  {'':30}" + "".join(f"{a['run'][-15:]:>{w}}" for a in items))
    for label, fn in rows:
        print(f"  {label:30}" + "".join(f"{str(fn(a)):>{w}}" for a in items))
    print()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("runs", nargs="*", help="omnet-run folders (default: the latest)")
    ap.add_argument("--results", default=str(HERE / "results"))
    args = ap.parse_args()

    runs = [Path(r) for r in args.runs]
    if not runs:
        found = sorted(Path(args.results).glob("omnet-run-*"))
        if not found:
            sys.exit(f"No omnet-run-* folders in {args.results}")
        runs = [found[-1]]

    items = []
    for r in runs:
        a = analyse(load_run(r))
        (r / "analysis.json").write_text(json.dumps(a, indent=2, default=str))
        items.append(a)
        print_one(a)
    if len(items) > 1:
        print("=" * 78)
        print("  Comparison")
        print("=" * 78)
        print_compare(items)
    return 0


if __name__ == "__main__":
    sys.exit(main())
