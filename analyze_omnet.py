#!/usr/bin/env python3
"""
Summarise a Phase 3a or 3b run (OMNeT++/Veins + gateway_service.py).

    python analyze_omnet.py                      latest results/omnet-run-*
    python analyze_omnet.py results/omnet-run-X  a specific run
    python analyze_omnet.py RUN_A RUN_B ...      side-by-side comparison

Reads, from each run folder:
    messages.csv          one row per message an RSU handled (written by OMNeT++)
    vehicles.csv          one row per car (written by OMNeT++)
    gateway_summary.json  the gateway service's own summary at the end
    run_info.json         which omnetpp.ini configuration produced it
    backhaul.csv          Phase 3b only: every packet that crossed the backhaul

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
    backhaul = []
    if (run / "backhaul.csv").exists():
        backhaul = list(csv.DictReader(open(run / "backhaul.csv", newline="")))
    return {"run": run, "msgs": msgs, "vehicles": vehicles, "gw": gw, "info": info,
            "backhaul": backhaul}


def gateway_load(msgs: list[dict], sim_s: float) -> dict:
    """Share of simulated time each gateway CPU was busy (all message types)."""
    busy: dict[str, float] = {}
    for m in msgs:
        if m.get("proc_ms"):
            busy[m["gateway"]] = busy.get(m["gateway"], 0.0) + float(m["proc_ms"])
    if not busy or not sim_s:
        return {}
    return {g: round(ms / 1000.0 / sim_s * 100, 1) for g, ms in sorted(busy.items())}


def analyse_backhaul(d: dict) -> dict | None:
    rows, info, rep = d.get("backhaul") or [], d["info"], d["gw"].get("replication")
    if not rows and not rep:
        return None
    data = [r for r in rows if r["event"] in ("delivered", "duplicate", "lost")]
    delivered = [r for r in rows if r["event"] == "delivered"]
    by_kind = {}
    for kind in ("GOSSIP", "SIG_SHARE", "FINAL"):
        k = [r for r in delivered if r["kind"] == kind]
        by_kind[kind] = {"delivered": len(k),
                         "delay_ms": stats([float(r["delay_ms"]) for r in k])}
    wire = sum(int(r["bytes"]) for r in data)
    acks = sum(1 for r in data if r["event"] != "lost")
    links: dict[str, int] = {}
    for r in data:
        a, b = int(r["from"]), int(r["to"])
        name = "-".join(sorted(["server" if x < 0 else f"rsu{x}" for x in (a, b)]))
        links[name] = links.get(name, 0) + int(r["bytes"])
    sim_s = d["gw"].get("sim_time_s") or 0
    out = {
        "profile": {"delay_ms": info.get("backhaul_delay_ms"),
                    "datarate_mbps": info.get("backhaul_datarate_mbps"),
                    "per": info.get("backhaul_per")},
        "by_kind": by_kind,
        "retransmitted": sum(1 for r in data if int(r["attempt"]) > 1),
        "lost_on_link": sum(1 for r in rows if r["event"] == "lost"),
        "gave_up": sum(1 for r in rows if r["event"] == "gave_up"),
        "data_bytes_on_wire": wire,
        "ack_bytes_on_wire": acks * 52,
        "busiest_link_kbps": round(max(links.values()) * 8 / 1000 / sim_s, 1) if links and sim_s else None,
        "bytes_per_link": dict(sorted(links.items())),
    }
    if rep:
        out["replication"] = rep
    return out


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
        "finality_split_s": gw.get("finality_breakdown_s", {}),
        "server_opened": gw.get("server_opened_aggregates", {}),
        "honest_readings": gw.get("honest_readings", {}),
        "malicious_readings": gw.get("malicious_readings", {}),
        "registry": gw.get("registry"),
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

    net["gateway_busy_pct"] = gateway_load(msgs, gw.get("sim_time_s") or 0)
    chain["ledger_mode"] = gw.get("config", {}).get("ledger_mode") or "shared"
    return {"run": d["run"].name, "config": d["info"].get("config", "?"), "network": net,
            "blockchain": chain, "attack_checks": checks, "backhaul": analyse_backhaul(d)}


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
    if n.get("gateway_busy_pct"):
        print("  Gateway CPU busy (all work)     "
              + "   ".join(f"{g} {p}%" for g, p in n["gateway_busy_pct"].items()))

    print("\n  Blockchain (gateway service)")
    f = c["finality_s"] or {}
    print(f"  Transactions published / final  {c['tx_published']} / {c['tx_finalised']}"
          f"   (pending at end {c['tx_pending_at_end']}, rejected {c['tx_rejected']})")
    print(f"  Time to finality                p50 {fnum(f.get('p50'), ' s')}  p95 {fnum(f.get('p95'), ' s')}")
    sp = c.get("finality_split_s") or {}
    if sp.get("created_to_FT_approvals", {}).get("n"):
        ap, ce = sp["created_to_FT_approvals"], sp["FT_to_certificate"]
        print(f"    of which waiting for FT       p50 {fnum(ap.get('p50'), ' s')}  p95 {fnum(ap.get('p95'), ' s')}")
        print(f"    of which certificate          p50 {fnum(ce.get('p50'), ' s', 2)}  p95 {fnum(ce.get('p95'), ' s', 2)}")
    so = c["server_opened"] or {}
    print(f"  Server opened C_j               {so.get('ok', '-')} ok, {so.get('failed', '-')} failed")
    hr, mr = c["honest_readings"] or {}, c["malicious_readings"] or {}
    print(f"  Honest readings                 accepted {hr.get('accepted', '-')}, "
          f"finalised {hr.get('finalised', '-')}")
    print(f"  False readings (ground truth)   accepted {mr.get('accepted', '-')}, "
          f"finalised {mr.get('finalised', '-')}   <- the gap VEYRA targets")
    reg = c.get("registry")
    if reg:
        roles = ", ".join(f"{v} {k}{'s' if v != 1 else ''}" for k, v in sorted(reg["by_role"].items()))
        refused = sorted({r["pd"] for r in reg["refused_handshakes"]})
        print(f"  Registered identities (BC_ID)   {reg['registered']} ({roles}); hash chain "
              + ("intact" if reg["chain_valid"] else "BROKEN") + f"; identity root {reg['identity_root'][:16]}")
        print(f"  Refused at handshake            "
              + (", ".join(refused) if refused else "none") + "   (full list: bc_id.json / gateway_summary.json)")
    print(f"  Ledger                          {c.get('ledger_mode', 'shared')}"
          + ("  (one replica per gateway)" if c.get("ledger_mode") == "replicated" else
             "  (all gateways write one ledger)"))
    b = a.get("backhaul")
    if b:
        print_backhaul(b)
    print()


def print_backhaul(b: dict) -> None:
    p = b["profile"]
    print("\n  Backhaul and replicas (Phase 3b)")
    print(f"  Link profile                    {fnum(p['delay_ms'], ' ms')} one way, "
          f"{fnum(p['datarate_mbps'], ' Mbit/s', 0)}, packet loss {fnum(p['per'], '', 3)}")
    for kind, label in (("GOSSIP", "Transactions (GOSSIP)"), ("SIG_SHARE", "Signature shares"),
                        ("FINAL", "Certificates (FINAL)")):
        k = b["by_kind"][kind]
        print(f"  {label:31} {k['delivered']:6} delivered   link delay p50 "
              f"{fnum(k['delay_ms']['p50'], ' ms', 2)}  p95 {fnum(k['delay_ms']['p95'], ' ms', 2)}")
    print(f"  Lost on a link / retransmitted  {b['lost_on_link']} / {b['retransmitted']}"
          f"   (gave up {b['gave_up']})")
    print(f"  Bytes on the backhaul           {b['data_bytes_on_wire']:,} data + "
          f"{b['ack_bytes_on_wire']:,} ACK   busiest link {fnum(b['busiest_link_kbps'], ' kbit/s')}")
    r = b.get("replication")
    if not r:
        return
    e, al = r["propagation_to_each_replica_s"], r["propagation_to_all_replicas_s"]
    print(f"  Publish -> in another replica   p50 {fnum((e.get('p50') or 0) * 1000, ' ms')}  "
          f"p95 {fnum((e.get('p95') or 0) * 1000, ' ms')}  max {fnum((e.get('max') or 0) * 1000, ' ms')}")
    print(f"  Publish -> in every replica     p50 {fnum((al.get('p50') or 0) * 1000, ' ms')}  "
          f"p95 {fnum((al.get('p95') or 0) * 1000, ' ms')}")
    ow = r["orphan_wait_s"]
    print(f"  Orphans (parent not there yet)  {r['orphans_resolved']} resolved"
          + (f", wait p50 {fnum(ow['p50'] * 1000, ' ms')} max {fnum(ow['max'] * 1000, ' ms')}"
             if ow.get("n") else "") + f", {r['orphans_at_end']} at the end")
    print(f"  Approvals of already-final tx   {r['stale_parent_references']} (parent final in the "
          "receiver's replica, not yet in the creator's)")
    m = r["messages"]
    print(f"  Signature shares                {m['shares_signed']} signed, {m['shares_received']} "
          f"received by the origin, {m['shares_late']} arrived after finality")
    print(f"  Replicas agree at the end       {r['in_every_replica_at_end']} of "
          f"{r['transactions_created']} tx in every replica; {r['final_in_every_replica_at_end']} of "
          f"{r['finalised_at_origin']} final everywhere")


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
