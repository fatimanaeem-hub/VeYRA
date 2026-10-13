#!/usr/bin/env python3
"""
sumo_driver.py - drive the gateway service with real SUMO traffic.

Same job as fake_omnet.py, but the cars come from SUMO instead of a made-up
straight road. Python talks to SUMO through TraCI, reads every car's real
speed and position each step, and sends the same HANDSHAKE / READING / TICK
messages the OMNeT++ RSUs will send (see PROTOCOL.md).

What this adds over fake_omnet.py
  * realistic driving: acceleration, braking, queues, cars entering and leaving
  * RSUs placed along the actual route on the Erlangen map
  * readings.csv - every reading with true vs reported speed, position,
    acceleration, CO2, road and ground-truth label: a ready dataset for the
    anomaly-detection work

What it still does NOT have (that is Phase 3)
  * no radio: a car is served by the nearest RSU, with no range, delay or loss
  * no OMNeT++: do not run veins_launchd for this; Python is SUMO's only client

Run (two Command Prompt windows, in this folder):

    python gateway_service.py --vehicles 20
    python sumo_driver.py --sumocfg C:\\fyp\\veins-5.3.1\\examples\\veins\\erlangen.sumo.cfg

Add --gui to watch the cars in sumo-gui.
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import shutil
import statistics
import sys
import time
from pathlib import Path

from fake_omnet import Check, Rsu       # same RSU connection and check helpers

DEFAULT_CFG = r"C:\fyp\veins-5.3.1\examples\veins\erlangen.sumo.cfg"


# --------------------------------------------------------------------------
# SUMO / TraCI plumbing
# --------------------------------------------------------------------------


def import_traci():
    """Prefer the TraCI that ships with the installed SUMO (matches its version)."""
    home = os.environ.get("SUMO_HOME")
    if home:
        tools = os.path.join(home, "tools")
        if os.path.isdir(tools) and tools not in sys.path:
            sys.path.insert(0, tools)
    try:
        import traci  # type: ignore
        return traci
    except ImportError:
        print("Could not import TraCI. Set SUMO_HOME to your SUMO folder "
              "(e.g. C:\\fyp\\sumo-1.22.0) or run:  pip install traci")
        sys.exit(2)


def sumo_binary(gui: bool) -> str:
    name = "sumo-gui" if gui else "sumo"
    exe = name + (".exe" if os.name == "nt" else "")
    home = os.environ.get("SUMO_HOME")
    if home:
        cand = os.path.join(home, "bin", exe)
        if os.path.exists(cand):
            return cand
    found = shutil.which(name)
    if found:
        return found
    print(f"Could not find {name}. Set SUMO_HOME or add SUMO's bin folder to PATH.")
    sys.exit(2)


def polyline_length(pts) -> float:
    return sum(math.dist(pts[i], pts[i + 1]) for i in range(len(pts) - 1))


def point_along(pts, dist: float):
    for i in range(len(pts) - 1):
        seg = math.dist(pts[i], pts[i + 1])
        if dist <= seg and seg > 0:
            f = dist / seg
            return (pts[i][0] + f * (pts[i + 1][0] - pts[i][0]),
                    pts[i][1] + f * (pts[i + 1][1] - pts[i][1]))
        dist -= seg
    return pts[-1]


def auto_place_rsus(traci, n: int) -> list[tuple[float, float]]:
    """Spread n RSUs evenly along the longest route in the scenario.

    Falls back to a line across the map if the scenario defines no routes.
    """
    best: list = []
    for rid in traci.route.getIDList():
        pts = []
        for edge in traci.route.getEdges(rid):
            if edge.startswith(":"):
                continue
            try:
                pts.extend(traci.lane.getShape(f"{edge}_0"))
            except traci.TraCIException:
                pass
        if len(pts) > 1 and polyline_length(pts) > polyline_length(best or [(0, 0)]):
            best = pts
    if len(best) > 1:
        total = polyline_length(best)
        return [point_along(best, total * (i + 0.5) / n) for i in range(n)]
    (x0, y0), (x1, y1) = traci.simulation.getNetBoundary()
    return [(x0 + (x1 - x0) * (i + 0.5) / n, (y0 + y1) / 2) for i in range(n)]


# --------------------------------------------------------------------------
# Vehicles
# --------------------------------------------------------------------------


class Car:
    def __init__(self, vid: str, index: int):
        self.vid, self.index = vid, index
        self.rsu: Rsu | None = None
        self.session_ok = False
        self.active = True
        self.departed_at: float | None = None
        self.first_reading_at: dict[str, float] = {}   # RSU name -> first reading time
        self.last_reading_rsu: Rsu | None = None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sumocfg", default=DEFAULT_CFG, help="SUMO .sumocfg to run")
    ap.add_argument("--gui", action="store_true", help="use sumo-gui to watch the cars")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--ports", default="9001,9002,9003")
    ap.add_argument("--rsu", default="",
                    help='RSU positions "x,y;x,y;x,y" (default: spread along the route)')
    ap.add_argument("--max-vehicles", type=int, default=20,
                    help="track the first N cars SUMO inserts (default 20; match the "
                         "service's --vehicles so FT is derived from the same size)")
    ap.add_argument("--duration", type=float, default=240.0,
                    help="simulated seconds to run after the first car departs (default 240)")
    ap.add_argument("--compromised", type=int, default=3,
                    help="index of the tracked car that turns malicious (default 3)")
    ap.add_argument("--fake-speed", type=float, default=250.0,
                    help="speed (km/h) the compromised car reports (default 250)")
    ap.add_argument("--attack-start", type=float, default=20.0,
                    help="seconds after its departure the compromised car starts lying")
    ap.add_argument("--no-attacks", action="store_true")
    ap.add_argument("--no-shutdown", action="store_true",
                    help="leave the gateway service running afterwards")
    ap.add_argument("--out", default="results", help="folder for readings.csv")
    args = ap.parse_args()

    if not os.path.exists(args.sumocfg):
        print(f"SUMO config not found: {args.sumocfg}")
        print("Pass the path with --sumocfg, e.g. the Veins Erlangen example:")
        print(r"  --sumocfg C:\fyp\veins-5.3.1\examples\veins\erlangen.sumo.cfg")
        return 2

    traci = import_traci()
    ports = [int(p) for p in args.ports.split(",") if p.strip()]

    # -- connect to the gateway service first, so a missing service fails fast
    rsus: list[Rsu] = []
    try:
        for i, p in enumerate(ports):
            rsus.append(Rsu(f"rsu[{i}]", args.host, p, 0.0))
    except OSError as e:
        print(f"Could not connect to the gateway service on port {ports[len(rsus)]}: {e}")
        print("Start it first:  python gateway_service.py --vehicles "
              f"{args.max_vehicles}")
        return 2

    # -- start SUMO
    cmd = [sumo_binary(args.gui), "-c", args.sumocfg, "--no-step-log", "true",
           "--quit-on-end", "true"]
    if args.gui:
        cmd += ["--start", "true"]
    traci.start(cmd)
    step = traci.simulation.getDeltaT()

    if args.rsu:
        positions = [tuple(float(v) for v in p.split(",")) for p in args.rsu.split(";")]
        if len(positions) != len(rsus):
            print(f"--rsu gives {len(positions)} positions for {len(rsus)} ports")
            traci.close()
            return 2
    else:
        positions = auto_place_rsus(traci, len(rsus))
    for r, (x, y) in zip(rsus, positions):
        r.x, r.y = x, y
        if args.gui:   # show the RSUs on the map
            try:
                traci.poi.add(r.name, x, y, (255, 0, 0, 255), "RSU", 10, "", 15, 15)
            except traci.TraCIException:
                pass

    for r in rsus:
        hello = r.rpc({"type": "HELLO", "rsu": r.name, "sim_time": 0.0, "protocol_version": 1})
    print(f"SUMO: {os.path.basename(args.sumocfg)}, step {step} s. Service: FT={hello['FT']} "
          f"({hello['ft_band']}), PoPQW {hello['difficulty_bits']} bits, "
          f"t={hello['threshold_t']}, backend {hello['crypto_backend']}")
    for r in rsus:
        print(f"  {r.name} at ({r.x:8.1f}, {r.y:8.1f}) -> port {r.port}")
    if hello["expected_vehicles"] != args.max_vehicles:
        print(f"  note: service expects {hello['expected_vehicles']} vehicles, this run tracks "
              f"up to {args.max_vehicles}; FT comes from the service's number.")

    # -- output
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out_dir = Path(args.out) / f"sumo-run-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    fh = open(out_dir / "readings.csv", "w", newline="")
    rows = csv.writer(fh)
    rows.writerow(["sim_s", "vehicle", "rsu", "gateway", "true_speed_kmh",
                   "reported_speed_kmh", "x", "y", "accel_ms2", "angle_deg", "edge",
                   "co2_mg_s", "mode", "truth", "outcome", "stage"])

    def nearest(x: float, y: float) -> Rsu:
        return min(rsus, key=lambda r: math.hypot(r.x - x, r.y - y))

    def handshake(car: Car, r: Rsu, t: float, mode: str = "normal") -> dict:
        rep = r.rpc({"type": "HANDSHAKE", "vehicle": car.vid, "sim_time": t, "mode": mode})
        car.rsu, car.session_ok = r, rep["ok"]
        return rep

    def send_reading(car: Car, r: Rsu, t: float, speed: float, x: float, y: float,
                     mode: str = "normal", truth: str = "honest", extra=None) -> dict:
        rep = r.rpc({"type": "READING", "vehicle": car.vid, "sim_time": t,
                     "speed": round(speed, 2), "x": round(x, 2), "y": round(y, 2),
                     "mode": mode, "truth": truth})
        e = extra or {}
        rows.writerow([round(t, 3), car.vid, r.name, rep.get("gateway", ""),
                       e.get("true_speed", ""), round(speed, 2), round(x, 2), round(y, 2),
                       e.get("accel", ""), e.get("angle", ""), e.get("edge", ""),
                       e.get("co2", ""), mode, truth,
                       "accepted" if rep.get("ok") else "rejected", rep.get("stage", "")])
        if rep.get("ok") and mode in ("normal", "compromised"):
            car.first_reading_at.setdefault(r.name, t)
            car.last_reading_rsu = r
        return rep

    attacks = not args.no_attacks
    checks: dict[str, Check] = {}
    if attacks:
        checks = {
            "unregistered": Check("Unregistered vehicle handshake", "REJECT", "Alg. 2 line 10"),
            "no_session": Check("Reading with no session", "REJECT", "Alg. 3 session lookup"),
            "tamper": Check("One flipped bit in transit", "REJECT", "Alg. 3 AEAD"),
            "replay_fresh": Check("Replay inside freshness window", "ACK",
                                  "paper gap: no duplicate check"),
            "replay_old": Check("Replay older than freshness window", "REJECT",
                                "Alg. 3 line 6"),
            "compromised": Check("Compromised registered vehicle, false speed", "ACK",
                                 "gap VEYRA targets"),
        }

    cars: dict[str, Car] = {}
    rogue = Car("rogue-99", -1)
    t0: float | None = None
    t = 0.0
    done_attacks: set[str] = set()
    wall0 = time.perf_counter()

    try:
        while traci.simulation.getMinExpectedNumber() > 0:
            traci.simulationStep()
            t = round(traci.simulation.getTime(), 6)

            for vid in traci.simulation.getDepartedIDList():
                if len(cars) < args.max_vehicles:
                    cars[vid] = Car(vid, len(cars))
                    cars[vid].departed_at = t
                    if t0 is None:
                        t0 = t
                    if args.gui:
                        traci.vehicle.setColor(vid, (0, 160, 255, 255))
            for vid in traci.simulation.getArrivedIDList():
                if vid in cars:
                    cars[vid].active = False

            if t0 is None:
                continue
            rel = t - t0
            if rel > args.duration:
                break
            live = [c for c in cars.values() if c.active]

            # handover: handshake whenever the nearest RSU changes
            for c in live:
                x, y = traci.vehicle.getPosition(c.vid)
                r = nearest(x, y)
                if c.rsu is not r:
                    handshake(c, r, t)

            if abs(t - round(t)) > step / 2 + 1e-9:
                continue                                    # once per simulated second

            bad = None
            if attacks and args.compromised < len(cars):
                bad = list(cars.values())[args.compromised]
                if args.gui and bad.active and "painted" not in done_attacks:
                    traci.vehicle.setColor(bad.vid, (255, 0, 0, 255))
                    done_attacks.add("painted")

            for c in live:
                if not c.session_ok:
                    continue
                x, y = traci.vehicle.getPosition(c.vid)
                true_kmh = traci.vehicle.getSpeed(c.vid) * 3.6
                extra = {"true_speed": round(true_kmh, 2),
                         "accel": round(traci.vehicle.getAcceleration(c.vid), 3),
                         "angle": round(traci.vehicle.getAngle(c.vid), 1),
                         "edge": traci.vehicle.getRoadID(c.vid),
                         "co2": round(traci.vehicle.getCO2Emission(c.vid), 1)}
                lying = (bad is c and c.departed_at is not None
                         and t - c.departed_at >= args.attack_start)
                if lying:
                    rep = send_reading(c, c.rsu, t, args.fake_speed + (t % 7) * 4, x, y,
                                       mode="compromised", truth="malicious", extra=extra)
                    chk = checks["compromised"]
                    if chk.got is None or rep["type"] != "ACK":
                        chk.got = rep["type"]
                        chk.detail = rep.get("reason", "accepted, buffered")
                else:
                    send_reading(c, c.rsu, t, true_kmh, x, y, extra=extra)

            # scripted attacks, timed from the first departure
            if attacks:
                victims = [c for c in live if c.session_ok and c is not bad
                           and c.last_reading_rsu is c.rsu]
                if rel >= 5 and "unregistered" not in done_attacks:
                    rep = handshake(rogue, rsus[0], t, mode="unregistered")
                    checks["unregistered"].got = rep["type"]
                    checks["unregistered"].detail = rep.get("reason", "")
                    done_attacks.add("unregistered")
                if rel >= 6 and "no_session" not in done_attacks:
                    rep = send_reading(rogue, rsus[0], t, 50.0, rsus[0].x, rsus[0].y,
                                       truth="malicious")
                    checks["no_session"].got = rep["type"]
                    checks["no_session"].detail = rep.get("reason", "")
                    done_attacks.add("no_session")
                if rel >= 10 and "tamper" not in done_attacks and victims:
                    v = victims[0]
                    x, y = traci.vehicle.getPosition(v.vid)
                    rep = send_reading(v, v.rsu, t, traci.vehicle.getSpeed(v.vid) * 3.6, x, y,
                                       mode="tamper", truth="malicious")
                    checks["tamper"].got = rep["type"]
                    checks["tamper"].detail = rep.get("reason", "")
                    done_attacks.add("tamper")
                if rel >= 12 and "replay_fresh" not in done_attacks and victims:
                    v = victims[0]
                    x, y = traci.vehicle.getPosition(v.vid)
                    rep = send_reading(v, v.rsu, t, 0.0, x, y, mode="replay_fresh",
                                       truth="malicious")
                    checks["replay_fresh"].got = rep["type"]
                    checks["replay_fresh"].detail = rep.get("reason", "accepted, buffered")
                    done_attacks.add("replay_fresh")
                if rel >= 150 and "replay_old" not in done_attacks:
                    # an eavesdropper near an RSU re-sends a packet it captured
                    # there more than 130 s ago (the window is 120 s)
                    for c in cars.values():
                        old = [(rn, ts) for rn, ts in c.first_reading_at.items()
                               if t - ts > 130]
                        if old:
                            rname = old[0][0]
                            r = next(x for x in rsus if x.name == rname)
                            rep = send_reading(c, r, t, 0.0, r.x, r.y, mode="replay_old",
                                               truth="malicious")
                            checks["replay_old"].got = rep["type"]
                            checks["replay_old"].detail = rep.get("reason", "")
                            done_attacks.add("replay_old")
                            break

            for r in rsus:
                r.rpc({"type": "TICK", "sim_time": t})

            if int(round(rel)) % 20 == 0:
                st = rsus[0].rpc({"type": "STATS", "sim_time": t})
                print(f"  t={rel:6.1f}s  cars {len(live):3d}  txs {st['ledger']['total']:4d}  "
                      f"finalised {st['ledger']['finalized']:4d}  pending "
                      f"{st['ledger']['pending']:3d}  wall {time.perf_counter() - wall0:6.1f}s",
                      flush=True)
    finally:
        fh.close()
        try:
            traci.close()
        except Exception:
            pass

    if attacks:
        for key, why in (("tamper", "no car had a session yet"),
                         ("replay_fresh", "no car had a session yet"),
                         ("replay_old", "needs a capture >130 s old; run --duration >= 150"),
                         ("compromised", "fewer cars than --compromised index")):
            if checks[key].got is None:
                checks[key].got, checks[key].detail = "SKIPPED", why

    st = rsus[0].rpc({"type": "STATS", "sim_time": t})
    if not args.no_shutdown:
        rsus[0].rpc({"type": "SHUTDOWN", "sim_time": t})
    for r in rsus:
        r.close()

    print_summary(args, cars, rsus, checks, st, t - (t0 or 0.0),
                  time.perf_counter() - wall0, out_dir)
    return 0 if all(c.passed or c.got == "SKIPPED" for c in checks.values()) else 1


def print_summary(args, cars, rsus, checks, st, sim_s, wall_s, out_dir) -> None:
    print()
    print("=" * 78)
    print(f"  SUMO run: {sim_s:.0f} simulated s, {len(cars)} cars tracked, {len(rsus)} RSUs, "
          f"{wall_s:.1f} s wall clock")
    print("=" * 78)
    if checks:
        print(f"  {'Attack / check':44s} {'expect':8s} {'got':8s}  result")
        for c in checks.values():
            mark = "SKIP" if c.got == "SKIPPED" else ("PASS" if c.passed else "FAIL")
            print(f"  {c.name:44s} {c.expect:8s} {str(c.got):8s}  {mark:4s}  ({c.paper})")
            if c.detail:
                print(f"  {'':44s} -> {c.detail}")
        print()

    led, cnt = st["ledger"], st["counts"]
    fin, pm, by = st["finality_latency_sim_s"], st["processing_ms"], st["bytes"]

    def p(d: dict, key: str) -> str:
        return "-" if not d or d.get("n", 0) == 0 else f"{d[key]}"

    print(f"  Handshakes ok / rejected     : {cnt.get('handshakes_ok', 0)} / "
          f"{cnt.get('handshakes_rejected', 0)}   (handovers {cnt.get('handovers', 0)})")
    print(f"  Readings accepted / rejected : {cnt.get('readings_accepted', 0)} / "
          f"{cnt.get('readings_rejected', 0)}")
    print(f"  Transactions                 : {led['total']} published, {led['finalized']} "
          f"finalised, {led['pending']} pending, {led['rejected']} rejected")
    print(f"  Time to finality (sim s)     : p50 {p(fin, 'p50')}  p95 {p(fin, 'p95')}")
    print(f"  Server opened C_j            : {st['server_opened_aggregates']}")
    for k in ("handshake_ms", "reading_gateway_ms", "popqw_ms", "tick_ms"):
        print(f"  CPU {k:25s}: p50 {p(pm.get(k, {}), 'p50')}  p95 {p(pm.get(k, {}), 'p95')}")
    for k in ("handshake_uplink_bytes", "reading_uplink_bytes", "c_j_bytes",
              "certificate_bytes"):
        print(f"  Bytes {k:23s}: mean {p(by.get(k, {}), 'mean')}")
    mal = st["malicious_readings"]
    print(f"  Malicious readings           : accepted {mal['accepted']}, published "
          f"{mal['published']}, FINALISED {mal['finalised']}")
    rtts = [x for r in rsus for x in r.rtt_ms]
    if rtts:
        print(f"  Socket round trip (wall ms)  : median {statistics.median(rtts):.2f}")
    print(f"  Readings dataset             : {out_dir / 'readings.csv'}")
    print()
    ok = all(c.passed or c.got == "SKIPPED" for c in checks.values())
    print("  ALL CHECKS PASSED" if ok else "  SOME CHECKS FAILED")


if __name__ == "__main__":
    sys.exit(main())
