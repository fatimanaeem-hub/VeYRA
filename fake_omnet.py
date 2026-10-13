#!/usr/bin/env python3
"""
fake_omnet.py - pretends to be the OMNeT++ RSUs, so the gateway service can be
tested before any C++ exists.

It opens one connection per RSU port, moves vehicles along a straight road,
hands each one over to the nearest RSU, and sends exactly the messages the real
VeyraRsuApp will send: HELLO, HANDSHAKE, READING, TICK (see PROTOCOL.md).
Simulation time is carried on every message, as OMNeT++ will do.

On top of honest traffic it runs scripted attacks and checks each outcome
against what the base paper should do:

    unregistered vehicle handshake     -> REJECT  (Alg. 2 line 10)
    reading with no session            -> REJECT  (Alg. 3 session lookup)
    one flipped bit                    -> REJECT  (Alg. 3, AEAD)
    replay older than the window       -> REJECT  (Alg. 3 line 6)
    replay inside the window           -> ACCEPT  (paper gap: no duplicate check)
    compromised registered vehicle     -> ACCEPT and FINALISED (the gap VEYRA targets)

Start the service first, then run this in a second window:

    python gateway_service.py
    python fake_omnet.py                  # 180 simulated seconds, 12 vehicles
    python fake_omnet.py --duration 60    # quicker; skips the old-replay check
"""

from __future__ import annotations

import argparse
import json
import random
import socket
import statistics
import sys
import time

ROAD_M = 3000.0


class Rsu:
    """One TCP connection, standing in for one VeyraRsuApp."""

    def __init__(self, name: str, host: str, port: int, x: float):
        self.name, self.port, self.x = name, port, x
        self.sock = socket.create_connection((host, port), timeout=60)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.rfile = self.sock.makefile("rb")
        self.next_id = 0
        self.rtt_ms: list[float] = []

    def rpc(self, msg: dict) -> dict:
        self.next_id += 1
        msg = {**msg, "id": self.next_id}
        t0 = time.perf_counter()
        self.sock.sendall((json.dumps(msg) + "\n").encode())
        line = self.rfile.readline()
        self.rtt_ms.append((time.perf_counter() - t0) * 1000.0)
        if not line:
            raise ConnectionError(f"{self.name}: service closed the connection")
        reply = json.loads(line)
        if reply.get("id") != self.next_id:
            raise RuntimeError(f"{self.name}: reply id mismatch")
        return reply

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class Vehicle:
    def __init__(self, vid: str, x: float, speed_kmh: float, parked: bool = False):
        self.vid, self.x, self.speed, self.parked = vid, x, speed_kmh, parked
        self.rsu: Rsu | None = None
        self.session_ok = False
        self.compromised = False

    def step(self, dt: float, rng: random.Random) -> None:
        if self.parked:
            self.speed = 0.0
            return
        # smooth speed: small random change, kept in a plausible urban range
        self.speed = min(110.0, max(20.0, self.speed + rng.gauss(0.0, 2.0)))
        self.x = (self.x + self.speed / 3.6 * dt) % ROAD_M


class Check:
    def __init__(self, name: str, expect: str, paper: str):
        self.name, self.expect, self.paper = name, expect, paper
        self.got: str | None = None
        self.detail = ""

    @property
    def passed(self) -> bool:
        return self.got == self.expect


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--ports", default="9001,9002,9003")
    ap.add_argument("--vehicles", type=int, default=12,
                    help="registered vehicles incl. 1 parked (default 12; match the service)")
    ap.add_argument("--duration", type=float, default=180.0, help="simulated seconds")
    ap.add_argument("--step", type=float, default=0.5, help="mobility step, seconds")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--no-attacks", action="store_true")
    ap.add_argument("--no-shutdown", action="store_true",
                    help="leave the service running afterwards")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    ports = [int(p) for p in args.ports.split(",") if p.strip()]
    spacing = ROAD_M / len(ports)
    rsus = []
    try:
        for i, p in enumerate(ports):
            rsus.append(Rsu(f"rsu[{i}]", args.host, p, spacing * (i + 0.5)))
    except OSError as e:
        print(f"Could not connect to the gateway service on port {ports[len(rsus)]}: {e}")
        print("Start it first:  python gateway_service.py")
        return 2

    for r in rsus:
        hello = r.rpc({"type": "HELLO", "rsu": r.name, "sim_time": 0.0,
                       "protocol_version": 1})
    cfg = hello
    print(f"Connected to {len(rsus)} RSU ports. Service: FT={cfg['FT']} ({cfg['ft_band']}), "
          f"PoPQW {cfg['difficulty_bits']} bits, t={cfg['threshold_t']}, "
          f"backend {cfg['crypto_backend']}")
    if cfg["expected_vehicles"] != args.vehicles:
        print(f"  note: service expects {cfg['expected_vehicles']} vehicles, this run "
              f"uses {args.vehicles}; FT is derived from the service's number.")

    # -- vehicles: n-1 moving, 1 parked next to the middle RSU -------------
    moving = [Vehicle(f"veh-{i:02d}", rng.uniform(0, ROAD_M), rng.uniform(40, 90))
              for i in range(max(1, args.vehicles - 1))]
    parked = Vehicle("parked-00", rsus[len(rsus) // 2].x + 20.0, 0.0, parked=True)
    fleet = moving + [parked]
    compromised = moving[min(3, len(moving) - 1)]
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

    def nearest(x: float) -> Rsu:
        return min(rsus, key=lambda r: abs(r.x - x))

    def handshake(v: Vehicle, r: Rsu, t: float, mode: str = "normal") -> dict:
        rep = r.rpc({"type": "HANDSHAKE", "vehicle": v.vid, "sim_time": t, "mode": mode})
        v.rsu, v.session_ok = r, rep["ok"]
        return rep

    def reading(v: Vehicle, r: Rsu, t: float, speed: float, mode="normal",
                truth="honest") -> dict:
        return r.rpc({"type": "READING", "vehicle": v.vid, "sim_time": t,
                      "speed": round(speed, 2), "x": round(v.x, 2), "y": 0.0,
                      "mode": mode, "truth": truth})

    finalised_total, malicious_finalised = 0, 0
    t, n_steps = 0.0, int(round(args.duration / args.step))
    wall0 = time.perf_counter()
    rogue = Vehicle("rogue-99", rsus[0].x, 50.0)
    old_replay_at = args.duration - 10.0

    for k in range(1, n_steps + 1):
        t = round(k * args.step, 6)
        whole_second = abs(t - round(t)) < 1e-9

        # mobility + handover: handshake whenever the nearest RSU changes
        for v in fleet:
            v.step(args.step, rng)
            r = nearest(v.x)
            if v.rsu is not r:
                handshake(v, r, t)

        if whole_second:
            # honest readings (and the compromised one after t=20)
            for v in fleet:
                if not v.session_ok:
                    continue
                if attacks and v is compromised and t >= 20:
                    rep = reading(v, v.rsu, t, 250.0 + rng.uniform(0, 30),
                                  mode="compromised", truth="malicious")
                    c = checks["compromised"]
                    if c.got is None or rep["type"] != "ACK":
                        c.got, c.detail = rep["type"], rep.get("reason", "accepted, buffered")
                else:
                    reading(v, v.rsu, t, v.speed)

            # scripted attacks
            if attacks:
                if t == 5:
                    rep = handshake(rogue, rsus[0], t, mode="unregistered")
                    checks["unregistered"].got = rep["type"]
                    checks["unregistered"].detail = rep.get("reason", "")
                if t == 6:
                    rep = reading(rogue, rsus[0], t, 60.0, truth="malicious")
                    checks["no_session"].got = rep["type"]
                    checks["no_session"].detail = rep.get("reason", "")
                if t == 10:
                    rep = reading(parked, parked.rsu, t, 0.0, mode="tamper", truth="malicious")
                    checks["tamper"].got = rep["type"]
                    checks["tamper"].detail = rep.get("reason", "")
                if t == 12:
                    rep = reading(parked, parked.rsu, t, 0.0, mode="replay_fresh",
                                  truth="malicious")
                    checks["replay_fresh"].got = rep["type"]
                    checks["replay_fresh"].detail = rep.get("reason", "accepted, buffered")
                if t == round(old_replay_at) and old_replay_at > 130:
                    rep = reading(parked, parked.rsu, t, 0.0, mode="replay_old",
                                  truth="malicious")
                    checks["replay_old"].got = rep["type"]
                    checks["replay_old"].detail = rep.get("reason", "")

            # each RSU ticks once a second: publish (Alg. 4) + finalise (Alg. 5)
            for r in rsus:
                rep = r.rpc({"type": "TICK", "sim_time": t})
                for f in rep.get("finalised", []):
                    finalised_total += 1
                    malicious_finalised += f["malicious_readings"]

            if int(t) % 20 == 0:
                st = rsus[0].rpc({"type": "STATS", "sim_time": t})
                print(f"  t={t:6.1f}s  txs {st['ledger']['total']:4d}  finalised "
                      f"{st['ledger']['finalized']:4d}  pending {st['ledger']['pending']:3d}  "
                      f"wall {time.perf_counter() - wall0:5.1f}s", flush=True)

    if attacks and old_replay_at <= 130:
        checks["replay_old"].got = "SKIPPED"
        checks["replay_old"].detail = "needs --duration >= 141 so the capture is >120 s old"

    st = rsus[0].rpc({"type": "STATS", "sim_time": t})
    if not args.no_shutdown:
        rsus[0].rpc({"type": "SHUTDOWN", "sim_time": t})
    for r in rsus:
        r.close()

    # ---------------------------------------------------------------------
    print()
    print("=" * 78)
    print(f"  Run: {args.duration:.0f} simulated s, {len(fleet)} vehicles, {len(rsus)} RSUs, "
          f"{time.perf_counter() - wall0:.1f} s wall clock")
    print("=" * 78)
    ok_all = True
    if checks:
        print(f"  {'Attack / check':44s} {'expect':8s} {'got':8s}  result")
        for c in checks.values():
            if c.got == "SKIPPED":
                mark = "SKIP"
            else:
                mark = "PASS" if c.passed else "FAIL"
                ok_all &= c.passed
            print(f"  {c.name:44s} {c.expect:8s} {str(c.got):8s}  {mark:4s}  ({c.paper})")
            if c.detail:
                print(f"  {'':44s} -> {c.detail}")
        print()

    led, cnt = st["ledger"], st["counts"]
    fin = st["finality_latency_sim_s"]
    pm, by = st["processing_ms"], st["bytes"]

    def p(d: dict, key: str) -> str:
        return "-" if not d or d.get("n", 0) == 0 else f"{d[key]}"

    print(f"  Handshakes ok / rejected     : {cnt.get('handshakes_ok', 0)} / "
          f"{cnt.get('handshakes_rejected', 0)}   (handovers {cnt.get('handovers', 0)})")
    print(f"  Readings accepted / rejected : {cnt.get('readings_accepted', 0)} / "
          f"{cnt.get('readings_rejected', 0)}")
    print(f"  Transactions                 : {led['total']} published, {led['finalized']} "
          f"finalised, {led['pending']} pending, {led['rejected']} rejected, "
          f"{led['publish_retries']} tip-race retries")
    print(f"  Time to finality (sim s)     : p50 {p(fin, 'p50')}  p95 {p(fin, 'p95')}")
    print(f"  Server opened C_j            : {st['server_opened_aggregates']}")
    for k in ("handshake_ms", "reading_gateway_ms", "popqw_ms", "tick_ms"):
        print(f"  CPU {k:25s}: p50 {p(pm.get(k, {}), 'p50')}  p95 {p(pm.get(k, {}), 'p95')}")
    for k in ("handshake_uplink_bytes", "handshake_downlink_bytes",
              "reading_uplink_bytes", "c_j_bytes", "certificate_bytes"):
        print(f"  Bytes {k:23s}: mean {p(by.get(k, {}), 'mean')}")
    mal = st["malicious_readings"]
    print(f"  Malicious readings           : accepted {mal['accepted']}, published "
          f"{mal['published']}, FINALISED {mal['finalised']}")
    if mal["finalised"]:
        print("    -> authenticated-but-false data reached finality. That is the gap.")
    rtts = [x for r in rsus for x in r.rtt_ms]
    if rtts:
        print(f"  Socket round trip (wall ms)  : median {statistics.median(rtts):.2f}")
    print()
    print("  ALL CHECKS PASSED" if ok_all else "  SOME CHECKS FAILED")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
