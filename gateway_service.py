#!/usr/bin/env python3
"""
VEYRA gateway service - the gateways and the server, outside OMNeT++.

OMNeT++/Veins carries every sensor <-> gateway message over simulated 802.11p.
When a message reaches an RSU, the RSU forwards it here over a local TCP socket,
waits for the answer, and sends the answer back over the air. Everything the
paper puts on the gateway, the server, BC_ID and BC_Data runs in this process:

    Alg. 1  registration (with proof-of-possession)        -> Server
    Alg. 2  session key, gateway side                      -> Gateway j
    Alg. 3  freshness, AEAD, hash check, buffer            -> Gateway j
    Eq. 6-7 aggregate as an evidence list, seal for server -> Gateway j / Server
    Alg. 4  transaction, Merkle root, PoPQW, parent checks -> Gateway j / Ledger
    Alg. 5  reference counting, tPQ-Sig                    -> Ledger / t gateways

One TCP port per RSU (default 9001, 9002, 9003 -> GW-00, GW-01, GW-02).
Messages are one JSON object per line; see PROTOCOL.md.

Clock: every message carries OMNeT++'s simulation time. That is the clock the
freshness check, transaction timestamps and time-to-finality use, so radio
delay and ledger delay are measured on the same timeline. CPU cost of the
cryptography is measured on the real clock and returned as proc_ms, which the
RSU adds as a processing delay before replying.

v1 simplification (state it in the report): the vehicle-side cryptography
(Alg. 2 lines 5-7 and 17-21, Eq. 3-4) runs here, on the vehicle's behalf, when
its packet arrives. OMNeT++ sends packets padded to the real post-quantum sizes,
so the radio still pays the true byte cost.

    python gateway_service.py                       # ports 9001-9003
    python gateway_service.py --vehicles 40         # FT is derived from size
    python gateway_service.py --ports 9001,9002     # two RSUs
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import selectors
import socket
import statistics
import sys
import time
from pathlib import Path

from pqdag import clock, crypto
from pqdag.ledger import DagLedger
from pqdag.network import Gateway, SensorNode, Server

PROTOCOL_VERSION = 1
READING_KIND, READING_UNIT = "speed", "km/h"


# --------------------------------------------------------------------------
# Simulation clock
# --------------------------------------------------------------------------


class SimClock:
    """Holds the latest OMNeT++ simulation time seen on any message.

    Never runs backwards: messages from different RSUs can arrive slightly out
    of order, and a clock that jumps back would make fresh readings look stale.
    """

    def __init__(self) -> None:
        self.t = 0.0

    def advance(self, t) -> None:
        if t is not None and float(t) > self.t:
            self.t = float(t)

    def __call__(self) -> float:
        return self.t


def pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round(q / 100.0 * (len(s) - 1)))))
    return round(s[k], 3)


def summarise(values: list[float]) -> dict:
    if not values:
        return {"n": 0}
    return {"n": len(values), "mean": round(statistics.mean(values), 3),
            "p50": pct(values, 50), "p95": pct(values, 95), "p99": pct(values, 99),
            "max": round(max(values), 3)}


# --------------------------------------------------------------------------
# The service
# --------------------------------------------------------------------------


class GatewayService:
    def __init__(self, ports: list[int], difficulty: int, t: int, vehicles: int,
                 freshness_s: float, out_dir: Path, quiet: bool = False):
        self.sim = SimClock()
        clock.set_clock(self.sim)
        self.quiet = quiet
        self.freshness_s = freshness_s
        self.started_wall = time.time()

        n_gw = len(ports)
        n_nodes = n_gw + vehicles                         # gateways + sensors
        self.server = Server()
        self.ledger = DagLedger(network_nodes=n_nodes, difficulty_bits=difficulty,
                                threshold_t=min(t, n_gw))

        # Gateways: register (Alg. 1 with proof-of-possession), then negotiate
        # Sk_j with the server so C_j can actually be opened later.
        self.gateways: list[Gateway] = []
        self.by_port: dict[int, Gateway] = {}
        for j, port in enumerate(ports):
            g = Gateway(f"GW-{j:02d}", self.server, self.ledger)
            nonce = self.server.issue_challenge(g.gid)
            reg = self.server.register_node(g.gid, "gateway", g.sig_key.public,
                                            crypto.sign(g.sig_key.secret, nonce), nonce)
            if not reg["ok"]:
                raise RuntimeError(f"could not register {g.gid}: {reg}")
            g.establish_server_key()
            self.gateways.append(g)
            self.by_port[port] = g

        self.vehicles: dict[str, SensorNode] = {}
        # Every sealed reading a vehicle sent, kept so the replay attacks can
        # re-send a genuine captured packet: pd -> [(gid, c_ij, tso)]
        self.captured: dict[str, list[tuple[str, bytes, float]]] = {}
        # Ground truth travels beside the data, never inside it: the gateway
        # makes no decision on it. It exists so results can count how many
        # malicious readings the baseline let through to finality.
        self.pending_labels: dict[str, list[dict]] = {g.gid: [] for g in self.gateways}
        self.tx_labels: dict[str, list[dict]] = {}

        self.counts: dict[str, int] = {}
        self.timings: dict[str, list[float]] = {}
        self.sizes: dict[str, list[int]] = {}
        self.finality_s: list[float] = []
        self.outcomes_by_mode: dict[str, dict[str, int]] = {}
        self.server_opened = {"ok": 0, "failed": 0}
        self.readings_lost = 0
        self.malicious = {"accepted": 0, "published": 0, "finalised": 0}
        self.honest = {"accepted": 0, "published": 0, "finalised": 0}

        stamp = time.strftime("%Y%m%d-%H%M%S")
        self.out_dir = out_dir / f"run-{stamp}"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self._trace_fh = open(self.out_dir / "trace.csv", "w", newline="")
        self.trace = csv.writer(self._trace_fh)
        self.trace.writerow(["wall_s", "sim_s", "gateway", "type", "vehicle", "mode",
                             "truth", "outcome", "stage", "proc_ms", "vehicle_ms",
                             "bytes_up", "bytes_down", "tx_id", "detail"])

        band = self.ledger.ft_band
        self.config = {
            "protocol_version": PROTOCOL_VERSION,
            "crypto_backend": crypto.BACKEND, "post_quantum": crypto.IS_POST_QUANTUM,
            "gateways": [g.gid for g in self.gateways], "ports": ports,
            "expected_vehicles": vehicles, "network_nodes": n_nodes,
            "FT": band["FT"], "ft_band": band["band"], "ft_range": band["range"],
            "ft_paper_range": band["paper_range"],
            "difficulty_bits": difficulty, "threshold_t": self.ledger.t,
            "freshness_window_s": freshness_s, "aggregate_mode": "list",
        }

    # ---- bookkeeping ----------------------------------------------------
    def _count(self, key: str, n: int = 1) -> None:
        self.counts[key] = self.counts.get(key, 0) + n

    def _time(self, key: str, ms: float) -> None:
        self.timings.setdefault(key, []).append(ms)

    def _size(self, key: str, b: int) -> None:
        self.sizes.setdefault(key, []).append(b)

    def _mode_outcome(self, mode: str, outcome: str) -> None:
        d = self.outcomes_by_mode.setdefault(mode, {})
        d[outcome] = d.get(outcome, 0) + 1

    def _row(self, g: Gateway | None, typ: str, vehicle: str = "", mode: str = "",
             truth: str = "", outcome: str = "", stage: str = "", proc_ms=None,
             vehicle_ms=None, up=None, down=None, tx_id: str = "", detail: str = ""):
        self.trace.writerow([round(time.time() - self.started_wall, 4), round(self.sim.t, 6),
                             g.gid if g else "", typ, vehicle, mode, truth, outcome,
                             stage, "" if proc_ms is None else round(proc_ms, 3),
                             "" if vehicle_ms is None else round(vehicle_ms, 3),
                             "" if up is None else up, "" if down is None else down,
                             tx_id, detail])

    def _say(self, text: str, force: bool = False) -> None:
        if force or not self.quiet:
            print(f"[t={self.sim.t:8.2f}s] {text}", flush=True)

    @staticmethod
    def pd_for(vehicle: str) -> str:
        """SUMO vehicle id -> sensor identity PD_ij. ':' separates payload
        fields, so it (and anything else unusual) is replaced."""
        return "SN-" + re.sub(r"[^A-Za-z0-9_.\-]", "_", str(vehicle))

    # ---- HELLO ----------------------------------------------------------
    def on_hello(self, g: Gateway, msg: dict) -> dict:
        self._say(f"{g.gid}: RSU '{msg.get('rsu', '?')}' connected")
        return {"type": "HELLO_OK", "ok": True, "gateway": g.gid, **self.config}

    # ---- HANDSHAKE: Alg. 1 (first contact) + Alg. 2 ---------------------
    def on_handshake(self, g: Gateway, msg: dict) -> dict:
        vehicle = str(msg["vehicle"])
        mode = msg.get("mode", "normal")
        pd = self.pd_for(vehicle)

        reg_ms = 0.0
        s = self.vehicles.get(pd)
        if s is None:
            # First time this vehicle is seen. Registration happens over the
            # paper's secure commissioning channel, not over the air, so its
            # cost is reported separately and not added to radio latency.
            t0 = time.perf_counter()
            s = SensorNode(pd=pd, kind=READING_KIND, gateway_id=g.gid)
            s.unit = READING_UNIT
            if mode != "unregistered":
                nonce = self.server.issue_challenge(pd)
                reg = self.server.register_node(pd, "sensor", s.sig_key.public,
                                                s.prove_possession(nonce), nonce)
                s.registered = reg["ok"]
                self._count("registrations_ok" if reg["ok"] else "registrations_failed")
            self.vehicles[pd] = s
            reg_ms = (time.perf_counter() - t0) * 1000.0
            self._time("registration_ms", reg_ms)

        handover = s.session_key is not None and s.gateway_id != g.gid
        s.gateway_id = g.gid
        t0 = time.perf_counter()
        res = s.establish_session(g)                     # Alg. 2, both sides
        proc_ms = (time.perf_counter() - t0) * 1000.0

        if res["ok"]:
            up = res["kem_ciphertext_bytes"] + res["c2_bytes"]
            down = res["c3_bytes"]
            self._count("handshakes_ok")
            if handover:
                self._count("handovers")
            self._time("handshake_ms", proc_ms)
            self._size("handshake_uplink_bytes", up)
            self._size("handshake_downlink_bytes", down)
            self._mode_outcome(mode, "handshake_ok")
            self._row(g, "HANDSHAKE", vehicle, mode, "", "ok",
                      "handover" if handover else "", proc_ms, None, up, down)
            return {"type": "HANDSHAKE_OK", "ok": True, "vehicle": vehicle, "pd": pd,
                    "gateway": g.gid, "handover": handover, "proc_ms": round(proc_ms, 3),
                    "reg_ms": round(reg_ms, 3), "bytes_up": up, "bytes_down": down,
                    "session": res["session_key_digest"]}

        self._count("handshakes_rejected")
        self._mode_outcome(mode, "handshake_rejected")
        self._row(g, "HANDSHAKE", vehicle, mode, "", "reject", "Alg.2 line 10",
                  proc_ms, None, None, None, "", res.get("error", ""))
        self._say(f"{g.gid}: handshake REJECTED for {pd}: {res.get('error')}")
        return {"type": "REJECT", "ok": False, "of": "HANDSHAKE", "vehicle": vehicle,
                "stage": "Alg.2 line 10", "reason": res.get("error", ""),
                "proc_ms": round(proc_ms, 3), "reg_ms": round(reg_ms, 3)}

    # ---- READING: Eq. 3-4 (vehicle side) + Alg. 3 (gateway side) --------
    def on_reading(self, g: Gateway, msg: dict) -> dict:
        vehicle = str(msg["vehicle"])
        mode = msg.get("mode", "normal")
        truth = msg.get("truth", "honest")
        pd = self.pd_for(vehicle)
        speed = float(msg.get("speed", 0.0))
        x, y = msg.get("x"), msg.get("y")
        s = self.vehicles.get(pd)

        # -- vehicle side: build the packet the radio carried --------------
        t0 = time.perf_counter()
        if s is None or s.session_key is None:
            # No session: the vehicle cannot produce a valid C_ij. Whatever
            # it sends is opaque bytes, which the gateway must refuse.
            c_ij, tso = os.urandom(96), self.sim.t
        elif mode in ("replay_fresh", "replay_old"):
            mine = [c for c in self.captured.get(pd, []) if c[0] == g.gid]
            if not mine:
                return self._reject_reading(g, vehicle, mode, truth, 0.0, 0.0,
                                            "no captured packet", "attack setup")
            # replay_old: the oldest capture (outside the window if run long
            # enough). replay_fresh: the latest capture, still inside it.
            _gid, c_ij, tso = mine[0] if mode == "replay_old" else mine[-1]
        else:
            c_ij, tso = s.seal(speed, READING_UNIT, x, y)       # Eq. 3-4
            if mode == "tamper":
                bad = bytearray(c_ij)
                bad[-1] ^= 0x01                                   # one flipped bit
                c_ij = bytes(bad)
            else:
                self.captured.setdefault(pd, []).append((g.gid, c_ij, tso))
                del self.captured[pd][1:-50]                      # keep first + last 50
        vehicle_ms = (time.perf_counter() - t0) * 1000.0

        # -- gateway side: Alg. 3 -----------------------------------------
        t0 = time.perf_counter()
        res = g.receive(pd, c_ij, tso, freshness_window_s=self.freshness_s)
        proc_ms = (time.perf_counter() - t0) * 1000.0
        up = len(c_ij) + len(pd.encode()) + 8                     # C_ij || tso || PD_ij

        if not res["ok"]:
            return self._reject_reading(g, vehicle, mode, truth, proc_ms, vehicle_ms,
                                        res.get("error", ""), self._stage(res), up)

        self._count("readings_accepted")
        self._time("reading_gateway_ms", proc_ms)
        self._time("reading_vehicle_ms", vehicle_ms)
        self._size("reading_uplink_bytes", up)
        self._mode_outcome(mode, "reading_accepted")
        (self.malicious if truth == "malicious" else self.honest)["accepted"] += 1
        self.pending_labels[g.gid].append({"vehicle": vehicle, "mode": mode, "truth": truth})
        self._row(g, "READING", vehicle, mode, truth, "ok", "buffered", proc_ms,
                  vehicle_ms, up, None)
        return {"type": "ACK", "ok": True, "vehicle": vehicle, "gateway": g.gid,
                "buffered": res["buffered"], "proc_ms": round(proc_ms, 3),
                "vehicle_ms": round(vehicle_ms, 3), "bytes_up": up,
                "risk_score": None}       # reserved for the anomaly detector

    @staticmethod
    def _stage(res: dict) -> str:
        e = res.get("error", "")
        if "unknown session" in e:
            return "Alg.3 session lookup"
        if "freshness" in e or "timestamp" in e:
            return "Alg.3 line 6 (freshness)"
        if "authentication" in e:
            return "Alg.3 line 7 (AEAD)"
        if "hash" in e:
            return "Alg.3 line 8 (hash)"
        return "Alg.3"

    def _reject_reading(self, g, vehicle, mode, truth, proc_ms, vehicle_ms, reason,
                        stage, up=None) -> dict:
        self._count("readings_rejected")
        self._mode_outcome(mode, "reading_rejected")
        self._row(g, "READING", vehicle, mode, truth, "reject", stage, proc_ms,
                  vehicle_ms, up, None, "", reason)
        self._say(f"{g.gid}: reading from {vehicle} [{mode}] REJECTED at {stage}: {reason}")
        return {"type": "REJECT", "ok": False, "of": "READING", "vehicle": vehicle,
                "stage": stage, "reason": reason, "proc_ms": round(proc_ms, 3),
                "vehicle_ms": round(vehicle_ms, 3)}

    # ---- TICK: Eq. 6-7 + Alg. 4 (publish) and Alg. 5 (finalise) ----------
    def on_tick(self, g: Gateway, msg: dict) -> dict:
        t0 = time.perf_counter()
        published = None
        if g.buffer:
            labels, self.pending_labels[g.gid] = self.pending_labels[g.gid], []
            res = g.publish(mode="list")
            if res["ok"]:
                tx_id = res["tx"]["tx_id"]
                tx = self.ledger.txs[tx_id]
                self.tx_labels[tx_id] = labels
                n_bad = sum(1 for l in labels if l["truth"] == "malicious")
                self.malicious["published"] += n_bad
                self.honest["published"] += len(labels) - n_bad
                # The server opens the sealed aggregate (Eq. 7, receiving end).
                try:
                    opened = json.loads(self.server.open_aggregate(g.gid, tx.ciphertext))
                    ok = len(opened) == res["readings_used"]
                except Exception:
                    ok = False
                self.server_opened["ok" if ok else "failed"] += 1
                self._count("transactions_published")
                self._time("popqw_ms", res["popqw_ms"])
                self._size("c_j_bytes", len(tx.ciphertext))
                published = {"tx_id": tx_id, "readings": res["readings_used"],
                             "c_j_bytes": len(tx.ciphertext), "parents": tx.parents,
                             "popqw_ms": res["popqw_ms"], "retries": res["retries"],
                             "server_opened": ok}
                self._row(g, "PUBLISH", "", "", "", "ok", "Alg.4", None, None,
                          len(tx.ciphertext), None, tx_id,
                          f"{res['readings_used']} readings, {n_bad} malicious")
            else:
                self.readings_lost += len(labels)
                self._count("publish_failed")
                self._row(g, "PUBLISH", "", "", "", "fail", "Alg.4", None, None,
                          None, None, "", res.get("error", ""))
                self._say(f"{g.gid}: publish FAILED: {res.get('error')}", force=True)

        finalised = []
        for tx in self.ledger.finalize_ready(self.gateways):      # Alg. 5
            latency = tx.finalized_at - tx.created_at
            cert = sum(s["bytes"] for s in tx.tpq_sig)
            labels = self.tx_labels.get(tx.tx_id, [])
            n_bad = sum(1 for l in labels if l["truth"] == "malicious")
            self.malicious["finalised"] += n_bad
            self.honest["finalised"] += len(labels) - n_bad
            self.finality_s.append(latency)
            self._size("certificate_bytes", cert)
            self._count("transactions_finalised")
            finalised.append({"tx_id": tx.tx_id, "latency_s": round(latency, 3),
                              "cert_bytes": cert, "malicious_readings": n_bad})
            self._row(g, "FINALISE", "", "", "", "ok", "Alg.5", None, None, cert,
                      None, tx.tx_id, f"latency {latency:.3f}s, {n_bad} malicious")
            if n_bad:
                first = self.malicious["finalised"] == n_bad
                self._say(f"{tx.tx_id} FINALISED containing {n_bad} malicious "
                          f"reading(s) - the base pipeline cannot tell"
                          + ("  (further ones: see trace.csv)" if first and self.quiet else ""),
                          force=first)

        proc_ms = (time.perf_counter() - t0) * 1000.0
        self._time("tick_ms", proc_ms)
        st = self.ledger.stats()
        return {"type": "TICK_OK", "ok": True, "gateway": g.gid,
                "published": published, "finalised": finalised,
                "pending": st["pending"], "total": st["total"],
                "proc_ms": round(proc_ms, 3)}

    # ---- STATS ----------------------------------------------------------
    def summary(self) -> dict:
        st = self.ledger.stats()
        return {
            "config": self.config,
            "sim_time_s": round(self.sim.t, 3),
            "wall_time_s": round(time.time() - self.started_wall, 3),
            "counts": dict(sorted(self.counts.items())),
            "outcomes_by_mode": self.outcomes_by_mode,
            "ledger": {k: st[k] for k in ("total", "finalized", "pending", "rejected",
                                          "publish_retries")},
            "finality_latency_sim_s": summarise(self.finality_s),
            "processing_ms": {k: summarise(v) for k, v in sorted(self.timings.items())},
            "bytes": {k: summarise([float(b) for b in v]) for k, v in sorted(self.sizes.items())},
            "server_opened_aggregates": self.server_opened,
            "readings_lost_in_failed_publish": self.readings_lost,
            "honest_readings": self.honest,
            "malicious_readings": self.malicious,
            "registered_identities": len(self.server.bc_id.leaves),
            "vehicles_seen": len(self.vehicles),
        }

    def on_stats(self, g: Gateway, msg: dict) -> dict:
        return {"type": "STATS_OK", "ok": True, **self.summary()}

    # ---- dispatch -------------------------------------------------------
    HANDLERS = {"HELLO": "on_hello", "HANDSHAKE": "on_handshake",
                "READING": "on_reading", "TICK": "on_tick", "STATS": "on_stats"}

    def handle(self, port: int, line: bytes) -> dict | None:
        try:
            msg = json.loads(line)
        except Exception as e:
            return {"type": "ERROR", "ok": False, "reason": f"bad JSON: {e}"}
        typ = msg.get("type")
        self.sim.advance(msg.get("sim_time"))
        g = self.by_port[port]
        name = self.HANDLERS.get(typ)
        if typ in ("BYE", "SHUTDOWN"):
            reply = {"type": f"{typ}_OK", "ok": True}
        elif name is None:
            reply = {"type": "ERROR", "ok": False, "reason": f"unknown type {typ!r}"}
        else:
            try:
                reply = getattr(self, name)(g, msg)
            except Exception as e:                   # report, never crash the run
                self._count("handler_errors")
                self._say(f"{g.gid}: ERROR handling {typ}: {type(e).__name__}: {e}",
                          force=True)
                reply = {"type": "ERROR", "ok": False, "reason": f"{type(e).__name__}: {e}"}
        if "id" in msg:
            reply["id"] = msg["id"]                  # lets the RSU match replies
        reply["sim_time"] = self.sim.t
        return reply

    def close(self) -> Path:
        self._trace_fh.close()
        path = self.out_dir / "summary.json"
        path.write_text(json.dumps(self.summary(), indent=2))
        clock.reset()
        return path


# --------------------------------------------------------------------------
# Network loop: one listening socket per RSU, newline-delimited JSON
# --------------------------------------------------------------------------


def serve(svc: GatewayService, host: str, ports: list[int]) -> None:
    sel = selectors.DefaultSelector()
    listeners = []
    for port in ports:
        ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind((host, port))
        ls.listen()
        ls.setblocking(False)
        sel.register(ls, selectors.EVENT_READ, ("listen", port))
        listeners.append(ls)

    print("=" * 70)
    print("  VEYRA gateway service")
    print("=" * 70)
    c = svc.config
    print(f"  crypto     : {c['crypto_backend']}"
          + ("" if c["post_quantum"] else "   !! NOT POST-QUANTUM"))
    for g, port in zip(svc.gateways, ports):
        print(f"  {g.gid}      : listening on {host}:{port}")
    print(f"  network    : {c['network_nodes']} nodes ({len(ports)} gateways + "
          f"{c['expected_vehicles']} vehicles) -> {c['ft_band']}, FT = {c['FT']}")
    print(f"  PoPQW      : {c['difficulty_bits']} bits   tPQ-Sig: {c['threshold_t']}-of-{len(ports)}")
    print(f"  results    : {svc.out_dir}")
    print("  Ctrl+C to stop (summary is written on exit).")
    print("-" * 70, flush=True)

    buffers: dict[socket.socket, bytearray] = {}
    stop = False
    try:
        while not stop:
            for key, _ in sel.select(timeout=0.5):    # timeout lets Ctrl+C through
                kind, port = key.data
                if kind == "listen":
                    conn, addr = key.fileobj.accept()
                    conn.setblocking(True)
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    sel.register(conn, selectors.EVENT_READ, ("conn", port))
                    buffers[conn] = bytearray()
                    continue
                conn = key.fileobj
                try:
                    data = conn.recv(65536)
                except (ConnectionResetError, OSError):
                    data = b""
                if not data:
                    sel.unregister(conn)
                    conn.close()
                    buffers.pop(conn, None)
                    continue
                buf = buffers[conn]
                buf.extend(data)
                while b"\n" in buf:
                    line, _, rest = bytes(buf).partition(b"\n")
                    buf[:] = rest
                    if not line.strip():
                        continue
                    reply = svc.handle(port, line)
                    try:
                        conn.sendall((json.dumps(reply) + "\n").encode())
                    except OSError:
                        break
                    if reply and reply.get("type") == "SHUTDOWN_OK":
                        stop = True
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        for s in list(buffers) + listeners:
            try:
                s.close()
            except OSError:
                pass
        path = svc.close()
        s = svc.summary()
        print("-" * 70)
        print(f"  sim time {s['sim_time_s']} s | txs {s['ledger']['total']} | finalised "
              f"{s['ledger']['finalized']} | rejected {s['ledger']['rejected']}")
        print(f"  malicious readings: {s['malicious_readings']}")
        print(f"  summary  : {path}")
        print(f"  trace    : {svc.out_dir / 'trace.csv'}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--ports", default="9001,9002,9003",
                    help="one port per RSU/gateway (default 9001,9002,9003)")
    ap.add_argument("--vehicles", type=int, default=12,
                    help="expected vehicles; with the gateways this sets the node "
                         "count, and the node count sets FT (Table III). Default 12.")
    ap.add_argument("--difficulty", type=int, default=12, help="PoPQW bits (default 12)")
    ap.add_argument("--t", type=int, default=3, help="tPQ-Sig signers (default 3)")
    ap.add_argument("--freshness", type=float, default=120.0,
                    help="Alg. 3 freshness window in seconds (default 120)")
    ap.add_argument("--out", default="results", help="results folder (default results/)")
    ap.add_argument("--quiet", action="store_true", help="only print rejections and errors")
    args = ap.parse_args()

    ports = [int(p) for p in args.ports.split(",") if p.strip()]
    svc = GatewayService(ports, args.difficulty, args.t, args.vehicles,
                         args.freshness, Path(args.out), args.quiet)
    serve(svc, args.host, ports)
    return 0


if __name__ == "__main__":
    sys.exit(main())
