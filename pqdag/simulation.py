"""
Live simulation driving the dashboard.

Builds a small VSN (server, gateways, sensors), runs the full paper pipeline,
and exposes a snapshot the GUI polls. Sensor readings can arrive either from
the operator typing a value into the GUI (manual IoT input) or from the
gateways' own traffic generator.
"""

from __future__ import annotations

import random
import statistics
import threading
import time

from . import crypto
from .ledger import DESIGN_NOTES, DagLedger
from .network import Gateway, SensorNode, Server

SENSOR_KINDS = [
    ("speed", "km/h", 20, 120),
    ("co2", "ppm", 380, 900),
    ("lidar-range", "m", 1, 90),
    ("engine-temp", "C", 60, 115),
    ("tyre-pressure", "kPa", 200, 260),
]


class LiveSimulation:
    def __init__(self):
        self.lock = threading.RLock()
        self.server: Server | None = None
        self.ledger: DagLedger | None = None
        self.gateways: list[Gateway] = []
        self.sensors: list[SensorNode] = []
        self.events: list[dict] = []
        self.timeline: list[dict] = []
        self.params: dict = {}
        self.setup_report: dict = {}
        self.security_checks: list[dict] = []
        self.epoch_report: dict | None = None
        self._traffic_thread: threading.Thread | None = None
        self._final_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.auto_traffic = False
        self.started_at: float | None = None

    # ------------------------------------------------------------------
    def log(self, kind: str, message: str, detail: dict | None = None):
        with self.lock:
            self.events.insert(0, {
                "at": time.time(), "kind": kind,
                "message": message, "detail": detail or {},
            })
            del self.events[300:]

    # ------------------------------------------------------------------
    def build(self, n_gateways=3, sensors_per_gateway=4,
              difficulty=13, t=3,
              batch_registration: bool = False,
              identity_structure: str = "sorted") -> dict:
        """Algorithms 1 and 2: register every node, then establish PQ sessions.

        FT is not an argument. Per Table III of the paper it is a function of the
        network size, so it is derived from the node count the caller asks for.
        """
        self.stop()
        with self.lock:
            self.events, self.timeline, self.security_checks = [], [], []
            t_all = time.perf_counter()

            n_nodes = n_gateways * (1 + sensors_per_gateway)  # gateways + sensors

            self.server = Server(batch_registration=batch_registration,
                                 identity_structure=identity_structure)
            self.ledger = DagLedger(network_nodes=n_nodes,
                                    difficulty_bits=difficulty,
                                    threshold_t=min(t, n_gateways))
            self.gateways, self.sensors = [], []
            handshakes = []

            reg_ms = []

            def enrol(pd: str, role: str, sig_key, sign) -> dict:
                """Algorithm 1 with proof-of-possession: challenge, sign, verify."""
                t0 = time.perf_counter()
                nonce = self.server.issue_challenge(pd)
                proof = sign(nonce)
                r = self.server.register_node(pd, role, sig_key.public, proof, nonce)
                reg_ms.append((time.perf_counter() - t0) * 1000.0)
                return r

            # -- phase 1: enrol every identity ---------------------------
            # Registration is separated from session establishment because in
            # batch mode nothing is on BC_ID until the epoch closes, and Alg. 2
            # line 10 checks BC_ID. Commissioning first, then sessions, is also
            # the more faithful order.
            pairs = []
            for j in range(n_gateways):
                g = Gateway(f"GW-{j:02d}", self.server, self.ledger)
                enrol(g.gid, "gateway", g.sig_key,
                      lambda n, k=g.sig_key: crypto.sign(k.secret, n))
                self.gateways.append(g)
                for i in range(sensors_per_gateway):
                    kind, unit, lo, hi = SENSOR_KINDS[i % len(SENSOR_KINDS)]
                    s = SensorNode(pd=f"SN-{j:02d}-{i:02d}", kind=kind,
                                   gateway_id=g.gid)
                    reg = enrol(s.pd, "sensor", s.sig_key, s.prove_possession)
                    s.registered = reg["ok"]
                    s.unit, s.lo, s.hi = unit, lo, hi
                    self.sensors.append(s)
                    pairs.append((s, g))

            # -- phase 1b: close the window, if batching ------------------
            self.epoch_report = None
            if batch_registration:
                self.epoch_report = self.server.close_registration_epoch()
                for s, _g in pairs:
                    s.registered = True

            # -- phase 2: post-quantum sessions --------------------------
            for s, g in pairs:
                res = s.establish_session(g)
                if res["ok"]:
                    handshakes.append(res["handshake_ms"])

            band = self.ledger.ft_band
            self.params = {
                "gateways": n_gateways, "sensors_per_gateway": sensors_per_gateway,
                "sensors_total": len(self.sensors),
                "network_nodes": n_nodes,
                "finalization_threshold": band["FT"],
                "ft_band": band["band"],
                "ft_range": band["range"],
                "ft_paper_range": band["paper_range"],
                "popqw_difficulty_bits": difficulty,
                "threshold_t": min(t, n_gateways),
            }
            self.setup_report = {
                "handshakes": len(handshakes),
                "median_handshake_ms": round(statistics.median(handshakes), 2)
                if handshakes else None,
                "max_handshake_ms": round(max(handshakes), 2) if handshakes else None,
                "total_build_ms": round((time.perf_counter() - t_all) * 1000.0, 1),
                "registration_blocks": len(self.server.bc_id.blocks),
                "median_registration_ms": round(statistics.median(reg_ms), 2)
                if reg_ms else None,
                "identity_root": self.server.bc_id.identity_root()[:16],
                "identities_committed": len(self.server.bc_id.leaves),
                "identity_structure": self.server.bc_id.idset.name,
                "batch_registration": batch_registration,
                "epoch": self.epoch_report,
                "network_nodes": n_nodes,
                "finalization_threshold": band["FT"],
                "ft_band": band["band"],
                "ft_range": band["range"],
                "ft_paper_range": band["paper_range"],
            }
            self.started_at = time.time()

        note = f" [paper band: {band['paper_range']}]"
        self.log("setup",
                 f"Network built: {n_gateways} gateways, {len(self.sensors)} sensors, "
                 f"{len(handshakes)} post-quantum sessions established. "
                 f"{n_nodes} nodes = {band['band']} ({band['range']}), "
                 f"so FT = {band['FT']} references{note}.",
                 self.setup_report)
        self._final_thread = threading.Thread(target=self._finalizer, daemon=True)
        self._stop.clear()
        self._final_thread.start()
        return self.setup_report

    # ------------------------------------------------------------------
    def _finalizer(self):
        while not self._stop.is_set():
            try:
                newly = self.ledger.finalize_ready(self.gateways)
                for tx in newly:
                    self.log("finalized",
                             f"{tx.tx_id} finalised: {tx.references} references "
                             f"(FT={self.ledger.FT}), certificate signed by "
                             f"{len(tx.tpq_sig)} gateways.",
                             {"tx_id": tx.tx_id,
                              "cert_bytes": sum(s["bytes"] for s in tx.tpq_sig),
                              "latency_s": round(tx.finalized_at - tx.created_at, 3)})
            except Exception as e:  # keep the demo alive
                self.log("error", f"finaliser: {e}")
            self._sample()
            time.sleep(0.4)

    def _sample(self):
        if not self.ledger:
            return
        s = self.ledger.stats()
        with self.lock:
            self.timeline.append({
                "t": round(time.time() - (self.started_at or time.time()), 1),
                "total": s["total"], "finalized": s["finalized"],
                "pending": s["pending"],
            })
            del self.timeline[:-400]

    # ------------------------------------------------------------------
    def submit_reading(self, sensor_pd: str, value: float) -> dict:
        """Manual IoT device input from the GUI."""
        with self.lock:
            s = next((x for x in self.sensors if x.pd == sensor_pd), None)
            g = next((x for x in self.gateways if x.gid == (s.gateway_id if s else "")), None)
        if s is None or g is None:
            return {"ok": False, "error": "unknown sensor"}
        res = s.send(value, g, s.unit)
        if res["ok"]:
            self.log("reading",
                     f"{s.pd} ({s.kind}) sent {value} {s.unit} -> {g.gid}: "
                     f"{res['ciphertext_bytes']} B ciphertext, decrypted and hash-verified.",
                     res)
        else:
            self.log("rejected", f"{s.pd} reading rejected: {res.get('error')}", res)
        return res

    def publish(self, gateway_id: str) -> dict:
        g = next((x for x in self.gateways if x.gid == gateway_id), None)
        if g is None:
            return {"ok": False, "error": "unknown gateway"}
        res = g.publish()
        if res["ok"]:
            self.log("transaction",
                     f"{g.gid} published {res['tx']['tx_id']} from "
                     f"{res['readings_used']} readings; PoPQW solved in "
                     f"{res['popqw_ms']} ms (nonce {res['popqw_nonce']}).", res)
        else:
            self.log("rejected", f"{g.gid} publish failed: {res.get('error')}", res)
        self._sample()
        return res

    def publish_all(self) -> list[dict]:
        return [self.publish(g.gid) for g in self.gateways]

    # ------------------------------------------------------------------
    def _traffic(self, rate_hz: float):
        while not self._stop.is_set() and self.auto_traffic:
            for g in self.gateways:
                if self._stop.is_set() or not self.auto_traffic:
                    break
                mine = [s for s in self.sensors if s.gateway_id == g.gid]
                for s in mine:
                    s.send(round(random.uniform(s.lo, s.hi), 2), g, s.unit)
                self.publish(g.gid)
            time.sleep(max(0.05, 1.0 / max(rate_hz, 0.1)))

    def set_traffic(self, on: bool, rate_hz: float = 2.0) -> dict:
        if on and not self.gateways:
            raise RuntimeError("Build a network before starting sensor traffic.")
        self.auto_traffic = on
        if on and (self._traffic_thread is None or not self._traffic_thread.is_alive()):
            self._traffic_thread = threading.Thread(
                target=self._traffic, args=(rate_hz,), daemon=True)
            self._traffic_thread.start()
            self.log("setup", f"Automatic sensor traffic ON ({rate_hz} rounds/s).")
        elif not on:
            self.log("setup", "Automatic sensor traffic OFF.")
        return {"ok": True, "auto_traffic": self.auto_traffic}

    def stop(self):
        self.auto_traffic = False
        self._stop.set()
        time.sleep(0.1)

    # ------------------------------------------------------------------
    # Adversarial checks - does the design actually reject bad input?
    # ------------------------------------------------------------------
    def run_security_checks(self) -> list[dict]:
        if not self.gateways or not self.sensors:
            raise RuntimeError("Build a network before running the adversarial checks.")
        out = []
        g = self.gateways[0]
        s = self.sensors[0]

        # 0a. registration under a public key the caller does not own
        #     (Algorithm 1 proof-of-possession)
        impostor_nonce = self.server.issue_challenge("SN-IMPOSTOR-98")
        wrong_sig = crypto.sign(self.sensors[1].sig_key.secret, impostor_nonce)
        r0 = self.server.register_node("SN-IMPOSTOR-98", "sensor",
                                       s.sig_key.public,     # victim's public key
                                       wrong_sig, impostor_nonce)
        out.append({
            "check": "Register under a public key you do not own",
            "expectation": "Server refuses: signature does not verify under the "
                           "claimed key (Alg. 1, proof-of-possession)",
            "result": "REJECTED" if not r0["ok"] else "ACCEPTED",
            "pass": not r0["ok"],
            "detail": r0.get("error", ""),
        })

        # 0b. tampered membership proof
        proof = self.server.prove_membership(s.pd)
        root = self.server.bc_id.identity_root()
        inner = proof.get("proof") or {}
        siblings = inner.get("path") or inner.get("sibs")
        if proof.get("ok") and siblings:
            bad = dict(proof)
            bad["proof"] = dict(inner)
            if "path" in inner:          # sorted-array Merkle
                bad["proof"]["path"] = [(("f" * 64) if sib is not None else None, d)
                                        for sib, d in inner["path"]]
            else:                        # sparse Merkle
                bad["proof"]["sibs"] = ["f" * 64 for _ in inner["sibs"]]
            v = Server.verify_membership(s.pd, "sensor", s.sig_key.public, bad, root)
            detail = v.get("error", "")
        else:
            # single-node registry: no siblings to tamper with, so forge the leaf
            v = Server.verify_membership(s.pd, "gateway", s.sig_key.public,
                                         proof, root)
            detail = v.get("error", "")
        out.append({
            "check": "Tamper with a membership proof",
            "expectation": "Recomputed identity root does not match BC_ID's root",
            "result": "REJECTED" if not v["ok"] else "ACCEPTED",
            "pass": not v["ok"],
            "detail": detail,
        })

        # 1. unregistered sensor tries to open a session
        rogue = SensorNode(pd="SN-ROGUE-99", kind="speed", gateway_id=g.gid)
        r = rogue.establish_session(g)
        out.append({
            "check": "Unregistered sensor identity",
            "expectation": "Gateway refuses the session (Alg. 2, line 10)",
            "result": "REJECTED" if not r["ok"] else "ACCEPTED",
            "pass": not r["ok"],
            "detail": r.get("error", ""),
        })

        # 2. replayed / stale timestamp
        payload = f"{s.pd}:{s.kind}:99:{s.unit}"
        d = payload + "||" + crypto.sha256(payload)
        c = crypto.sym_encrypt(s.session_key, d.encode())
        r2 = g.receive(s.pd, c, time.time() - 4000)
        out.append({
            "check": "Replayed reading with a stale timestamp",
            "expectation": "Gateway discards it (Alg. 3, line 6)",
            "result": "REJECTED" if not r2["ok"] else "ACCEPTED",
            "pass": not r2["ok"],
            "detail": r2.get("error", ""),
        })

        # 3. ciphertext tampered in transit
        tampered = bytearray(c)
        tampered[-1] ^= 0xFF
        r3 = g.receive(s.pd, bytes(tampered), time.time())
        out.append({
            "check": "Ciphertext flipped in transit",
            "expectation": "AEAD authentication fails, reading discarded",
            "result": "REJECTED" if not r3["ok"] else "ACCEPTED",
            "pass": not r3["ok"],
            "detail": r3.get("error", ""),
        })

        # 4. transaction body edited after publication
        real = [t for t in self.ledger.txs.values() if t.gateway_id != "GENESIS"]
        if real:
            victim = real[-1]
            with self.ledger.lock:      # keep the finaliser out while we tamper
                original = victim.ciphertext
                victim.ciphertext = original + b"tamper"
                ok, why = self.ledger.verify_parent(victim.tx_id)
                victim.ciphertext = original
            out.append({
                "check": "Ledger transaction edited after publication",
                "expectation": "Hash check fails on verification (Alg. 4)",
                "result": "REJECTED" if not ok else "ACCEPTED",
                "pass": not ok,
                "detail": why,
            })

        # 5. forged finalisation certificate
        if real:
            victim = real[-1]
            forged = crypto.sign(crypto.sig_keygen().secret,
                                 bytes.fromhex(victim.tx_hash))
            valid = crypto.verify(self.gateways[0].sig_key.public,
                                  bytes.fromhex(victim.tx_hash), forged)
            out.append({
                "check": "Finalisation certificate signed by a non-gateway key",
                "expectation": "ML-DSA verification against the gateway key fails",
                "result": "REJECTED" if not valid else "ACCEPTED",
                "pass": not valid,
                "detail": "signature does not verify under the registered gateway key",
            })

        with self.lock:
            self.security_checks = out
        self.log("security",
                 f"Adversarial checks: {sum(1 for o in out if o['pass'])}/{len(out)} "
                 f"rejected as designed.")
        return out

    # ------------------------------------------------------------------
    def snapshot(self, tx_limit: int = 40) -> dict:
        if not self.ledger:
            return {"built": False}
        with self.lock:
            order = self.ledger.order[-tx_limit:]
            txs = [self.ledger.txs[i].to_public() for i in order]
            return {
                "built": True,
                "params": self.params,
                "setup": self.setup_report,
                "stats": self.ledger.stats(),
                "txs": txs,
                "timeline": list(self.timeline[-120:]),
                "events": list(self.events[:40]),
                "auto_traffic": self.auto_traffic,
                "security_checks": self.security_checks,
                "design_notes": DESIGN_NOTES,
                "gateways": [
                    {"gid": g.gid, "buffered": len(g.buffer),
                     "sessions": len(g.sessions), "discarded": len(g.discarded)}
                    for g in self.gateways
                ],
                "sensors": [
                    {"pd": s.pd, "kind": s.kind, "unit": s.unit,
                     "gateway": s.gateway_id, "registered": s.registered,
                     "session": s.session_key is not None,
                     "handshake_ms": round(s.handshake_ms, 2),
                     "sent": s.readings_sent,
                     "last": s.last_reading}
                    for s in self.sensors
                ],
                "registration_chain": self.server.bc_id.public()[-12:],
            }


SIM = LiveSimulation()
