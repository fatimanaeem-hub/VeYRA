"""
Vehicular Sensor Network roles: Sensor, Gateway, Server.

Follows the paper's Algorithms 1-3:
  Alg. 1  registration of a sensor node into the registration chain BC_ID
  Alg. 2  one-time post-quantum session-key establishment sensor <-> gateway
  Alg. 3  gateway decryption, hash verification, aggregation, re-encryption

Every step is instrumented so the GUI can show what it cost.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

from . import crypto
from .identity import STRUCTURES, verify_proof
from .ledger import DagLedger, Transaction, merkle_root, solve_popqw


# --------------------------------------------------------------------------
# BC_ID : registration blockchain (Algorithm 1)
# --------------------------------------------------------------------------


class RegistrationChain:
    """Hash-linked ledger of registered node identities, with a Merkle commitment.

    The chain answers "what happened, in what order". The identity root answers
    "who is registered right now" in 32 bytes, so a gateway can prove a node's
    registration to a third party without handing over the whole registry.

    Both are kept: the chain is the audit trail, the root is the evidence.
    """

    def __init__(self, identity_structure: str = "sorted"):
        self.idset = STRUCTURES[identity_structure]()
        self.blocks: list[dict] = [
            {"index": 0, "pd": "GENESIS", "role": "system", "prev": "0" * 64,
             "hash": crypto.sha256("bcid-genesis"), "ts": time.time(),
             "id_root": self.idset.root()}
        ]
        self.index: dict[str, dict] = {}
        self.leaves: dict[str, str] = {}        # PD -> leaf
        self.epochs: list[dict] = []            # populated only in batch mode

    # ---- identity commitment -------------------------------------------

    @staticmethod
    def leaf_for(pd: str, role: str, pubkey: bytes) -> str:
        """L = H(PD || role || PK). Binds identity, role and key together, so a
        sensor cannot later present itself as a gateway with the same key."""
        return crypto.sha256(pd, role, pubkey.hex())

    def identity_root(self) -> str:
        return self.idset.root()

    def prove(self, pd: str) -> dict:
        """Inclusion proof for one identity against the current root.

        Generated on demand rather than issued once, so re-registration churn
        never leaves a device holding a stale proof.
        """
        leaf = self.leaves.get(pd)
        if leaf is None:
            return {"ok": False, "error": f"{pd} is not registered"}
        proof = self.idset.prove(leaf)
        if proof is None:
            return {"ok": False, "error": f"{pd} is not in the committed set"}
        return {"ok": True, "leaf": leaf, "proof": proof,
                "root": self.idset.root(), "set_size": len(self.idset),
                "structure": self.idset.kind, "proof_bytes": proof["bytes"]}

    def exists(self, pd: str) -> bool:
        return pd in self.index

    def register(self, pd: str, role: str, pubkey_digest: str,
                 leaf: str | None = None) -> dict:
        if self.exists(pd):
            return {"ok": False, "error": f"{pd} already registered"}
        if leaf is not None:
            self.leaves[pd] = leaf
            self.idset.insert(leaf)
        blk = self._append_block(pd, role, pubkey_digest)
        return {"ok": True, "block": blk}

    def _append_block(self, pd: str, role: str, pubkey_digest: str) -> dict:
        prev = self.blocks[-1]["hash"]
        blk = {
            "index": len(self.blocks), "pd": pd, "role": role,
            "pubkey_digest": pubkey_digest, "prev": prev, "ts": time.time(),
            "id_root": self.idset.root(),       # commits to the set after this step
        }
        blk["hash"] = crypto.sha256(blk["index"], pd, role, pubkey_digest, prev,
                                    blk["id_root"])
        self.blocks.append(blk)
        self.index[pd] = blk
        return blk

    # ---- batch mode: one block and one anchor for the whole epoch --------

    def commit_epoch(self, members: list[tuple[str, str, str, str]]) -> dict:
        """Insert every member, then write ONE block for the epoch.

        members: (pd, role, pubkey_digest, leaf)

        This is the only structural difference batching makes to the registry.
        Individually, n registrations write n blocks and produce n roots to
        anchor. Batched, they write one block and produce one root - which is
        what the certificate-byte argument turns on.
        """
        t0 = time.perf_counter()
        for pd, _role, _dig, leaf in members:
            self.leaves[pd] = leaf
            self.idset.insert(leaf)
        insert_ms = (time.perf_counter() - t0) * 1000.0

        t1 = time.perf_counter()
        root = self.idset.root()
        root_ms = (time.perf_counter() - t1) * 1000.0

        epoch_no = len(self.epochs)
        blk = self._append_block(f"EPOCH-{epoch_no}", "epoch-root", root[:16])
        for pd, role, dig, _leaf in members:          # index them for exists()
            self.index[pd] = blk
        ep = {"epoch": epoch_no, "root": root, "members": len(members),
              "block": blk["index"], "closed_at": time.time()}
        self.epochs.append(ep)
        return {"ok": True, "epoch": epoch_no, "members": len(members),
                "root": root[:16], "blocks_written": 1,
                "blocks_avoided": len(members) - 1,
                "insert_ms": round(insert_ms, 3), "root_ms": round(root_ms, 3),
                "structure": self.idset.kind}

    def public(self) -> list[dict]:
        return [
            {"index": b["index"], "pd": b["pd"], "role": b["role"],
             "hash": b["hash"][:16], "prev": b["prev"][:16], "ts": b["ts"],
             "id_root": b.get("id_root", "")[:16]}
            for b in self.blocks
        ]


# --------------------------------------------------------------------------
# Sensor node
# --------------------------------------------------------------------------


@dataclass
class SensorNode:
    pd: str                     # PD_ij : sensor identity
    kind: str                   # speed / co2 / lidar-range / temperature ...
    gateway_id: str
    registered: bool = False
    session_key: bytes | None = None
    handshake_ms: float = 0.0
    readings_sent: int = 0
    last_reading: dict | None = None
    # ML-DSA identity key. The secret never leaves the node; registration proves
    # possession of it rather than trusting whatever public key is presented.
    sig_key: crypto.KeyPair = field(default_factory=crypto.sig_keygen)

    def prove_possession(self, nonce: bytes) -> bytes:
        """Sign the server's registration challenge with our own secret key."""
        return crypto.sign(self.sig_key.secret, nonce)

    # ---- Algorithm 2 (sensor side) ------------------------------------
    def establish_session(self, gateway: "Gateway") -> dict:
        """One-time post-quantum session-key establishment."""
        t0 = time.perf_counter()

        # C1 = Encaps(P_j)  -> gateway learns R_ij ; C2 = SymEnc_{R_ij}(PD_ij)
        r_ij, c1 = crypto.kem_encaps(gateway.kem_key.public)
        c2 = crypto.sym_encrypt(r_ij, self.pd.encode())

        resp = gateway.accept_session(self.pd, c1, c2)
        if not resp["ok"]:
            self.handshake_ms = (time.perf_counter() - t0) * 1000.0
            return resp

        # sensor decrypts C3 = SymEnc_{R_ij}(R_j || H_j || Nn), checks H_j
        r_j, h_j, nn = crypto.sym_decrypt(r_ij, resp["c3"]).split(b"||")
        if crypto.sha256(r_j) != h_j.decode():
            self.handshake_ms = (time.perf_counter() - t0) * 1000.0
            return {"ok": False, "error": "gateway hash check failed"}

        self.session_key = r_j + r_ij            # Sk_ij = R_j || R_ij
        self.handshake_ms = (time.perf_counter() - t0) * 1000.0
        return {
            "ok": True,
            "handshake_ms": self.handshake_ms,
            "kem_ciphertext_bytes": len(c1),
            "session_key_digest": crypto.sha256(self.session_key)[:16],
        }

    # ---- Equations 3-4: send a reading ---------------------------------
    def send(self, value: float, gateway: "Gateway", unit: str = "") -> dict:
        if self.session_key is None:
            return {"ok": False, "error": "no session key - run the handshake first"}
        t0 = time.perf_counter()
        payload = f"{self.pd}:{self.kind}:{value}:{unit}"
        d_ij = payload + "||" + crypto.sha256(payload)      # Eq. 3
        c_ij = crypto.sym_encrypt(self.session_key, d_ij.encode())  # Eq. 4
        tso = time.time()
        enc_ms = (time.perf_counter() - t0) * 1000.0
        res = gateway.receive(self.pd, c_ij, tso)
        self.readings_sent += 1
        self.last_reading = {"value": value, "unit": unit, "at": tso}
        res.update({"encrypt_ms": enc_ms, "ciphertext_bytes": len(c_ij)})
        return res


# --------------------------------------------------------------------------
# Gateway  (RSU / roadside unit)
# --------------------------------------------------------------------------


class Gateway:
    def __init__(self, gid: str, server: "Server", ledger: DagLedger):
        self.gid = gid
        self.server = server
        self.ledger = ledger
        self.kem_key = crypto.kem_keygen()      # (P_j, S_j) - Kyber
        self.sig_key = crypto.sig_keygen()      # ML-DSA key for tPQ-Sig
        self.sessions: dict[str, bytes] = {}    # PD_ij -> Sk_ij
        self.buffer: list[dict] = []            # decrypted, verified readings
        self.log: list[dict] = []
        self.discarded: list[dict] = []

    # ---- Algorithm 2 (gateway side) ------------------------------------
    def accept_session(self, pd: str, c1: bytes, c2: bytes) -> dict:
        r_ij = crypto.kem_decaps(self.kem_key.secret, c1)
        try:
            claimed = crypto.sym_decrypt(r_ij, c2).decode()
        except Exception:
            return {"ok": False, "error": "C2 could not be decrypted"}
        if claimed != pd:
            return {"ok": False, "error": "identity in C2 does not match"}

        # Alg. 2 line 10: identity must be on the registration blockchain
        if not self.server.bc_id.exists(pd):
            self.log.append({"event": "auth-reject", "pd": pd,
                             "why": "not registered on BC_ID", "at": time.time()})
            return {"ok": False, "error": f"{pd} is not registered on BC_ID"}

        import os

        r_j = os.urandom(16)
        nn = os.urandom(8)
        h_j = crypto.sha256(r_j).encode()
        c3 = crypto.sym_encrypt(r_ij, r_j + b"||" + h_j + b"||" + nn)
        self.sessions[pd] = r_j + r_ij
        self.log.append({"event": "session-established", "pd": pd, "at": time.time()})
        return {"ok": True, "c3": c3}

    # ---- Algorithm 3 ----------------------------------------------------
    def receive(self, pd: str, c_ij: bytes, tso: float,
                freshness_window_s: float = 120.0) -> dict:
        key = self.sessions.get(pd)
        if key is None:
            return {"ok": False, "error": "unknown session"}

        if abs(time.time() - tso) > freshness_window_s:      # Alg. 3 line 6
            self.discarded.append({"pd": pd, "why": "stale timestamp (replay)",
                                   "at": time.time()})
            return {"ok": False, "error": "timestamp outside freshness window"}

        t0 = time.perf_counter()
        try:
            d_ij = crypto.sym_decrypt(key, c_ij).decode()
        except Exception:
            self.discarded.append({"pd": pd, "why": "authentication tag failed",
                                   "at": time.time()})
            return {"ok": False, "error": "ciphertext failed authentication"}
        dec_ms = (time.perf_counter() - t0) * 1000.0

        payload, digest = d_ij.rsplit("||", 1)
        if crypto.sha256(payload) != digest:                  # integrity check
            self.discarded.append({"pd": pd, "why": "payload hash mismatch",
                                   "at": time.time()})
            return {"ok": False, "error": "payload hash mismatch - discarded"}

        parts = payload.split(":")
        self.buffer.append(
            {"pd": parts[0], "kind": parts[1], "value": float(parts[2]),
             "unit": parts[3] if len(parts) > 3 else "", "tso": tso}
        )
        return {"ok": True, "decrypt_ms": dec_ms, "buffered": len(self.buffer),
                "kind": parts[1], "value": float(parts[2])}

    # ---- Eq. 6-7 + Alg. 4: aggregate and publish a DAG transaction -----
    def aggregate(self, mode: str = "avg"):
        """Eq. 6: AGG over the readings buffered since the last publish."""
        if not self.buffer:
            return None, None, 0
        readings, self.buffer = self.buffer, []
        by_kind: dict[str, list[float]] = {}
        for r in readings:
            by_kind.setdefault(r["kind"], []).append(r["value"])
        agg = {}
        for kind, vals in by_kind.items():
            if mode == "max":
                agg[kind] = max(vals)
            elif mode == "min":
                agg[kind] = min(vals)
            elif mode == "sum":
                agg[kind] = round(sum(vals), 3)
            else:
                agg[kind] = round(sum(vals) / len(vals), 3)
        return agg, ";".join(f"{k}={v}" for k, v in sorted(agg.items())), len(readings)

    def publish(self, mode: str = "avg", max_retries: int = 3) -> dict:
        agg, d_j, n_readings = self.aggregate(mode)
        if agg is None:
            return {"ok": False, "error": "nothing buffered to aggregate"}

        t_enc = time.perf_counter()
        c_j = crypto.sym_encrypt(self.server.session_key_for(self.gid), d_j.encode())  # Eq. 7
        enc_ms = (time.perf_counter() - t_enc) * 1000.0

        retries = 0
        for attempt in range(max_retries):
            parents = self.ledger.select_parents()                      # Alg. 4
            prev_hash = self.ledger.txs[self.ledger.order[-1]].tx_hash  # H_pb
            tso = time.time()

            tx = Transaction(
                tx_id=self.ledger.next_id(self.gid), gateway_id=self.gid,
                ciphertext=c_j, timestamp=tso, parents=parents,
                prev_hash=prev_hash, merkle_root="", popqw_nonce=0,
                popqw_difficulty=self.ledger.difficulty, tx_hash="",
                sensor_count=n_readings, payload_preview=d_j, created_at=tso,
            )
            tx.tx_hash = tx.header()                              # Eq. 11 / Alg. 4 l.4
            tx.merkle_root = merkle_root([*parents, tx.tx_hash])  # Alg. 4 l.5-6

            nonce, pq_hash, pow_ms = solve_popqw(
                tx.tx_hash, self.gid, self.ledger.difficulty)      # Alg. 5 l.13-22
            tx.popqw_nonce = nonce

            result = self.ledger.append(tx)
            if result["accepted"]:
                return {
                    "ok": True, "tx": tx.to_public(),
                    "parent_checks": result["checks"], "aggregated": agg,
                    "aggregate_plaintext": d_j, "readings_used": n_readings,
                    "aggregate_encrypt_ms": round(enc_ms, 3),
                    "popqw_ms": round(pow_ms, 2), "popqw_nonce": nonce,
                    "popqw_hash": pq_hash[:20], "retries": retries,
                }
            retries += 1
            self.ledger.retry_count += 1

        return {"ok": False, "error": "parents kept being finalised under us",
                "retries": retries, "parent_checks": result["checks"]}


# --------------------------------------------------------------------------
# Server
# --------------------------------------------------------------------------


class Server:
    CHALLENGE_TTL_S = 30.0

    def __init__(self, batch_registration: bool = False,
                 identity_structure: str = "sorted"):
        self.kem_key = crypto.kem_keygen()      # (P_s, S_s)
        self.batch_registration = batch_registration
        self.bc_id = RegistrationChain(identity_structure)
        self.pending: dict[str, tuple] = {}     # used only in batch mode
        self._gw_keys: dict[str, bytes] = {}
        self._challenges: dict[str, tuple[bytes, float]] = {}   # PD -> (nonce, issued)
        self._spent_nonces: set[str] = set()
        self.rejected_registrations: list[dict] = []

    # ---- Algorithm 1, step 1: challenge ---------------------------------

    def issue_challenge(self, pd: str) -> bytes:
        """Fresh random nonce the node must sign to prove it holds the secret key."""
        nonce = os.urandom(32)
        self._challenges[pd] = (nonce, time.time())
        return nonce

    # ---- Algorithm 1, step 2: register, only on a valid proof -----------

    def register_node(self, pd: str, role: str, pubkey: bytes,
                      pop_signature: bytes | None = None,
                      nonce: bytes | None = None) -> dict:
        """Register an identity.

        Proof-of-possession is mandatory: the node must return a signature over
        the challenge we issued, verifiable under the public key it is claiming.
        Without this, anyone able to reach the server could register any public
        key under any identity - including a key copied from a real sensor.
        """
        def reject(why, stage):
            rec = {"pd": pd, "role": role, "why": why, "stage": stage,
                   "at": time.time()}
            self.rejected_registrations.append(rec)
            return {"ok": False, "error": why, "stage": stage}

        if pop_signature is None or nonce is None:
            return reject("no proof-of-possession supplied", "PoP required")

        issued = self._challenges.get(pd)
        if issued is None:
            return reject("no challenge was issued for this identity", "challenge lookup")

        expected, at = issued
        if nonce != expected:
            return reject("challenge does not match the one issued", "challenge match")

        nonce_hex = nonce.hex()
        if nonce_hex in self._spent_nonces:
            return reject("challenge already used", "replay check")

        if time.time() - at > self.CHALLENGE_TTL_S:
            return reject("challenge expired", "freshness check")

        if not crypto.verify(pubkey, nonce, pop_signature):
            return reject("proof-of-possession failed - signature does not verify "
                          "under the claimed public key", "PoP verification")

        # the proof is good; burn the nonce and the challenge so neither is reusable
        self._spent_nonces.add(nonce_hex)
        self._challenges.pop(pd, None)

        leaf = RegistrationChain.leaf_for(pd, role, pubkey)
        digest = crypto.sha256(pubkey)[:16]

        if self.batch_registration:
            # The proof was checked; the identity waits for the window to close.
            # Nothing is written to BC_ID and no root changes until then.
            self.pending[pd] = (pd, role, digest, leaf)
            return {"ok": True, "pending": True, "queued": len(self.pending),
                    "stage": "queued for epoch"}

        return self.bc_id.register(pd, role, digest, leaf)

    def close_registration_epoch(self) -> dict:
        """Close the open window: commit every queued identity as one epoch."""
        if not self.batch_registration:
            return {"ok": False, "error": "server is not in batch mode"}
        if not self.pending:
            return {"ok": False, "error": "no identities queued"}
        members = list(self.pending.values())
        self.pending.clear()
        return self.bc_id.commit_epoch(members)

    # ---- membership proof ------------------------------------------------

    def prove_membership(self, pd: str) -> dict:
        return self.bc_id.prove(pd)

    @staticmethod
    def verify_membership(pd: str, role: str, pubkey: bytes,
                          proof: dict, trusted_root: str) -> dict:
        """Verify registration from a proof alone - no access to the registry.

        This is what the hash-linked chain could not do: a 32-byte root plus a
        few hundred bytes of path settles the question for any third party.
        """
        if not proof.get("ok"):
            return {"ok": False, "error": "no proof", "stage": "proof present"}
        leaf = RegistrationChain.leaf_for(pd, role, pubkey)
        if leaf != proof["leaf"]:
            return {"ok": False, "stage": "leaf recomputation",
                    "error": "identity/role/key do not produce the proof's leaf"}
        if not verify_proof(leaf, proof["proof"], trusted_root):
            return {"ok": False, "stage": "path verification",
                    "error": "recomputed root does not match the trusted root"}
        return {"ok": True, "stage": "inclusion proof",
                "structure": proof.get("structure"),
                "proof_bytes": proof["proof_bytes"], "set_size": proof["set_size"]}

    def session_key_for(self, gid: str) -> bytes:
        """Sk_j - gateway<->server key, established the same way as Sk_ij
        (paper says the process is identical, so it is not repeated here)."""
        if gid not in self._gw_keys:
            ss, _ct = crypto.kem_encaps(self.kem_key.public)
            self._gw_keys[gid] = ss
        return self._gw_keys[gid]
