"""
Reference baseline: a linear post-quantum blockchain with Pre-Selected Node
(PSN) consensus, in the style of the comparison system used in the paper.

Same cryptography, same PoPQW difficulty, same t-of-n signing cost. The only
structural difference is the one under test: blocks form a single chain, so
exactly one gateway can extend the ledger at a time and every other gateway
waits. This is the control condition for the DAG claim.
"""

from __future__ import annotations

import threading
import time

from . import crypto
from .ledger import merkle_root, solve_popqw


class LinearChain:
    def __init__(self, difficulty_bits: int = 12, endorsers_t: int = 3,
                 confirm_depth: int = 3):
        self.difficulty = difficulty_bits
        self.t = endorsers_t
        self.confirm_depth = confirm_depth
        self.blocks: list[dict] = [
            {"index": 0, "gateway_id": "GENESIS", "prev": "0" * 64,
             "hash": crypto.sha256("linear-genesis"), "created_at": time.time(),
             "confirmed": True, "confirmed_at": time.time(), "tx_count": 0}
        ]
        self.lock = threading.Lock()   # the serialisation point under test
        self.contention_ms = 0.0

    def append(self, gateway_id: str, ciphertext: bytes, endorsers: list,
               sensor_count: int = 0) -> dict:
        wait0 = time.perf_counter()
        with self.lock:
            waited = (time.perf_counter() - wait0) * 1000.0
            self.contention_ms += waited

            prev = self.blocks[-1]["hash"]
            index = len(self.blocks)
            created = time.time()
            header = crypto.sha256(index, gateway_id, ciphertext, f"{created:.6f}", prev)
            mr = merkle_root([prev, header])
            nonce, _h, pow_ms = solve_popqw(header, gateway_id, self.difficulty)

            # PSN endorsement: t pre-selected nodes sign the block
            sigs = []
            for g in endorsers[: self.t]:
                sigs.append(crypto.sign(g.sig_key.secret, bytes.fromhex(header)))

            blk = {
                "index": index, "gateway_id": gateway_id, "prev": prev,
                "hash": header, "merkle_root": mr, "nonce": nonce,
                "created_at": created, "confirmed": False, "confirmed_at": None,
                "tx_count": sensor_count, "cert_bytes": sum(len(s) for s in sigs),
                "popqw_ms": pow_ms, "queue_wait_ms": waited,
            }
            self.blocks.append(blk)

            # depth-based confirmation
            for b in self.blocks:
                if not b["confirmed"] and (index - b["index"]) >= self.confirm_depth:
                    b["confirmed"] = True
                    b["confirmed_at"] = time.time()
            return blk

    def stats(self) -> dict:
        real = [b for b in self.blocks if b["gateway_id"] != "GENESIS"]
        conf = [b for b in real if b["confirmed"]]
        lat = [b["confirmed_at"] - b["created_at"] for b in conf if b["confirmed_at"]]
        return {
            "total": len(real),
            "finalized": len(conf),
            "pending": len(real) - len(conf),
            "avg_finalization_latency_s": (sum(lat) / len(lat)) if lat else None,
            "total_queue_wait_ms": round(self.contention_ms, 1),
        }
