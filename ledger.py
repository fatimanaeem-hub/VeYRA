"""
DAG ledger for the PQ-DAG VSN proof of concept.

Implements, at small scale, the structures of the reference paper:
  Eq. 10 / Alg. 4  transaction with two parent references
  Alg. 5           Merkle root, PoPQW puzzle, reference-count finalisation
  Eq. 12           t-of-n post-quantum finalisation certificate (tPQ-Sig)

Honest deviations from the paper are recorded in DESIGN_NOTES and are surfaced
in the GUI, because a proof of concept that hides its simplifications is not
evidence.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from . import crypto

# --------------------------------------------------------------------------
# Finalisation threshold: the paper's scale, mapped onto this prototype's range
# --------------------------------------------------------------------------
#
# FT is NOT a free parameter. The paper states it "is decided based on the size
# of the network" and gives reference values for static networks in Table III:
#
#     Small  DAG   10 - 100 nodes    ->  3 references
#     Medium DAG  100 - 1,000 nodes  ->  5 references
#     Large  DAG  1,000+ nodes       -> 10 references
#
# Those absolute numbers cannot be used directly. A node here is a sensor or a
# gateway, and this prototype tops out at MAX_NODES - every network it can build
# would land in the paper's smallest band, so FT would be 3 forever and the
# relationship between size and threshold would never be visible.
#
# So we keep the paper's *scale* and rescale its axis. The paper's table spans
# three bands across two orders of magnitude (10 -> 100 -> 1,000), i.e. three
# geometric steps. We divide our own range the same way: MIN_NODES to MAX_NODES
# split into three geometric bands, each carrying the paper's FT for that band.
#
#     exact geometric boundaries for 2..72 are 6.6 and 21.8
#     (ratio = (72/2) ** (1/3) = 3.30)
#     rounded to 8 and 24 for legibility - that rounding is ours, not the paper's
#
# The FT values themselves are unchanged: 3, 5, 10, exactly as published. Only
# the node counts that select between them are compressed.

MIN_NODES = 2    # 1 gateway with 1 sensor
MAX_NODES = 72   # 8 gateways with 8 sensors each - the UI caps

# Table III as published, kept verbatim for display and for the write-up.
PAPER_FT_TABLE = [
    (10,   100,  3,  "Small DAG"),
    (101,  1000, 5,  "Medium DAG"),
    (1001, None, 10, "Large DAG"),
]

# The same three bands, rescaled onto 2..72 nodes.
FT_TABLE = [
    (0,  8,    3,  "Small DAG",  "10-100 nodes"),
    (9,  24,   5,  "Medium DAG", "101-1,000 nodes"),
    (25, None, 10, "Large DAG",  "1,001+ nodes"),
]


def finalization_threshold(n_nodes: int) -> dict:
    """Derive FT from network size. There is deliberately no way to override it."""
    for lo, hi, ft, band, paper_range in FT_TABLE:
        if n_nodes >= lo and (hi is None or n_nodes <= hi):
            lo_shown = max(lo, MIN_NODES)
            return {
                "nodes": n_nodes,
                "FT": ft,
                "band": band,
                "range": f"{lo_shown}-{hi} nodes" if hi else f"{lo_shown}+ nodes",
                "paper_range": paper_range,
                "scaled": True,
            }
    raise ValueError(f"no finalisation band for {n_nodes} nodes")


DESIGN_NOTES = [
    {
        "topic": "FT is derived from network size, never chosen",
        "detail": (
            "The paper decides the finalisation threshold from the number of "
            "nodes (Table III). This prototype does the same: FT is computed at "
            "build time from sensors + gateways and cannot be set by hand, so a "
            "small network cannot be given a large network's threshold to "
            "flatter the results."
        ),
    },
    {
        "topic": "The node counts that select FT are rescaled, the FT values are not",
        "detail": (
            "The paper's bands start at 10, 100 and 1,000 nodes. This prototype "
            "can build at most 72 nodes, so every network would sit in the "
            "paper's smallest band and FT would never move off 3. We keep the "
            "paper's three-band geometric scale and its published thresholds "
            "(3, 5, 10) but compress the axis onto 2-72 nodes, giving bands at "
            "2-8, 9-24 and 25-72. The compression is ours and is stated wherever "
            "the threshold is shown; the thresholds themselves are the paper's."
        ),
    },
    {
        "topic": "tPQ-Sig is a t-of-n multi-signature, not a compact threshold signature",
        "detail": (
            "No threshold variant of ML-DSA is standardised by NIST today. This "
            "prototype collects t independent ML-DSA-44 signatures and verifies "
            "all of them. Security (t honest gateways must agree) is preserved; "
            "compactness is not - the certificate grows linearly with t."
        ),
    },
    {
        "topic": "PoPQW uses a SHA-256 puzzle",
        "detail": (
            "This follows Eq. 8-9 of the paper. A SHA-256 puzzle is not itself "
            "post-quantum hard in the strong sense: Grover's algorithm gives a "
            "quadratic speed-up, so the difficulty target must be squared to keep "
            "the same margin against a quantum miner."
        ),
    },
    {
        "topic": "Single-process simulation",
        "detail": (
            "Sensors, gateways and the server run as threads in one process. "
            "Network latency, packet loss and clock skew are not modelled. The "
            "prototype measures cryptographic and consensus cost, not radio cost."
        ),
    },
]


# --------------------------------------------------------------------------
# Merkle root  (Alg. 5, lines 3-12)
# --------------------------------------------------------------------------


def merkle_root(hashes: list[str]) -> str:
    if not hashes:
        return crypto.sha256(b"")
    level = list(hashes)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(crypto.sha256(level[i], level[i + 1]))
        if len(level) % 2:
            nxt.append(level[-1])  # carry the odd hash up
        level = nxt
    return level[0]


def merkle_path(hashes: list[str], index: int) -> list:
    """Inclusion path for hashes[index], following merkle_root's carry-up rule.

    Returned as [(sibling, is_right), ...]. A (None, None) entry means the node
    was carried up untouched because its level had odd length.
    """
    level = list(hashes)
    idx = index
    path: list = []
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(crypto.sha256(level[i], level[i + 1]))
        carried = len(level) % 2
        if carried:
            nxt.append(level[-1])
        if carried and idx == len(level) - 1:
            path.append((None, None))          # carried, no sibling to hash with
            idx = len(nxt) - 1
        else:
            sib = idx ^ 1
            path.append((level[sib], idx & 1))
            idx >>= 1
        level = nxt
    return path


def merkle_verify(leaf: str, path: list, root: str) -> bool:
    """Recompute the root from a leaf and its path. No access to the set needed."""
    h = leaf
    for sib, is_right in path:
        if sib is None:
            continue
        h = crypto.sha256(sib, h) if is_right else crypto.sha256(h, sib)
    return h == root


# --------------------------------------------------------------------------
# PoPQW  (Eq. 8-9, Alg. 5 lines 13-22)
# --------------------------------------------------------------------------


def solve_popqw(tx_hash: str, challenge: str, difficulty_bits: int, cap: int = 5_000_000):
    """Find nonce N such that SHA256(H || N) has `difficulty_bits` leading zero bits."""
    base = crypto.sha256(tx_hash, challenge)
    prefix = "0" * (difficulty_bits // 4)
    remainder = difficulty_bits % 4
    t0 = time.perf_counter()
    nonce = 0
    while nonce < cap:
        h = crypto.sha256(base, nonce)
        if h.startswith(prefix):
            if remainder == 0 or int(h[len(prefix)], 16) < (1 << (4 - remainder)):
                return nonce, h, (time.perf_counter() - t0) * 1000.0
        nonce += 1
    raise RuntimeError("PoPQW nonce cap exceeded - lower the difficulty")


def check_popqw(tx_hash: str, challenge: str, nonce: int, difficulty_bits: int) -> bool:
    base = crypto.sha256(tx_hash, challenge)
    h = crypto.sha256(base, nonce)
    prefix = "0" * (difficulty_bits // 4)
    if not h.startswith(prefix):
        return False
    remainder = difficulty_bits % 4
    return remainder == 0 or int(h[len(prefix)], 16) < (1 << (4 - remainder))


# --------------------------------------------------------------------------
# Transaction  (Eq. 10)
# --------------------------------------------------------------------------


@dataclass
class Transaction:
    tx_id: str
    gateway_id: str
    ciphertext: bytes            # C_j : encrypted aggregated sensor data
    timestamp: float             # tso
    parents: list[str]           # H(Tx_i), H(Tx_k)
    prev_hash: str               # H_pb
    merkle_root: str             # MR
    popqw_nonce: int             # N
    popqw_difficulty: int        # D
    tx_hash: str                 # H(Tx_j)
    sensor_count: int = 0
    payload_preview: str = ""    # plaintext echo, for the GUI only
    references: int = 0          # direct children only
    weight: int = 0              # Reference_Count: direct + indirect approvals
    finalized: bool = False
    finalized_at: float | None = None
    tpq_sig: list[dict] = field(default_factory=list)
    created_at: float = 0.0

    def header(self) -> str:
        """H(Tx_j) per Eq. 11 / Alg. 4 line 4.

        Deliberately excludes the Merkle root: MR is computed *from* this hash
        (Alg. 4 lines 5-6), so including it here would be circular.
        """
        return crypto.sha256(
            self.gateway_id,
            self.ciphertext,
            f"{self.timestamp:.6f}",
            "|".join(self.parents),
            self.prev_hash,
        )

    def to_public(self) -> dict:
        return {
            "tx_id": self.tx_id,
            "gateway_id": self.gateway_id,
            "timestamp": self.timestamp,
            "parents": self.parents,
            "prev_hash": self.prev_hash[:16],
            "merkle_root": self.merkle_root[:16],
            "popqw_nonce": self.popqw_nonce,
            "popqw_difficulty": self.popqw_difficulty,
            "weight": self.weight,
            "tx_hash": self.tx_hash[:16],
            "tx_hash_full": self.tx_hash,
            "ciphertext_bytes": len(self.ciphertext),
            "ciphertext_preview": self.ciphertext[:24].hex(),
            "payload_preview": self.payload_preview,
            "sensor_count": self.sensor_count,
            "references": self.references,
            "finalized": self.finalized,
            "signers": [s["gateway_id"] for s in self.tpq_sig],
            "cert_bytes": sum(s["bytes"] for s in self.tpq_sig),
            "created_at": self.created_at,
            "finalized_at": self.finalized_at,
        }


# --------------------------------------------------------------------------
# DAG ledger
# --------------------------------------------------------------------------


class DagLedger:
    """BC_Data: the DAG blockchain holding encrypted aggregated sensor data."""

    def __init__(self, network_nodes: int, difficulty_bits: int = 12,
                 threshold_t: int = 3):
        self.txs: dict[str, Transaction] = {}
        self.order: list[str] = []
        # Table III: the threshold follows from the size of the network. It is
        # read-only on purpose - there is no setter and no constructor override.
        self.ft_band = finalization_threshold(network_nodes)
        self.network_nodes = network_nodes
        self.FT = self.ft_band["FT"]
        self.difficulty = difficulty_bits
        self.t = threshold_t
        self.lock = threading.RLock()
        self.rejected: list[dict] = []
        self.events: list[dict] = []
        self.retry_count = 0
        self._counter = 0
        self._genesis()

    # -- genesis -----------------------------------------------------------
    def _genesis(self, n: int = 10):
        for i in range(n):
            tid = f"GEN-{i:02d}"
            tx = Transaction(
                tx_id=tid,
                gateway_id="GENESIS",
                ciphertext=b"",
                timestamp=time.time(),
                parents=[],
                prev_hash="0" * 64,
                merkle_root=crypto.sha256(tid),
                popqw_nonce=0,
                popqw_difficulty=0,
                tx_hash=crypto.sha256("genesis", tid),
                created_at=time.time(),
            )
            self.txs[tid] = tx
            self.order.append(tid)

    # -- tip selection -----------------------------------------------------
    def select_parents(self) -> list[str]:
        """Pick two tips that are unfinalised and still short of the threshold.

        Finalised transactions are never referenced again (paper, Section IV-D),
        and referencing a transaction that already has FT references would waste
        the reference, so those are excluded too.
        """
        import random

        with self.lock:
            window = self.order[-80:]
            candidates = [
                t for t in window
                if not self.txs[t].finalized and self.txs[t].weight < self.FT
            ]
            if len(candidates) < 2:
                candidates = [
                    t for t in self.order
                    if not self.txs[t].finalized and self.txs[t].weight < self.FT
                ]
            if len(candidates) >= 2:
                return random.sample(candidates, 2)
            if len(candidates) == 1:
                return candidates * 2
            # everything is saturated: fall back to the newest transactions
            return (window[-2:] if len(window) >= 2 else window * 2)

    # -- verification of a parent (Alg. 4, lines 10-24) --------------------
    def verify_parent(self, parent_id: str) -> tuple[bool, str]:
        tx = self.txs.get(parent_id)
        if tx is None:
            return False, "parent not present in DAG"
        if tx.gateway_id == "GENESIS":
            return True, "genesis (implicitly valid)"
        if tx.finalized:
            return False, "already finalised - not eligible as a parent"
        if tx.tx_hash != tx.header():
            return False, "transaction hash does not match its header"
        expected_mr = merkle_root([*(p for p in tx.parents), tx.tx_hash])
        if expected_mr != tx.merkle_root:
            return False, "Merkle root mismatch"
        if not check_popqw(tx.tx_hash, tx.gateway_id, tx.popqw_nonce, tx.popqw_difficulty):
            return False, "PoPQW invalid"
        for p in tx.parents:
            if p not in self.txs:
                return False, "grandparent missing from DAG"
        return True, "verified"

    # -- append ------------------------------------------------------------
    def append(self, tx: Transaction) -> dict:
        with self.lock:
            checks = []
            for p in tx.parents:
                ok, why = self.verify_parent(p)
                checks.append({"parent": p, "ok": ok, "reason": why})
            if not all(c["ok"] for c in checks):
                self.rejected.append(
                    {"tx_id": tx.tx_id, "reason": "parent verification failed",
                     "checks": checks, "at": time.time()}
                )
                return {"accepted": False, "checks": checks}

            if not check_popqw(tx.tx_hash, tx.gateway_id, tx.popqw_nonce, tx.popqw_difficulty):
                self.rejected.append(
                    {"tx_id": tx.tx_id, "reason": "own PoPQW invalid", "at": time.time()}
                )
                return {"accepted": False, "checks": checks}

            self.txs[tx.tx_id] = tx
            self.order.append(tx.tx_id)
            # set(): a transaction that names the same parent twice (possible
            # when only one eligible tip exists) approves it once, not twice.
            for p in set(tx.parents):
                self.txs[p].references += 1
            self._credit_approvals(tx)
            return {"accepted": True, "checks": checks}

    # -- cumulative approvals (Alg. 5, lines 25-29) ------------------------
    APPROVAL_VISIT_CAP = 400

    def _credit_approvals(self, tx: Transaction):
        """Give +1 approval to every ancestor this transaction approves.

        Algorithm 5 line 25 scans *every* transaction in the DAG asking whether
        it references Tx, not only Tx's direct children - so Reference_Count is
        the transitive approval count (cumulative weight), which is also how DAG
        ledgers define confirmation in practice.

        This matters. Every publish creates one transaction and hands out exactly
        two direct references, so the mean direct-reference count is pinned at 2
        no matter how the DAG is shaped: FT=5 would finalise ~5% of traffic and
        FT=10 essentially none. Counting approvals transitively removes that
        ceiling and lets the paper's larger thresholds behave as intended.

        The walk is breadth-first, stops at finalised ancestors (they are closed
        and their own ancestors were credited long ago) and is capped, so append
        stays O(1) in the size of the ledger rather than O(n).
        """
        seen: set[str] = set()
        frontier = list(tx.parents)
        visits = 0
        while frontier and visits < self.APPROVAL_VISIT_CAP:
            nxt: list[str] = []
            for tid in frontier:
                if tid in seen:
                    continue
                seen.add(tid)
                visits += 1
                anc = self.txs.get(tid)
                if anc is None or anc.gateway_id == "GENESIS":
                    continue
                anc.weight += 1
                if not anc.finalized:
                    nxt.extend(anc.parents)
            frontier = nxt

    def next_id(self, gateway_id: str) -> str:
        with self.lock:
            self._counter += 1
            return f"TX-{self._counter:05d}"

    # -- finalisation (Alg. 5, lines 23-34) -------------------------------
    def finalize_ready(self, gateways: list) -> list[Transaction]:
        """Any transaction with references >= FT gets a t-of-n PQ certificate."""
        newly = []
        with self.lock:
            pending = [
                t for t in self.txs.values()
                if not t.finalized and t.gateway_id != "GENESIS" and t.weight >= self.FT
            ]
        for tx in pending:
            signers = gateways[: self.t]
            partials = []
            for g in signers:
                sig = crypto.sign(g.sig_key.secret, bytes.fromhex(tx.tx_hash))
                partials.append(
                    {"gateway_id": g.gid, "sig": sig, "bytes": len(sig)}
                )
            # verify the combined certificate before accepting it
            if all(
                crypto.verify(
                    next(g for g in signers if g.gid == p["gateway_id"]).sig_key.public,
                    bytes.fromhex(tx.tx_hash),
                    p["sig"],
                )
                for p in partials
            ):
                with self.lock:
                    tx.tpq_sig = partials
                    tx.finalized = True
                    tx.finalized_at = time.time()
                newly.append(tx)
        return newly

    # -- stats -------------------------------------------------------------
    def stats(self) -> dict:
        with self.lock:
            real = [t for t in self.txs.values() if t.gateway_id != "GENESIS"]
            fin = [t for t in real if t.finalized]
            lat = [t.finalized_at - t.created_at for t in fin if t.finalized_at]
            return {
                "total": len(real),
                "finalized": len(fin),
                "pending": len(real) - len(fin),
                "rejected": len(self.rejected),
                "publish_retries": self.retry_count,
                "avg_finalization_latency_s": (sum(lat) / len(lat)) if lat else None,
                "avg_direct_references": (sum(t.references for t in real) / len(real))
                if real else None,
                "FT": self.FT,
                "ft_band": self.ft_band["band"],
                "ft_range": self.ft_band["range"],
                "ft_paper_range": self.ft_band["paper_range"],
                "network_nodes": self.network_nodes,
                "difficulty_bits": self.difficulty,
                "threshold_t": self.t,
            }
