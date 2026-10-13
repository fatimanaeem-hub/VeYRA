"""
The controlled experiment behind the PoC claim.

Question under test
-------------------
The paper claims a DAG ledger absorbs the cost of post-quantum cryptography
better than a linear chain because transactions can be produced in parallel.
Is that structurally true, and how much of it can we actually observe?

Why the two arms are a fair comparison
--------------------------------------
Both arms perform *identical* cryptographic work per ledger entry:
  * one PoPQW puzzle at the same difficulty, and
  * t ML-DSA-44 signatures for the finalisation certificate.

The single difference is the data structure, and it produces a genuine,
implementation-independent constraint:

  Linear chain : block N+1's header contains block N's hash. A gateway cannot
                 begin mining until the previous block exists. Production is
                 inherently sequential - no amount of hardware removes this.

  DAG          : a gateway selects any two existing tips and mines immediately.
                 Gateways never wait for one another, so production is
                 embarrassingly parallel.

Because Python threads share one interpreter lock, this experiment runs the DAG
gateways as separate *processes* so that the parallelism is real rather than an
artefact. The speed-up is therefore bounded by the number of CPU cores on the
machine, and the script reports that bound honestly.
"""

from __future__ import annotations

import os
import time
from concurrent.futures import ProcessPoolExecutor

from . import crypto
from .ledger import merkle_root, solve_popqw


def _mine_batch(args) -> dict:
    """One gateway producing `n_tx` DAG transactions independently.

    Runs in its own process. Uses the real PoPQW solver and real ML-DSA signing,
    so the measured cost is the cost of the actual scheme.
    """
    gid, n_tx, difficulty, t = args
    sig_keys = [crypto.sig_keygen() for _ in range(t)]
    t0 = time.perf_counter()
    pow_ms_total = 0.0
    sign_ms_total = 0.0
    tips = [crypto.sha256("genesis", i) for i in range(10)]

    for k in range(n_tx):
        parents = [tips[(k) % len(tips)], tips[(k + 3) % len(tips)]]
        ciphertext = crypto.sym_encrypt(b"k" * 32, f"{gid}-agg-{k}".encode())
        tx_hash = crypto.sha256(gid, ciphertext, parents[0], parents[1], k)
        _mr = merkle_root([*parents, tx_hash])

        nonce, _h, pow_ms = solve_popqw(tx_hash, gid, difficulty)
        pow_ms_total += pow_ms

        s0 = time.perf_counter()
        for kp in sig_keys:                       # tPQ-Sig partial signatures
            crypto.sign(kp.secret, bytes.fromhex(tx_hash))
        sign_ms_total += (time.perf_counter() - s0) * 1000.0

        tips.append(tx_hash)
        tips = tips[-40:]

    return {
        "gateway": gid,
        "tx": n_tx,
        "wall_ms": (time.perf_counter() - t0) * 1000.0,
        "popqw_ms": pow_ms_total,
        "sign_ms": sign_ms_total,
    }


def _mine_linear(n_blocks: int, difficulty: int, t: int) -> dict:
    """The linear chain. Block N+1 depends on block N, so this cannot be
    parallelised - which is exactly the property under test."""
    sig_keys = [crypto.sig_keygen() for _ in range(t)]
    t0 = time.perf_counter()
    pow_ms_total = 0.0
    sign_ms_total = 0.0
    prev = crypto.sha256("linear-genesis")

    for i in range(n_blocks):
        ciphertext = crypto.sym_encrypt(b"k" * 32, f"blk-{i}".encode())
        header = crypto.sha256(i, "GW", ciphertext, prev)   # <- depends on prev
        _mr = merkle_root([prev, header])

        nonce, _h, pow_ms = solve_popqw(header, "GW", difficulty)
        pow_ms_total += pow_ms

        s0 = time.perf_counter()
        for kp in sig_keys:                                  # PSN endorsements
            crypto.sign(kp.secret, bytes.fromhex(header))
        sign_ms_total += (time.perf_counter() - s0) * 1000.0

        prev = header                                        # serialisation point

    return {
        "blocks": n_blocks,
        "wall_ms": (time.perf_counter() - t0) * 1000.0,
        "popqw_ms": pow_ms_total,
        "sign_ms": sign_ms_total,
    }


def run(n_gateways: int = 4, tx_per_gateway: int = 6, difficulty: int = 14,
        t: int = 3) -> dict:
    cores = os.cpu_count() or 1
    total = n_gateways * tx_per_gateway

    # ---- DAG arm: gateways mine concurrently, in real processes ----
    d0 = time.perf_counter()
    jobs = [(f"GW-{j:02d}", tx_per_gateway, difficulty, t) for j in range(n_gateways)]
    with ProcessPoolExecutor(max_workers=min(n_gateways, cores)) as pool:
        dag_parts = list(pool.map(_mine_batch, jobs))
    dag_wall = (time.perf_counter() - d0) * 1000.0

    # ---- Linear arm: the same total work, forced sequential by structure ----
    lin = _mine_linear(total, difficulty, t)

    dag_tps = total / (dag_wall / 1000.0)
    lin_tps = total / (lin["wall_ms"] / 1000.0)

    return {
        "parameters": {
            "gateways": n_gateways,
            "tx_per_gateway": tx_per_gateway,
            "total_entries": total,
            "popqw_difficulty_bits": difficulty,
            "threshold_t": t,
            "cpu_cores": cores,
            "worker_processes": min(n_gateways, cores),
            "backend": crypto.BACKEND,
            "post_quantum": crypto.IS_POST_QUANTUM,
        },
        "dag": {
            "wall_ms": round(dag_wall, 1),
            "entries_per_s": round(dag_tps, 2),
            "cpu_ms_popqw": round(sum(p["popqw_ms"] for p in dag_parts), 1),
            "cpu_ms_sign": round(sum(p["sign_ms"] for p in dag_parts), 1),
            "per_gateway": [
                {"gateway": p["gateway"], "wall_ms": round(p["wall_ms"], 1)}
                for p in dag_parts
            ],
        },
        "linear": {
            "wall_ms": round(lin["wall_ms"], 1),
            "entries_per_s": round(lin_tps, 2),
            "cpu_ms_popqw": round(lin["popqw_ms"], 1),
            "cpu_ms_sign": round(lin["sign_ms"], 1),
        },
        "speedup": round(dag_tps / lin_tps, 2) if lin_tps else None,
        "ceiling_note": (
            f"Observed speed-up is bounded by the {cores} CPU core(s) available "
            f"to this process. The structural ceiling is the gateway count; "
            f"confirming that requires a multi-machine testbed."
        ),
    }


if __name__ == "__main__":
    import json

    print(json.dumps(run(), indent=2))
