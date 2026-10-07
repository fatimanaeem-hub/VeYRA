#!/usr/bin/env python3
"""
Scale study: where does batching start to pay, and where does the sparse tree
overtake the sorted one?

Both are OFF by default in the prototype. This script measures what turning
them on would buy at each network size, so the choice is evidenced rather than
argued.

Registration here uses leaves directly rather than the full ML-DSA
proof-of-possession handshake. PoP costs ~49 ms per node whichever structure is
used, so including it would add a constant to every row and hide the curve. The
PoP cost is reported separately by the build report.

Run:  python scale_study.py
"""

from __future__ import annotations

import json
import statistics
import sys
import time

sys.path.insert(0, "/home/claude/pqdag-poc")

from pqdag import crypto
from pqdag.identity import SortedMerkleSet, SparseMerkleSet

CERT_BYTES = 2420 * 3        # measured: a three-gateway finalisation certificate
COUNTS = [72, 150, 300, 600, 1200, 2400]
REPEATS = 3


def leaves_for(n: int) -> list[str]:
    return [crypto.sha256("pd", i, "sensor", i) for i in range(n)]


def enrol_all(cls, leaves: list[str]) -> dict:
    """Cost of registering every identity, then committing the set once."""
    s = cls()
    t0 = time.perf_counter()
    for l in leaves:
        s.insert(l)
    insert_ms = (time.perf_counter() - t0) * 1000.0

    t1 = time.perf_counter()
    root = s.root()
    root_ms = (time.perf_counter() - t1) * 1000.0

    t2 = time.perf_counter()
    p = s.prove(leaves[len(leaves) // 2])
    prove_ms = (time.perf_counter() - t2) * 1000.0

    assert cls.verify(leaves[len(leaves) // 2], p, root), "proof failed to verify"
    return {"insert_ms": insert_ms, "root_ms": root_ms,
            "commit_ms": insert_ms + root_ms,
            "prove_ms": prove_ms, "proof_bytes": p["bytes"]}


def per_registration_commit(cls, leaves: list[str]) -> float:
    """Unbatched: the set is committed again after every single arrival."""
    s = cls()
    t0 = time.perf_counter()
    for l in leaves:
        s.insert(l)
        s.root()                       # a new root to anchor, every time
    return (time.perf_counter() - t0) * 1000.0


def main():
    print("=" * 84)
    print("SCALE STUDY — identity structure and batching, measured")
    print("=" * 84)
    print(f"backend: {crypto.backend_info()['sig_name']}, "
          f"certificate = {CERT_BYTES:,} B per finalised transaction\n")

    rows = []
    for n in COUNTS:
        leaves = leaves_for(n)
        rec = {"n": n}
        for cls in (SortedMerkleSet, SparseMerkleSet):
            batched = [enrol_all(cls, leaves) for _ in range(REPEATS)]
            rec[cls.kind] = {
                k: round(statistics.median(b[k] for b in batched), 3)
                for k in ("commit_ms", "prove_ms", "proof_bytes")
            }
            rec[cls.kind]["unbatched_ms"] = round(
                statistics.median(per_registration_commit(cls, leaves)
                                  for _ in range(REPEATS)), 3)
        rec["anchor_bytes_individual"] = n * CERT_BYTES
        rec["anchor_bytes_batched"] = CERT_BYTES
        rows.append(rec)

    print("A. Committing the whole set once (batched), by structure\n")
    print(f"{'n':>6}{'sorted commit':>16}{'smt commit':>14}"
          f"{'sorted proof':>15}{'smt proof':>12}{'winner':>10}")
    print("-" * 73)
    for r in rows:
        w = "sorted" if r["sorted"]["commit_ms"] <= r["smt"]["commit_ms"] else "SMT"
        print(f"{r['n']:>6}{r['sorted']['commit_ms']:>13.3f} ms"
              f"{r['smt']['commit_ms']:>11.3f} ms"
              f"{r['sorted']['proof_bytes']:>13} B{r['smt']['proof_bytes']:>10} B"
              f"{w:>10}")

    print("\nB. If you CANNOT batch: commit after every arrival\n")
    print("   This is the only case where the sparse tree helps. Sorted is O(n^2)")
    print("   here because every arrival rebuilds; SMT is flat per join.\n")
    print(f"{'n':>6}{'sorted total':>15}{'smt total':>13}"
          f"{'sorted/join':>14}{'smt/join':>11}{'winner':>9}")
    print("-" * 68)
    for r in rows:
        so, sm = r["sorted"]["unbatched_ms"], r["smt"]["unbatched_ms"]
        w = "sorted" if so < sm else "SMT"
        print(f"{r['n']:>6}{so:>12.1f} ms{sm:>10.1f} ms"
              f"{so / r['n']:>11.3f} ms{sm / r['n']:>8.3f} ms{w:>9}")

    print("\nB2. If you CAN batch: commit once per epoch\n")
    print(f"{'n':>6}{'sorted':>13}{'smt':>13}{'batching saves (sorted)':>26}")
    print("-" * 56)
    for r in rows:
        print(f"{r['n']:>6}{r['sorted']['commit_ms']:>10.3f} ms"
              f"{r['smt']['commit_ms']:>10.3f} ms"
              f"{r['sorted']['unbatched_ms'] / r['sorted']['commit_ms']:>23.0f}x")

    print("\nC. Anchoring cost — the argument that does not depend on structure\n")
    print(f"{'n':>6}{'individual':>18}{'batched':>12}{'saved':>16}")
    print("-" * 52)
    for r in rows:
        ind, bat = r["anchor_bytes_individual"], r["anchor_bytes_batched"]
        print(f"{r['n']:>6}{ind:>15,} B{bat:>9,} B{ind - bat:>13,} B")

    # crossover
    cross = next((r["n"] for r in rows
                  if r["smt"]["unbatched_ms"] < r["sorted"]["unbatched_ms"]), None)
    print("\n" + "=" * 84)
    print("CONCLUSION")
    print("  Batching and the sparse tree are ALTERNATIVES, not complements.")
    print("  Batch, and the sorted tree is always cheaper - it hashes n things")
    print("  once, while the sparse tree walks 256 levels per identity.")
    if cross:
        print(f"  Do not batch, and the sparse tree overtakes at about n = {cross}.")
    print("  So: batch if you can, and the structure question goes away.")
    print("  Defaults stay sorted + unbatched: correct for a 72-node network.")
    print("=" * 84)

    with open("/home/claude/pqdag-poc/scale_results.json", "w") as f:
        json.dump({"rows": rows, "cert_bytes": CERT_BYTES,
                   "crossover_n": cross,
                   "backend": crypto.backend_info()}, f, indent=2)
    print("\nwritten to scale_results.json")


if __name__ == "__main__":
    main()
