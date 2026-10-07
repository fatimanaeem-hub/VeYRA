#!/usr/bin/env python3
"""
Feasibility experiment: batch registration for PQ-VehicleGuard.

Answers three questions with measurements rather than argument:

  1. Which commitment structure should back a registration batch, given that
     this project is post-quantum and our own PoC already showed that BYTES,
     not CPU, are the binding cost?
  2. Does batching actually pay at OUR network size (2-72 nodes), or only at
     scales we will never reach?
  3. Do the security properties from the IIoT assignment survive the switch
     from ECC to ML-DSA?

Run:  python batch_experiment.py
"""

from __future__ import annotations

import json
import statistics
import sys
import time

sys.path.insert(0, "/home/claude/pqdag-poc")

from pqdag import crypto
from pqdag.batchreg import (
    BatchRegistrar, make_device, STRUCTURES,
    MerkleBatch, SortedBitmapBatch, SkipListBatch,
    SignedCredentialBatch, XorDigestBatch,
)
from pqdag.network import RegistrationChain


COUNTS = [5, 10, 25, 50, 72, 100, 250]
REPEATS = 3
OUR_CAP = 72          # 8 gateways x (1 + 8 sensors) is the UI maximum


def enrol(reg: BatchRegistrar, devices):
    """Full assignment Phase-1 handshake for each device."""
    for d in devices:
        nonce = reg.challenge()
        sig = d.answer_challenge(nonce)
        r = reg.register(d.did, d.role, d.sig_key.public, sig, nonce)
        if not r["ok"]:
            raise RuntimeError(f"enrolment failed: {r}")


def bench_structure(struct, n: int, leaves, server_key) -> dict:
    """One structure, one device count. Measures the STRUCTURE only: the
    post-quantum handshake cost is identical across structures and is measured
    separately in Experiment 3, so including it here would hide the difference."""
    build, gen, ver, pbytes = [], [], [], []
    sub = leaves[:n]
    target = sub[0]

    for _ in range(REPEATS):
        t0 = time.perf_counter()
        if struct is SignedCredentialBatch:
            commitment, aux = struct.close(sub, server_key, 0)
        else:
            commitment, aux = struct.close(sub)
        build.append((time.perf_counter() - t0) * 1000.0)

        t1 = time.perf_counter()
        proofs = {l: struct.prove(l, sub, aux) for l in sub}
        gen.append((time.perf_counter() - t1) * 1000.0)

        proof = proofs[target]
        t2 = time.perf_counter()
        if struct in (SortedBitmapBatch, SignedCredentialBatch):
            ok = struct.verify(target, proof, commitment, aux)
        else:
            ok = struct.verify(target, proof, commitment)
        ver.append((time.perf_counter() - t2) * 1000.0)
        if not ok:
            raise RuntimeError(f"{struct.name}: verification failed at n={n}")
        pbytes.append(struct.proof_bytes(proof))

    return {
        "structure": struct.name,
        "is_tree": struct.is_tree,
        "n": n,
        "build_ms": round(statistics.mean(build), 3),
        "proof_gen_ms": round(statistics.mean(gen), 3),
        "verify_ms": round(statistics.mean(ver), 4),
        "proof_bytes": int(statistics.mean(pbytes)),
    }


def run_structure_comparison():
    print("=" * 78)
    print("EXPERIMENT 1 — five commitment structures, same batch")
    print("=" * 78)
    print(f"backend: {crypto.backend_info()}\n")

    rows = []
    server_key = crypto.sig_keygen()
    # leaves are just hashes of (DID || PK); generate the key material once
    biggest = max(COUNTS)
    all_leaves = [crypto.sha256(f"did:pqvg:SN-{i:04d}", crypto.sha256("pk", i))
                  for i in range(biggest)]
    for n in COUNTS:
        for struct in STRUCTURES:
            if struct is XorDigestBatch and n > 100:
                continue
            if struct is SkipListBatch and n > 100:
                continue        # O(n^2) proof construction in this reference impl
            rows.append(bench_structure(struct, n, all_leaves, server_key))

    hdr = f"{'structure':<30}{'tree':<7}{'n':>5}{'close ms':>11}{'proofs ms':>11}{'verify ms':>11}{'proof B':>10}"
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        print(f"{r['structure']:<30}{'yes' if r['is_tree'] else 'no':<7}{r['n']:>5}"
              f"{r['build_ms']:>11.3f}{r['proof_gen_ms']:>11.3f}"
              f"{r['verify_ms']:>11.4f}{r['proof_bytes']:>10}")
    return rows


def run_batch_vs_individual():
    """The assignment's required comparison, at our scale and beyond."""
    print("\n" + "=" * 78)
    print("EXPERIMENT 2 — batch vs per-device root rebuild")
    print("=" * 78)

    rows = []
    biggest = max(COUNTS)
    all_leaves = [crypto.sha256(f"did:pqvg:SN-{i:04d}", crypto.sha256("pk", i))
                  for i in range(biggest)]
    for n in COUNTS:
        leaves = all_leaves[:n]

        # batch: build the tree once
        t0 = time.perf_counter()
        for _ in range(REPEATS):
            MerkleBatch.close(leaves)
        batch_ms = (time.perf_counter() - t0) * 1000.0 / REPEATS

        # individual: rebuild after every arrival (root changes each time)
        t0 = time.perf_counter()
        for _ in range(REPEATS):
            for k in range(1, n + 1):
                MerkleBatch.close(leaves[:k])
        indiv_ms = (time.perf_counter() - t0) * 1000.0 / REPEATS

        rows.append({"n": n, "batch_ms": round(batch_ms, 3),
                     "individual_ms": round(indiv_ms, 3),
                     "speedup": round(indiv_ms / batch_ms, 1) if batch_ms else 0,
                     "root_updates_batch": 1, "root_updates_individual": n})

    hdr = f"{'n':>5}{'batch ms':>12}{'per-device ms':>16}{'speed-up':>11}{'root anchors':>15}"
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        print(f"{r['n']:>5}{r['batch_ms']:>12.3f}{r['individual_ms']:>16.3f}"
              f"{r['speedup']:>10.1f}x{'1 vs ' + str(r['n']):>15}")
    return rows


def run_current_baseline():
    """What the existing hash-linked BC_ID costs, for honesty."""
    print("\n" + "=" * 78)
    print("EXPERIMENT 3 — today's BC_ID (hash-linked, one block per node)")
    print("=" * 78)

    rows = []
    for n in COUNTS:
        dids = [f"did:pqvg:SN-{i:04d}" for i in range(n)]
        samples = []
        for _ in range(REPEATS):
            chain = RegistrationChain()
            t0 = time.perf_counter()
            for i, did in enumerate(dids):
                chain.register(did, "sensor", crypto.sha256("pk", i)[:16])
            samples.append((time.perf_counter() - t0) * 1000.0)
        rows.append({"n": n, "register_all_ms": round(statistics.mean(samples), 3),
                     "per_device_us": round(statistics.mean(samples) * 1000 / n, 1)})

    print(f"{'n':>5}{'register all ms':>18}{'per device us':>16}   membership proof")
    print("-" * 70)
    for r in rows:
        print(f"{r['n']:>5}{r['register_all_ms']:>18.3f}{r['per_device_us']:>16.1f}"
              f"   none — needs whole chain")
    return rows


def run_attacks():
    """The assignment requires at least three. We run six."""
    print("\n" + "=" * 78)
    print("EXPERIMENT 4 — attacks against batch registration")
    print("=" * 78)

    results = []
    devices = [make_device(f"did:pqvg:SN-{i:04d}") for i in range(8)]

    # --- 1. proof-of-possession forgery: claim someone else's public key ----
    reg = BatchRegistrar(window_seconds=999)
    reg.open_window()
    victim, attacker = devices[0], devices[1]
    nonce = reg.challenge()
    forged = attacker.answer_challenge(nonce)          # signed with WRONG key
    r = reg.register("did:pqvg:IMPOSTOR", "sensor", victim.sig_key.public, forged, nonce)
    results.append(("Register under a public key you do not own",
                    "PoP verification", not r["ok"], r.get("error", "")))

    # --- 2. nonce replay during registration --------------------------------
    reg2 = BatchRegistrar(window_seconds=999)
    reg2.open_window()
    d = devices[2]
    n1 = reg2.challenge()
    s1 = d.answer_challenge(n1)
    reg2.register(d.did, "sensor", d.sig_key.public, s1, n1)
    r = reg2.register("did:pqvg:CLONE", "sensor", d.sig_key.public, s1, n1)
    results.append(("Replay a captured registration challenge",
                    "nonce validator", not r["ok"], r.get("error", "")))

    # --- 3. tampered inclusion proof ---------------------------------------
    reg3 = BatchRegistrar(window_seconds=999)
    reg3.open_window()
    enrol(reg3, devices[:6])
    reg3.close_window()
    target = devices[0]
    epoch_no, proof = reg3.membership[target.did]
    bad = [(("f" * 64), d) for (_h, d) in proof]       # corrupt every sibling
    reg3.membership[target.did] = (epoch_no, bad)
    v = reg3.verify_membership(target.did, target.sig_key.public)
    results.append(("Tamper with a sibling hash in the inclusion proof",
                    "Merkle proof verification", not v["ok"], "root mismatch"))

    # --- 4. unregistered device forges membership ---------------------------
    reg4 = BatchRegistrar(window_seconds=999)
    reg4.open_window()
    enrol(reg4, devices[:6])
    reg4.close_window()
    outsider = make_device("did:pqvg:OUTSIDER")
    member = devices[0]
    stolen_epoch, stolen_proof = reg4.membership[member.did]
    reg4.membership[outsider.did] = (stolen_epoch, stolen_proof)   # steal a proof
    v = reg4.verify_membership(outsider.did, outsider.sig_key.public)
    results.append(("Use a stolen inclusion proof with your own identity",
                    "leaf recomputation", not v["ok"], "leaf does not match proof"))

    # --- 5. stolen temporary token used by another device -------------------
    reg5 = BatchRegistrar(window_seconds=999)
    reg5.open_window()
    enrol(reg5, devices[:3])
    holder, thief = devices[0], devices[1]
    reg5.issue_token(holder.did, "sensor")
    nonce = reg5.challenge()
    # thief presents holder's token but can only sign with its own key
    r = reg5.check_token(holder.did, nonce,
                         thief.answer_challenge(nonce), holder.sig_key.public)
    results.append(("Use a stolen temporary token from another device",
                    "session binding / PoP", not r["ok"], r.get("error", "")))

    # --- 6. revoked device attempts access ----------------------------------
    reg6 = BatchRegistrar(window_seconds=999)
    reg6.open_window()
    enrol(reg6, devices[:4])
    reg6.close_window()
    gone = devices[1]
    reg6.revoke(gone.did)
    v = reg6.verify_membership(gone.did, gone.sig_key.public)
    results.append(("Present a valid historical proof after revocation",
                    "revocation check", not v["ok"], v.get("error", "")))

    print(f"{'attack':<52}{'detected by':<28}{'result'}")
    print("-" * 95)
    passed = 0
    for name, where, ok, detail in results:
        passed += ok
        print(f"{name:<52}{where:<28}{'REJECTED' if ok else '*** ACCEPTED ***'}")
        if detail:
            print(f"{'':<52}{'':<28}  {detail}")
    print(f"\n{passed} of {len(results)} attacks refused")
    return results, passed, len(results)


if __name__ == "__main__":
    s = run_structure_comparison()
    b = run_batch_vs_individual()
    c = run_current_baseline()
    a, passed, total = run_attacks()

    with open("/home/claude/pqdag-poc/batch_results.json", "w") as f:
        json.dump({"structures": s, "batch_vs_individual": b,
                   "current_baseline": c,
                   "attacks": {"passed": passed, "total": total},
                   "backend": crypto.backend_info(),
                   "our_node_cap": OUR_CAP}, f, indent=2)
    print("\nresults written to batch_results.json")
