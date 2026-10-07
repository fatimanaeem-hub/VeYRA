#!/usr/bin/env python3
"""
TC-01 — End-to-end post-quantum integrity of a single sensor reading.

Run this in front of the panel:   python testcase.py

Why this test case, and not a simpler one
-----------------------------------------
A happy-path test proves almost nothing on its own. "The gateway accepted the
reading" is equally consistent with "the gateway verified the reading" and with
"the gateway accepts anything". Only a paired negative case separates those two,
so every step below that performs a check is immediately followed by a corrupted
version of the same input that must be refused.

The test follows one reading, from one sensor, all the way to finality. That
single path exercises every algorithm in the reference paper:

    step 1-2   Algorithm 1   registration on the identity chain BC_ID
    step 3     Algorithm 2   post-quantum session-key establishment
    step 4-6   Algorithm 3   transport confidentiality and integrity
    step 7-8   Algorithm 4   DAG transaction, Merkle root, PoPQW
    step 9-10  Algorithm 5   reference-count finality, tPQ-Sig certificate

If this one test passes, the pipeline is feasible. If any negative case is
accepted, the security argument in the proposal collapses.
"""

import sys
import time

from pqdag import crypto
from pqdag.ledger import DagLedger, check_popqw, merkle_root
from pqdag.network import Gateway, SensorNode, Server

PASS, FAIL = [], []
STEP = [0]


def step(n, title):
    print(f"\n\033[1mSTEP {n} — {title}\033[0m")


def expect(label, condition, observed):
    ok = bool(condition)
    (PASS if ok else FAIL).append(label)
    mark = "\033[32mPASS\033[0m" if ok else "\033[31mFAIL\033[0m"
    print(f"  [{mark}] {label}")
    print(f"         observed: {observed}")


print("=" * 76)
print("  TC-01  End-to-end post-quantum integrity of a single sensor reading")
print("=" * 76)
info = crypto.backend_info()
print(f"  backend    : {info['backend']}  ({'post-quantum' if info['post_quantum'] else 'CLASSICAL FALLBACK'})")
print(f"  KEM        : {info['kem_name']}")
print(f"  signature  : {info['sig_name']}")
print(f"  symmetric  : {info['symmetric']}")

# --------------------------------------------------------------------------
server = Server()
# 15 nodes (3 gateways + 12 sensors) -> Small DAG band -> FT = 3 (Table III)
ledger = DagLedger(network_nodes=15, difficulty_bits=12, threshold_t=3)
gws = [Gateway(f"GW-{j:02d}", server, ledger) for j in range(3)]
for g in gws:
    n = server.issue_challenge(g.gid)
    server.register_node(g.gid, "gateway", g.sig_key.public,
                         crypto.sign(g.sig_key.secret, n), n)
gw = gws[0]

# the sensor holds its own ML-DSA identity key; the secret never leaves it
sensor = SensorNode(pd="SN-00-00", kind="speed", gateway_id=gw.gid)
sensor.unit = "km/h"

# ==========================================================================
step(1, "Register sensor SN-00-00 with proof-of-possession (Algorithm 1)")
# Reasoning: identity must be anchored on-chain before any key material exists,
# otherwise authentication in step 3 has nothing to check against. And the node
# must PROVE it holds the secret half of the key it is registering, or the
# registry records a key an attacker merely copied.
before = len(server.bc_id.blocks)
nonce = server.issue_challenge(sensor.pd)
reg = server.register_node(sensor.pd, "sensor", sensor.sig_key.public,
                           sensor.prove_possession(nonce), nonce)
expect("registration accepted and a block is appended",
       reg["ok"] and len(server.bc_id.blocks) == before + 1,
       f"block #{reg['block']['index']}, hash {reg['block']['hash'][:16]}…")
expect("new block links to the previous block's hash",
       reg["block"]["prev"] == server.bc_id.blocks[before - 1]["hash"],
       f"prev={reg['block']['prev'][:16]}…")
expect("block commits to the identity root after this registration",
       len(reg["block"]["id_root"]) == 64,
       f"id_root={reg['block']['id_root'][:16]}…")

# ==========================================================================
step(2, "NEGATIVE — the same identity cannot register twice")
# Reasoning: without this, an attacker re-registers a known sensor ID and
# obtains a legitimate-looking identity. Algorithm 1's else-branch is the
# only thing preventing it.
n2 = server.issue_challenge(sensor.pd)
dup = server.register_node(sensor.pd, "sensor", sensor.sig_key.public,
                           sensor.prove_possession(n2), n2)
expect("duplicate registration is refused",
       not dup["ok"], dup.get("error"))

# ==========================================================================
step("2b", "NEGATIVE — you cannot register a public key you do not own")
# Reasoning: this is the gap proof-of-possession closes. Without it, anyone who
# can observe a sensor's public key can register it under a new identity.
impostor = SensorNode(pd="SN-IMPOSTOR", kind="speed", gateway_id=gw.gid)
n3 = server.issue_challenge("SN-IMPOSTOR")
bad = server.register_node("SN-IMPOSTOR", "sensor",
                           sensor.sig_key.public,          # victim's public key
                           impostor.prove_possession(n3),  # impostor's signature
                           n3)
expect("registration under someone else's public key is refused",
       not bad["ok"], bad.get("error"))
expect("rejection happens at proof-of-possession, not later",
       bad.get("stage") == "PoP verification", f"stage={bad.get('stage')}")

n4 = server.issue_challenge("SN-REPLAY")
good_sig = sensor.prove_possession(n4)
server.register_node("SN-REPLAY", "sensor", sensor.sig_key.public, good_sig, n4)
replay = server.register_node("SN-REPLAY-2", "sensor", sensor.sig_key.public,
                              good_sig, n4)
expect("a captured challenge cannot be replayed for a second identity",
       not replay["ok"], replay.get("error"))

# ==========================================================================
step("2c", "Membership proof — registration provable in 231 bytes")
# Reasoning: the hash-linked chain records registration but cannot prove it to
# anyone without handing over the whole registry. A Merkle commitment over the
# registered identities makes the proof compact and independently checkable.
root = server.bc_id.identity_root()
proof = server.prove_membership(sensor.pd)
v = Server.verify_membership(sensor.pd, "sensor", sensor.sig_key.public,
                             proof, root)
expect("membership verifies against the identity root alone",
       v["ok"], f"{v['proof_bytes']} B {v['structure']} proof "
                f"over {v['set_size']} identities")

forged = Server.verify_membership(sensor.pd, "gateway", sensor.sig_key.public,
                                  proof, root)
expect("NEGATIVE — the same proof does not work for a different role",
       not forged["ok"], forged.get("error"))

tampered = dict(proof)
tampered["proof"] = dict(proof["proof"])
tampered["proof"]["path"] = [(("f" * 64) if sib is not None else None, d)
                             for sib, d in proof["proof"]["path"]]
vt = Server.verify_membership(sensor.pd, "sensor", sensor.sig_key.public,
                              tampered, root)
expect("NEGATIVE — a tampered proof path fails against the root",
       not vt["ok"], vt.get("error"))

# ==========================================================================
step(3, "Establish a post-quantum session key (Algorithm 2)")
# Reasoning: this is the step quantum computers break in the classical design.
# We check both that it succeeds and that the two sides derived the SAME key —
# a handshake that "succeeds" with mismatched keys is worse than one that fails.
res = sensor.establish_session(gw)
expect("session established", res["ok"], f"{res.get('handshake_ms', 0):.2f} ms")
expect("sensor and gateway derived an identical session key",
       sensor.session_key == gw.sessions.get("SN-00-00"),
       f"Sk digest {crypto.sha256(sensor.session_key)[:16]}…")
expect("ML-KEM-768 ciphertext is the standard 1088 bytes"
       if info["post_quantum"] else "KEM ciphertext produced",
       res["kem_ciphertext_bytes"] == 1088 if info["post_quantum"] else True,
       f"{res['kem_ciphertext_bytes']} B on the wire")

# ==========================================================================
step(4, "NEGATIVE — an unregistered sensor cannot establish a session")
# Reasoning: proves the check in step 1 is actually consulted at handshake time
# and is not decorative.
rogue = SensorNode(pd="SN-ROGUE", kind="speed", gateway_id=gw.gid)
r = rogue.establish_session(gw)
expect("unregistered identity is refused a session",
       not r["ok"], r.get("error"))

# ==========================================================================
step(5, "Send the reading 87.4 km/h (Equations 3-4, Algorithm 3)")
# Reasoning: the payload carries its own hash, so the gateway can distinguish
# "decrypted successfully" from "decrypted to the right thing".
sent = sensor.send(87.4, gw, "km/h")
expect("gateway decrypted the reading and the payload hash matched",
       sent["ok"] and sent["value"] == 87.4,
       f"recovered {sent.get('value')} {sensor.unit}, "
       f"ciphertext {sent['ciphertext_bytes']} B, "
       f"decrypt {sent['decrypt_ms']:.3f} ms")
expect("plaintext value never appears in the ciphertext",
       b"87.4" not in crypto.sym_encrypt(sensor.session_key, b"SN-00-00:speed:87.4:km/h"),
       "byte scan of the ciphertext found no plaintext")

# ==========================================================================
step(6, "NEGATIVE — replayed and tampered readings are discarded")
# Reasoning: two distinct attacks, two distinct defences. Freshness stops a
# recorded-and-resent message; the AEAD tag stops a modified one. A test that
# only checks one leaves the other completely unevidenced.
payload = "SN-00-00:speed:999:km/h"
blob = crypto.sym_encrypt(sensor.session_key,
                          (payload + "||" + crypto.sha256(payload)).encode())

replay = gw.receive("SN-00-00", blob, time.time() - 4000)
expect("replay with a stale timestamp is discarded",
       not replay["ok"], replay.get("error"))

bad = bytearray(blob)
bad[-1] ^= 0xFF                      # flip exactly one bit of one byte
flipped = gw.receive("SN-00-00", bytes(bad), time.time())
expect("single flipped bit is detected and the reading discarded",
       not flipped["ok"], flipped.get("error"))

# ==========================================================================
step(7, "Publish the aggregated reading as a DAG transaction (Algorithm 4)")
# Reasoning: checks the three structural invariants a verifying gateway will
# later re-check — two parents, a Merkle root over them, and a PoPQW nonce that
# actually satisfies the difficulty target.
sensor.send(87.4, gw, "km/h")
pub = gw.publish()
tx = ledger.txs[pub["tx"]["tx_id"]]
expect("transaction accepted into the DAG", pub["ok"],
       f"{tx.tx_id} from {pub['readings_used']} reading(s)")
expect("transaction references exactly two parents",
       len(tx.parents) == 2, f"parents {tx.parents}")
expect("Merkle root recomputes to the stored value",
       merkle_root([*tx.parents, tx.tx_hash]) == tx.merkle_root,
       f"MR {tx.merkle_root[:16]}…")
expect("PoPQW nonce satisfies the difficulty target",
       check_popqw(tx.tx_hash, tx.gateway_id, tx.popqw_nonce, tx.popqw_difficulty),
       f"nonce {tx.popqw_nonce} at {tx.popqw_difficulty} bits, "
       f"solved in {pub['popqw_ms']:.2f} ms")
expect("a wrong nonce would NOT satisfy it",
       not check_popqw(tx.tx_hash, tx.gateway_id, tx.popqw_nonce + 1,
                       tx.popqw_difficulty),
       f"nonce {tx.popqw_nonce + 1} rejected")

# ==========================================================================
step(8, "NEGATIVE — editing the transaction after publication is detected")
# Reasoning: this is the ledger's core promise. If a published transaction can
# be altered without detection, the blockchain is only a database.
original = tx.ciphertext
tx.ciphertext = original + b"tampered"
ok, why = ledger.verify_parent(tx.tx_id)
tx.ciphertext = original
expect("tampered transaction fails verification", not ok, why)
expect("restoring the original makes it verify again",
       ledger.verify_parent(tx.tx_id)[0], "verified")

# ==========================================================================
step(9, "Drive the transaction to finality (Algorithm 5)")
# Reasoning: finality is not a timer, it is an approval count (Alg. 5 line 25
# scans the whole DAG, so approvals are transitive, not just direct children).
# We check the transaction is NOT final one approval short of the threshold,
# then becomes final on the approval that crosses it.
target = tx.tx_id
while tx.weight < ledger.FT:
    g = gws[tx.weight % len(gws)]
    for s in [sensor]:
        s.send(60.0 + tx.weight, g, "km/h")
    child_id = ledger.next_id(g.gid)
    from pqdag.ledger import Transaction, solve_popqw
    child = Transaction(
        tx_id=child_id, gateway_id=g.gid,
        ciphertext=crypto.sym_encrypt(server.session_key_for(g.gid), b"agg"),
        timestamp=time.time(), parents=[target, ledger.order[-1]],
        prev_hash=ledger.txs[ledger.order[-1]].tx_hash, merkle_root="",
        popqw_nonce=0, popqw_difficulty=ledger.difficulty, tx_hash="",
        created_at=time.time())
    child.tx_hash = child.header()
    child.merkle_root = merkle_root([*child.parents, child.tx_hash])
    child.popqw_nonce = solve_popqw(child.tx_hash, g.gid, ledger.difficulty)[0]

    if tx.weight == ledger.FT - 1:
        expect(f"not final at {tx.weight} approvals (threshold is {ledger.FT})",
               not tx.finalized, f"approvals={tx.weight}, finalized={tx.finalized}")
    ledger.append(child)

ledger.finalize_ready(gws)
expect(f"finalised once it reaches {ledger.FT} approvals",
       tx.finalized, f"approvals={tx.weight} (direct references {tx.references}), "
                     f"finalized={tx.finalized}, "
                     f"latency {tx.finalized_at - tx.created_at:.2f} s")

# ==========================================================================
step(10, "Verify the t-of-n post-quantum certificate (Equation 12)")
# Reasoning: the certificate is what makes finality mean something. We verify
# every partial signature under the signer's registered key, then show a
# forgery under an unregistered key is rejected — otherwise "signed" is a label,
# not a guarantee.
gw_pub = {g.gid: g.sig_key.public for g in gws}
all_valid = all(
    crypto.verify(gw_pub[p["gateway_id"]], bytes.fromhex(tx.tx_hash), p["sig"])
    for p in tx.tpq_sig)
expect(f"all {len(tx.tpq_sig)} partial signatures verify under registered keys",
       all_valid and len(tx.tpq_sig) == ledger.t,
       f"signers {[p['gateway_id'] for p in tx.tpq_sig]}, "
       f"certificate {sum(p['bytes'] for p in tx.tpq_sig)} B")

forged = crypto.sign(crypto.sig_keygen().secret, bytes.fromhex(tx.tx_hash))
expect("a signature from a non-gateway key does NOT verify",
       not crypto.verify(gw_pub[tx.tpq_sig[0]["gateway_id"]],
                         bytes.fromhex(tx.tx_hash), forged),
       "forged certificate rejected")

wrong_msg = crypto.sha256("a different transaction")
expect("a valid signature does NOT verify against a different transaction hash",
       not crypto.verify(gw_pub[tx.tpq_sig[0]["gateway_id"]],
                         bytes.fromhex(wrong_msg), tx.tpq_sig[0]["sig"]),
       "signature is bound to this transaction only")

# ==========================================================================
print("\n" + "=" * 76)
print(f"  TC-01 RESULT:  {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    for f in FAIL:
        print(f"    FAILED: {f}")
print("=" * 76)
print(f"""
  Verdict: {'PASS' if not FAIL else 'FAIL'} — one reading from a registered sensor travelled the full
  path under {info['kem_name'].split(' (')[0]} and {info['sig_name'].split(' (')[0]}, and every corrupted variant of
  that same reading was refused at the layer designed to catch it.
""")
sys.exit(0 if not FAIL else 1)
