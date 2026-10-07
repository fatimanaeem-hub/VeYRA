# Registration hardening — what changed and why

Two gaps in the inherited BC_ID registration are now closed. Nothing else in the
pipeline was touched.

## Gap 1 — no proof-of-possession

**Before.** `register_node(pd, role, pubkey)` stored `sha256(pubkey)[:16]` and
returned success. Nothing proved the caller held the matching secret key, so any
party able to reach the server could register any public key under any identity —
including a key copied from a legitimate sensor.

**Now.** Registration is a challenge–response:

1. `server.issue_challenge(pd)` returns a fresh 32-byte nonce.
2. The node signs it with its own ML-DSA-44 secret key.
3. `server.register_node(pd, role, pubkey, signature, nonce)` verifies the
   signature under the public key being claimed, and refuses otherwise.

Nonces are single-use and expire after 30 seconds. Rejections carry a `stage`
field naming the check that fired, so the evidence tab can show *where* an
attack was caught.

Gateways now register under `sig_key.public` rather than `kem_key.public` —
identity should bind to the key that can make assertions, not the one that can
only receive secrets.

## Gap 2 — no membership proof

**Before.** Registration status lived in a Python dict plus a hash-linked chain.
Answering "is PD-0042 registered?" required holding the entire registry; a
gateway could not prove a node's registration to any third party.

**Now.** `RegistrationChain` keeps the hash-linked chain — that is the audit
trail — and adds a Merkle commitment over the registered identity set:

- leaf `L = H(PD || role || PK)`; the role is included so a sensor cannot later
  present itself as a gateway using the same key
- every block records `id_root`, the identity root as it stood after that
  registration, so the chain commits to the *set*, not only the sequence
- `server.prove_membership(pd)` returns a **231-byte proof** at 72 identities
- `Server.verify_membership(pd, role, pubkey, proof, root)` checks it against a
  32-byte root with no access to the registry

Proofs are generated **on demand rather than issued once**, so re-registration
churn never leaves a device holding a stale proof. That is what makes epoch
batching unnecessary for this fix.

## Files changed

| File | Change |
|---|---|
| `pqdag/ledger.py` | added `merkle_path()` and `merkle_verify()`, matching `merkle_root`'s carry-up rule |
| `pqdag/network.py` | `RegistrationChain` gains leaves, `identity_root()`, `prove()`; `Server` gains challenges, PoP enforcement, `prove_membership()`, `verify_membership()`; `SensorNode` gains an ML-DSA identity key and `prove_possession()` |
| `pqdag/simulation.py` | build loop enrols every node through the challenge–response; two new adversarial checks; setup report carries the identity root |
| `testcase.py` | steps 1 and 2 use the new flow; new steps 2b and 2c cover PoP forgery, challenge replay, and membership proof with negative cases |

## Cost

Measured on the pure-Python ML-DSA-44 backend:

| Operation | Cost |
|---|---|
| identity keygen (device) | 4.2 ms |
| sign challenge (device) | 39.9 ms |
| verify (server) | 5.0 ms |
| **per node** | **~49 ms** |
| full build at the 72-node ceiling | 3.0 s wall clock |

A compiled backend would cut this by one to two orders of magnitude. Quote the
3.0 s figure rather than letting a panellist discover it by clicking Build at
maximum size.

## Test status

| Suite | Before | After |
|---|---|---|
| `testcase.py` | 23 passed | **30 passed, 0 failed** |
| `verify.py` | 9/9 | **9/9** |
| adversarial checks | 5/5 | **7/7** (after traffic) |

The evidence tab now runs seven attacks. The two new ones are constructed
against the running system like the others, and both can fail.

## Deviation notice

The base paper's Algorithm 1 has no proof-of-possession step. This is a third
deviation from the baseline, alongside Equation 11 and transitive approval
counting. It is defensible — an authentication gap is being fixed, not the
contribution changed — but the panel should hear it from you, and the
proposal's deviation list needs a fourth entry.

## Not wired in

`pqdag/batchreg.py`, `batch_experiment.py` and `batch_results.json` are the
batch-registration feasibility experiment. They are standalone: nothing in the
running system imports them, and adopting any of it remains a decision.
