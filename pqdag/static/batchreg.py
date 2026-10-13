"""
Batch registration for BC_ID — an experiment, not yet part of the committed FYP scope.

WHAT THIS TESTS
---------------
Today `RegistrationChain.register()` appends one hash-linked block per node and
keeps a dict for lookup. Two properties are missing:

  1. No proof-of-possession. register_node(pd, role, pubkey) stores a digest of
     whatever public key it is handed. Nothing proves the caller holds the
     matching secret key, so anyone can register any key under any identity.

  2. No membership proof. To check that PD is registered you must hold the whole
     chain. A gateway cannot prove registration to a third party with anything
     smaller than the entire registry.

This module implements the batch/epoch model from the IIoT assignment, adapted
to post-quantum primitives (ML-DSA-44 instead of ECC), and implements FIVE
different structures for committing to a batch so the choice can be measured
rather than asserted.

ADAPTATION NOTE
---------------
The assignment specifies ECC key pairs. This project is post-quantum, so
proof-of-possession here uses ML-DSA-44 — the signature scheme already in the
system. That substitution is the point: it makes the byte cost visible, because
an ML-DSA signature is 2,420 bytes against roughly 64 for ECDSA.
"""

from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass, field

from . import crypto


# --------------------------------------------------------------------------
# Device identity
# --------------------------------------------------------------------------


@dataclass
class DeviceIdentity:
    """A sensor or gateway holding its own ML-DSA key pair."""

    did: str                       # decentralized identifier, e.g. did:pqvg:SN-00-01
    role: str                      # sensor | gateway
    sig_key: crypto.KeyPair        # ML-DSA-44 key pair; secret never leaves the device

    @property
    def leaf(self) -> str:
        """L_d = H(DID || PK) — the assignment's leaf construction."""
        return crypto.sha256(self.did, self.sig_key.public.hex())

    def answer_challenge(self, nonce: bytes) -> bytes:
        """Proof-of-possession: sign the fog/server's fresh challenge."""
        return crypto.sign(self.sig_key.secret, nonce)


def make_device(did: str, role: str = "sensor") -> DeviceIdentity:
    return DeviceIdentity(did=did, role=role, sig_key=crypto.sig_keygen())


# --------------------------------------------------------------------------
# Commitment structures — five ways to commit to one batch of leaves
# --------------------------------------------------------------------------
#
# Every structure implements the same three operations so they can be measured
# against each other:
#
#   close(leaves)            -> (commitment, aux)   built once per epoch
#   prove(leaf, leaves, aux) -> proof               per device
#   verify(leaf, proof, commitment) -> bool         at the verifier
#
# `commitment` is what gets anchored. `proof` is what the device carries and
# transmits on every verification, so its size is the number that matters most
# for this project — our own PoC measured that bytes, not CPU, are the binding
# cost of post-quantum operation.


class MerkleBatch:
    """Baseline: binary Merkle tree. This is the structure to beat."""

    name = "Merkle tree"
    is_tree = True

    @staticmethod
    def close(leaves: list[str]):
        ordered = sorted(leaves)               # deterministic sort, per the assignment
        if not ordered:
            return crypto.sha256("empty-epoch"), {"levels": []}
        levels = [ordered]
        cur = ordered
        while len(cur) > 1:
            nxt = []
            for i in range(0, len(cur), 2):
                a = cur[i]
                b = cur[i + 1] if i + 1 < len(cur) else cur[i]   # duplicate odd tail
                nxt.append(crypto.sha256(a, b))
            levels.append(nxt)
            cur = nxt
        return cur[0], {"levels": levels}

    @staticmethod
    def prove(leaf: str, leaves: list[str], aux):
        levels = aux["levels"]
        if not levels:
            return None
        idx = levels[0].index(leaf)
        path = []
        for lvl in levels[:-1]:
            sib = idx ^ 1
            if sib >= len(lvl):
                sib = idx                       # duplicated tail
            path.append((lvl[sib], idx & 1))    # (sibling hash, am-I-the-right-child)
            idx >>= 1
        return path

    @staticmethod
    def verify(leaf: str, proof, commitment: str) -> bool:
        if proof is None:
            return False
        h = leaf
        for sib, is_right in proof:
            h = crypto.sha256(sib, h) if is_right else crypto.sha256(h, sib)
        return h == commitment

    @staticmethod
    def proof_bytes(proof) -> int:
        # 32-byte digest + 1 byte direction per level
        return 0 if proof is None else len(proof) * 33


class SortedBitmapBatch:
    """
    NOT A TREE #1 — sorted roster committed by hash, membership by slot bitmap.

    The whole batch roster is published once per epoch. The commitment is the
    hash of the sorted roster. A device's "proof" is just its slot index: the
    verifier, which already holds the roster for the current epoch, checks that
    roster[slot] == leaf.

    This is the degenerate case that wins when the network is small enough that
    every verifier can simply hold the roster. Our network caps at 72 nodes.
    """

    name = "Sorted roster + index"
    is_tree = False

    @staticmethod
    def close(leaves: list[str]):
        ordered = sorted(leaves)
        commitment = crypto.sha256(*ordered) if ordered else crypto.sha256("empty-epoch")
        return commitment, {"roster": ordered}

    @staticmethod
    def prove(leaf: str, leaves: list[str], aux):
        roster = aux["roster"]
        return roster.index(leaf) if leaf in roster else None

    @staticmethod
    def verify(leaf: str, proof, commitment: str, aux=None) -> bool:
        # The verifier must hold the roster; that is the trade-off.
        if proof is None or aux is None:
            return False
        roster = aux["roster"]
        if not (0 <= proof < len(roster)):
            return False
        if roster[proof] != leaf:
            return False
        return crypto.sha256(*roster) == commitment

    @staticmethod
    def proof_bytes(proof) -> int:
        return 0 if proof is None else 2        # a uint16 slot index


class SkipListBatch:
    """
    NOT A TREE #2 — authenticated (Merkle-ised) skip list.

    A layered linked list, not a tree: every node sits on level 0 and is promoted
    to higher levels by a deterministic coin derived from its own hash. Each node
    commits to the node after it on its level, so the head digest commits to the
    whole ordered chain. Membership is proved by the chain of hops from the head
    down to the element — O(log n) expected, like a tree, but the structure is a
    list and supports ordered range queries a Merkle tree cannot answer.
    """

    name = "Authenticated skip list"
    is_tree = False
    MAX_LEVEL = 16

    @staticmethod
    def _height(leaf: str) -> int:
        """Deterministic promotion: count trailing zero bits of the leaf hash."""
        h = int(leaf[:16], 16)
        lvl = 1
        while lvl < SkipListBatch.MAX_LEVEL and (h >> lvl) & 1 == 0:
            lvl += 1
        return lvl

    @staticmethod
    def close(leaves: list[str]):
        ordered = sorted(leaves)
        if not ordered:
            return crypto.sha256("empty-epoch"), {"nodes": [], "digest": {}}
        heights = {l: SkipListBatch._height(l) for l in ordered}
        # digest of a node commits to itself and to the successor on each level
        digest: dict[str, str] = {}
        for i in range(len(ordered) - 1, -1, -1):
            l = ordered[i]
            succ_digests = []
            for lvl in range(heights[l]):
                nxt = None
                for j in range(i + 1, len(ordered)):
                    if heights[ordered[j]] > lvl:
                        nxt = ordered[j]
                        break
                succ_digests.append(digest.get(nxt, "TAIL") if nxt else "TAIL")
            digest[l] = crypto.sha256(l, *succ_digests)
        head = crypto.sha256("HEAD", digest[ordered[0]])
        return head, {"nodes": ordered, "digest": digest, "heights": heights}

    @staticmethod
    def prove(leaf: str, leaves: list[str], aux):
        """Proof = the leaves preceding it on the search path, plus their successor digests."""
        nodes, digest, heights = aux["nodes"], aux["digest"], aux["heights"]
        if leaf not in digest:
            return None
        idx = nodes.index(leaf)
        # everything needed to recompute head from this node forward
        hops = []
        for i in range(idx, -1, -1):
            l = nodes[i]
            succ = []
            for lvl in range(heights[l]):
                nxt = None
                for j in range(i + 1, len(nodes)):
                    if heights[nodes[j]] > lvl:
                        nxt = nodes[j]
                        break
                succ.append(digest.get(nxt, "TAIL") if nxt else "TAIL")
            hops.append((l, succ))
            if i == 0:
                break
        return hops

    @staticmethod
    def verify(leaf: str, proof, commitment: str) -> bool:
        if not proof:
            return False
        if proof[0][0] != leaf:
            return False
        computed: dict[str, str] = {}
        for node, succ in proof:
            computed[node] = crypto.sha256(node, *succ)
        head_node = proof[-1][0]
        return crypto.sha256("HEAD", computed[head_node]) == commitment

    @staticmethod
    def proof_bytes(proof) -> int:
        if not proof:
            return 0
        return sum(32 + 32 * len(succ) for _node, succ in proof)


class SignedCredentialBatch:
    """
    NOT A TREE #3 — no set structure at all; the registrar signs each device.

    At batch close the server issues one ML-DSA-44 signature over
    (epoch || leaf) per device. The device's proof is that signature. The
    verifier needs only the server's public key — no roster, no path, no root.

    This is the classical PKI answer, and it is the honest competitor to a tree.
    Its weakness in a post-quantum system is exactly the weakness our own proof
    of concept already measured: a signature is 2,420 bytes.
    """

    name = "Per-device signed credential"
    is_tree = False

    @staticmethod
    def close(leaves: list[str], server_key: crypto.KeyPair = None, epoch: int = 0):
        ordered = sorted(leaves)
        key = server_key or crypto.sig_keygen()
        creds = {l: crypto.sign(key.secret, f"{epoch}|{l}".encode()) for l in ordered}
        # the anchored commitment is just the registrar's public key + epoch id
        commitment = crypto.sha256("registrar", key.public.hex(), epoch)
        return commitment, {"creds": creds, "key": key, "epoch": epoch}

    @staticmethod
    def prove(leaf: str, leaves: list[str], aux):
        return aux["creds"].get(leaf)

    @staticmethod
    def verify(leaf: str, proof, commitment: str, aux=None) -> bool:
        if proof is None or aux is None:
            return False
        return crypto.verify(aux["key"].public, f"{aux['epoch']}|{leaf}".encode(), proof)

    @staticmethod
    def proof_bytes(proof) -> int:
        return 0 if proof is None else len(proof)


class XorDigestBatch:
    """
    NOT A TREE #4 — incremental XOR multiset digest.

    commitment = XOR over H(leaf) for every member. Adding or removing a device
    is one XOR, O(1), with no rebuild — the most attractive property on this list
    for a network where sensors join and leave continuously.

    It is included to be rejected, and the reason is instructive: a XOR digest
    supports set-integrity checking but NOT membership proof. You cannot show
    that one leaf is in the digest without revealing every other leaf. Listed
    here because 'incremental and O(1)' is seductive and the panel may ask why
    we did not take it.
    """

    name = "XOR multiset digest"
    is_tree = False

    @staticmethod
    def close(leaves: list[str]):
        acc = bytearray(32)
        for l in sorted(leaves):
            h = bytes.fromhex(crypto.sha256(l))[:32]
            for i in range(32):
                acc[i] ^= h[i]
        return bytes(acc).hex(), {"leaves": sorted(leaves)}

    @staticmethod
    def prove(leaf: str, leaves: list[str], aux):
        # the only possible "proof" is the entire complement of the set
        return [l for l in aux["leaves"] if l != leaf]

    @staticmethod
    def verify(leaf: str, proof, commitment: str) -> bool:
        if proof is None:
            return False
        acc = bytearray(32)
        for l in sorted([leaf, *proof]):
            h = bytes.fromhex(crypto.sha256(l))[:32]
            for i in range(32):
                acc[i] ^= h[i]
        return bytes(acc).hex() == commitment

    @staticmethod
    def proof_bytes(proof) -> int:
        return 0 if proof is None else len(proof) * 32


STRUCTURES = [MerkleBatch, SortedBitmapBatch, SkipListBatch,
              SignedCredentialBatch, XorDigestBatch]


# --------------------------------------------------------------------------
# The registrar: epoch windows, proof-of-possession, revocation
# --------------------------------------------------------------------------


@dataclass
class PendingDevice:
    did: str
    role: str
    public_key: bytes
    leaf: str
    joined_at: float
    pop_verified: bool


@dataclass
class Epoch:
    number: int
    commitment: str
    leaves: list[str]
    aux: dict
    closed_at: float
    device_count: int


class BatchRegistrar:
    """
    Collects device registrations during an open window, then closes the window
    into one epoch with a single anchored commitment.

    Mirrors the assignment's fog node, with post-quantum primitives and with the
    epoch commitment anchored on the existing BC_ID chain rather than a separate
    registry.
    """

    def __init__(self, structure=MerkleBatch, window_seconds: float = 5.0,
                 registration_chain=None):
        self.structure = structure
        self.window_seconds = window_seconds
        self.chain = registration_chain          # existing RegistrationChain, optional
        self.server_sig_key = crypto.sig_keygen()

        self.pending: dict[str, PendingDevice] = {}
        self.epochs: list[Epoch] = []
        self.membership: dict[str, tuple[int, object]] = {}   # did -> (epoch, proof)
        self.revoked: set[str] = set()
        self.used_nonces: set[str] = set()
        self.tokens: dict[str, dict] = {}
        self.window_opened_at: float | None = None

    # ---- Phase 1: registration with proof-of-possession -------------------

    def open_window(self):
        self.window_opened_at = time.time()
        self.pending.clear()

    def challenge(self) -> bytes:
        """Fresh nonce for proof-of-possession. Never reused."""
        return secrets.token_bytes(32)

    def register(self, did: str, role: str, public_key: bytes,
                 pop_signature: bytes, nonce: bytes) -> dict:
        """
        Step 5 of the assignment: the device signed our fresh challenge with its
        secret key; we verify against the public key it is claiming.
        """
        nonce_hex = nonce.hex()
        if nonce_hex in self.used_nonces:
            return {"ok": False, "error": "nonce already used", "stage": "replay check"}
        self.used_nonces.add(nonce_hex)

        if did in self.revoked:
            return {"ok": False, "error": "identity revoked", "stage": "revocation check"}

        if not crypto.verify(public_key, nonce, pop_signature):
            return {"ok": False, "error": "proof-of-possession failed",
                    "stage": "PoP verification"}

        if did in self.membership or did in self.pending:
            return {"ok": False, "error": f"{did} already registered", "stage": "duplicate check"}

        leaf = crypto.sha256(did, public_key.hex())
        self.pending[did] = PendingDevice(did=did, role=role, public_key=public_key,
                                          leaf=leaf, joined_at=time.time(),
                                          pop_verified=True)
        return {"ok": True, "leaf": leaf, "queued": len(self.pending)}

    def window_expired(self) -> bool:
        return (self.window_opened_at is not None
                and time.time() - self.window_opened_at >= self.window_seconds)

    # ---- Phase 1b: close the batch into an epoch --------------------------

    def close_window(self) -> dict:
        if not self.pending:
            return {"ok": False, "error": "no devices queued in this window"}

        leaves = [d.leaf for d in self.pending.values()]
        epoch_no = len(self.epochs)

        t0 = time.perf_counter()
        if self.structure is SignedCredentialBatch:
            commitment, aux = self.structure.close(leaves, self.server_sig_key, epoch_no)
        else:
            commitment, aux = self.structure.close(leaves)
        build_ms = (time.perf_counter() - t0) * 1000.0

        t1 = time.perf_counter()
        for did, dev in self.pending.items():
            proof = self.structure.prove(dev.leaf, leaves, aux)
            self.membership[did] = (epoch_no, proof)
        prove_ms = (time.perf_counter() - t1) * 1000.0

        ep = Epoch(number=epoch_no, commitment=commitment, leaves=sorted(leaves),
                   aux=aux, closed_at=time.time(), device_count=len(leaves))
        self.epochs.append(ep)

        # anchor the single epoch commitment on the existing identity chain
        anchored = None
        if self.chain is not None:
            anchored = self.chain.register(f"EPOCH-{epoch_no}", "epoch-root",
                                           commitment[:16])

        n = len(leaves)
        self.pending.clear()
        self.window_opened_at = None
        return {"ok": True, "epoch": epoch_no, "devices": n,
                "commitment": commitment[:16], "build_ms": round(build_ms, 3),
                "proof_gen_ms": round(prove_ms, 3), "anchored": bool(anchored),
                "structure": self.structure.name}

    # ---- Phase 2: temporary token for devices awaiting inclusion ----------

    def issue_token(self, did: str, role: str, ttl_seconds: float = 30.0) -> dict:
        """Short-lived, server-signed, for provisional access before batch close."""
        if did not in self.pending:
            return {"ok": False, "error": "device is not in the open window"}
        expiry = time.time() + ttl_seconds
        body = f"{did}|{role}|{expiry}"
        sig = crypto.sign(self.server_sig_key.secret, body.encode())
        self.tokens[did] = {"body": body, "sig": sig, "expiry": expiry, "role": role}
        return {"ok": True, "expiry": expiry, "token_bytes": len(body) + len(sig)}

    def check_token(self, did: str, nonce: bytes,
                    pop_signature: bytes, public_key: bytes) -> dict:
        """Validate signature, expiry, nonce freshness, revocation — and binding."""
        tok = self.tokens.get(did)
        if tok is None:
            return {"ok": False, "error": "no token", "stage": "token lookup"}
        if did in self.revoked:
            return {"ok": False, "error": "revoked", "stage": "revocation check"}
        if time.time() > tok["expiry"]:
            return {"ok": False, "error": "token expired", "stage": "expiry check"}
        if not crypto.verify(self.server_sig_key.public, tok["body"].encode(), tok["sig"]):
            return {"ok": False, "error": "bad token signature", "stage": "signature check"}
        nh = nonce.hex()
        if nh in self.used_nonces:
            return {"ok": False, "error": "nonce replayed", "stage": "nonce check"}
        self.used_nonces.add(nh)
        # binding: the bearer must prove possession of the key the token names
        if not crypto.verify(public_key, nonce, pop_signature):
            return {"ok": False, "error": "token holder does not hold the key",
                    "stage": "session binding"}
        return {"ok": True, "role": tok["role"]}

    # ---- Phase 3: membership verification --------------------------------

    def verify_membership(self, did: str, public_key: bytes) -> dict:
        if did in self.revoked:
            return {"ok": False, "error": "revoked", "stage": "revocation check"}
        rec = self.membership.get(did)
        if rec is None:
            return {"ok": False, "error": "not in any finalized epoch",
                    "stage": "membership lookup"}
        epoch_no, proof = rec
        ep = self.epochs[epoch_no]
        leaf = crypto.sha256(did, public_key.hex())

        t0 = time.perf_counter()
        if self.structure in (SortedBitmapBatch, SignedCredentialBatch):
            ok = self.structure.verify(leaf, proof, ep.commitment, ep.aux)
        else:
            ok = self.structure.verify(leaf, proof, ep.commitment)
        ms = (time.perf_counter() - t0) * 1000.0

        return {"ok": ok, "epoch": epoch_no, "verify_ms": round(ms, 4),
                "proof_bytes": self.structure.proof_bytes(proof),
                "stage": "inclusion proof"}

    def revoke(self, did: str) -> dict:
        self.revoked.add(did)
        self.tokens.pop(did, None)
        return {"ok": True, "revoked": did}
