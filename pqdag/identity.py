"""
Identity-set structures for BC_ID.

Two interchangeable ways to commit to the set of registered identities, so the
choice can be measured rather than argued:

  SortedMerkleSet   dense binary Merkle tree over sorted leaves. A leaf's
                    position is its rank, so inserting shifts every rank after
                    it and the tree is rebuilt: O(n) per insert, O(log n) proof.
                    Cheapest at small n, which is why it is the default.

  SparseMerkleSet   leaf position is the key itself, over a 256-bit space.
                    Nothing ever moves, so an insert walks one root-to-leaf
                    path: O(depth) per insert regardless of n. Costs more at
                    small n because depth is fixed at 256; wins once n is large
                    enough that rebuilding beats walking the depth.

Both expose the same four operations, so RegistrationChain does not care which
it holds:

    insert(leaf)              add an identity
    root()                    32-byte commitment to the whole set
    prove(leaf)               inclusion proof
    verify(leaf, proof, root) static; needs no access to the set

PROOF SIZE, AND WHY THE SPARSE TREE IS THE COMPACT VARIANT
----------------------------------------------------------
A naive sparse Merkle proof carries one sibling per level - 256 of them, about
8 KB. That is unusable here: this project's own measurements show bytes are the
binding cost. So the sibling list omits every sibling that is just the empty
subtree default, and a bitmap records which levels were kept. Proofs come back
to roughly log2(n) hashes plus 32 bytes of bitmap.
"""

from __future__ import annotations

from . import crypto
from .ledger import merkle_root, merkle_path, merkle_verify


# --------------------------------------------------------------------------
# Dense: sorted-array Merkle tree  (what the prototype uses by default)
# --------------------------------------------------------------------------


class SortedMerkleSet:
    name = "sorted-array Merkle"
    kind = "sorted"

    def __init__(self):
        self._leaves: set[str] = set()
        self._ordered: list[str] | None = None      # cache, invalidated on insert

    def insert(self, leaf: str) -> None:
        self._leaves.add(leaf)
        self._ordered = None

    def _sorted(self) -> list[str]:
        if self._ordered is None:
            self._ordered = sorted(self._leaves)
        return self._ordered

    def __len__(self) -> int:
        return len(self._leaves)

    def root(self) -> str:
        return merkle_root(self._sorted())

    def prove(self, leaf: str) -> dict | None:
        if leaf not in self._leaves:
            return None
        ordered = self._sorted()
        path = merkle_path(ordered, ordered.index(leaf))
        return {"structure": "sorted", "path": path,
                "bytes": sum(33 for s, _ in path if s is not None)}

    @staticmethod
    def verify(leaf: str, proof: dict, root: str) -> bool:
        return merkle_verify(leaf, proof["path"], root)


# --------------------------------------------------------------------------
# Sparse: position fixed by key, compact proofs
# --------------------------------------------------------------------------


class SparseMerkleSet:
    name = "sparse Merkle (compact)"
    kind = "smt"
    DEPTH = 256

    def __init__(self):
        self.node: dict[tuple[int, int], str] = {}
        self._leaves: set[str] = set()
        self._default = self._defaults()

    @classmethod
    def _defaults(cls) -> list[str]:
        """default[level] is the root of a completely empty subtree at that level.

        Deterministic and identical for every party, so a verifier reconstructs
        them without touching the set.
        """
        d = [""] * (cls.DEPTH + 1)
        d[cls.DEPTH] = crypto.sha256("smt-empty-leaf")
        for lvl in range(cls.DEPTH - 1, -1, -1):
            d[lvl] = crypto.sha256(d[lvl + 1], d[lvl + 1])
        return d

    def __len__(self) -> int:
        return len(self._leaves)

    # ---- insert: one root-to-leaf path, no rebuild ----------------------

    def insert(self, leaf: str) -> None:
        self._leaves.add(leaf)
        D = self.DEPTH
        ki = int(leaf, 16)
        self.node[(D, ki)] = leaf
        for lvl in range(D - 1, -1, -1):
            pre = ki >> (D - lvl)
            left = self.node.get((lvl + 1, pre * 2), self._default[lvl + 1])
            right = self.node.get((lvl + 1, pre * 2 + 1), self._default[lvl + 1])
            self.node[(lvl, pre)] = crypto.sha256(left, right)

    def root(self) -> str:
        return self.node.get((0, 0), self._default[0])

    # ---- prove: skip default siblings, record which in a bitmap ---------

    def prove(self, leaf: str) -> dict | None:
        if leaf not in self._leaves:
            return None
        D = self.DEPTH
        ki = int(leaf, 16)
        sibs, bitmap = [], 0
        for lvl in range(D - 1, -1, -1):
            pre = ki >> (D - lvl)
            bit = (ki >> (D - 1 - lvl)) & 1
            sib = self.node.get((lvl + 1, pre * 2 + (1 - bit)), self._default[lvl + 1])
            if sib != self._default[lvl + 1]:
                sibs.append(sib)
                bitmap |= 1 << lvl
        return {"structure": "smt", "sibs": sibs, "bitmap": bitmap,
                "bytes": len(sibs) * 32 + 32}      # siblings + the 256-bit bitmap

    @staticmethod
    def verify(leaf: str, proof: dict, root: str) -> bool:
        D = SparseMerkleSet.DEPTH
        default = SparseMerkleSet._defaults()
        ki = int(leaf, 16)
        sibs, bitmap = proof["sibs"], proof["bitmap"]
        si = 0
        h = leaf
        for lvl in range(D - 1, -1, -1):
            if (bitmap >> lvl) & 1:
                if si >= len(sibs):
                    return False
                sib = sibs[si]
                si += 1
            else:
                sib = default[lvl + 1]
            bit = (ki >> (D - 1 - lvl)) & 1
            h = crypto.sha256(sib, h) if bit else crypto.sha256(h, sib)
        return si == len(sibs) and h == root


STRUCTURES = {"sorted": SortedMerkleSet, "smt": SparseMerkleSet}


def verify_proof(leaf: str, proof: dict, root: str) -> bool:
    """Dispatch on the structure the proof declares."""
    if not proof:
        return False
    cls = STRUCTURES.get(proof.get("structure"))
    return bool(cls and cls.verify(leaf, proof, root))
