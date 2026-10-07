"""
Cryptographic layer for the PQ-DAG VSN proof of concept.

Backend selection is deliberate and visible: the prototype reports which
implementation it is actually running so that no measurement is ever mistaken
for something it is not.

Preference order
  1. liboqs-python (compiled C, production-grade)          -> backend "liboqs"
  2. kyber-py + dilithium-py (pure Python, NIST-correct)   -> backend "pure-python"
  3. RSA-3072 / ECDSA-P256 classical stand-in              -> backend "classical-fallback"

Backends 1 and 2 implement the real NIST standards:
  ML-KEM-768  (FIPS 203, formerly CRYSTALS-Kyber-768)
  ML-DSA-44   (FIPS 204, formerly CRYSTALS-Dilithium-2)

Backend 3 is NOT post-quantum. It exists only so the demo still runs on a
machine with no network access, and the GUI shows a red banner when it is used.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from dataclasses import dataclass

# --------------------------------------------------------------------------
# Backend detection
# --------------------------------------------------------------------------

BACKEND = None
BACKEND_NOTE = ""
IS_POST_QUANTUM = False

_kem = None
_sig = None

try:  # 1. liboqs (compiled)
    import oqs  # type: ignore

    BACKEND = "liboqs"
    BACKEND_NOTE = "Open Quantum Safe liboqs (compiled C) - production-grade speed."
    IS_POST_QUANTUM = True
except ImportError:
    try:  # 2. pure-python reference implementations
        from kyber_py.ml_kem import ML_KEM_768 as _kem  # type: ignore
        from dilithium_py.ml_dsa import ML_DSA_44 as _sig  # type: ignore

        BACKEND = "pure-python"
        BACKEND_NOTE = (
            "kyber-py / dilithium-py pure-Python reference implementations. "
            "Algorithms and key sizes are the real NIST standards; raw speed is "
            "roughly 1-2 orders of magnitude slower than optimised C."
        )
        IS_POST_QUANTUM = True
    except ImportError:  # 3. classical stand-in
        BACKEND = "classical-fallback"
        BACKEND_NOTE = (
            "NOT POST-QUANTUM. RSA-3072 / ECDSA-P256 stand-in because no PQC "
            "library is installed. Install requirements.txt for real results."
        )
        IS_POST_QUANTUM = False

# --------------------------------------------------------------------------
# Symmetric layer (AES-256-GCM preferred, stdlib fallback always available)
# --------------------------------------------------------------------------

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore

    SYMMETRIC = "AES-256-GCM"

    def sym_encrypt(key: bytes, plaintext: bytes) -> bytes:
        k = hashlib.sha256(key).digest()
        nonce = os.urandom(12)
        return nonce + AESGCM(k).encrypt(nonce, plaintext, None)

    def sym_decrypt(key: bytes, blob: bytes) -> bytes:
        k = hashlib.sha256(key).digest()
        return AESGCM(k).decrypt(blob[:12], blob[12:], None)

except ImportError:  # stdlib-only authenticated stream cipher
    SYMMETRIC = "SHA256-CTR + HMAC-SHA256 (stdlib fallback)"

    def _keystream(key: bytes, nonce: bytes, n: int) -> bytes:
        out = bytearray()
        ctr = 0
        while len(out) < n:
            out += hashlib.sha256(key + nonce + ctr.to_bytes(8, "big")).digest()
            ctr += 1
        return bytes(out[:n])

    def sym_encrypt(key: bytes, plaintext: bytes) -> bytes:
        k = hashlib.sha256(key).digest()
        nonce = os.urandom(12)
        ct = bytes(a ^ b for a, b in zip(plaintext, _keystream(k, nonce, len(plaintext))))
        tag = hmac.new(k, nonce + ct, hashlib.sha256).digest()[:16]
        return nonce + tag + ct

    def sym_decrypt(key: bytes, blob: bytes) -> bytes:
        k = hashlib.sha256(key).digest()
        nonce, tag, ct = blob[:12], blob[12:28], blob[28:]
        if not hmac.compare_digest(tag, hmac.new(k, nonce + ct, hashlib.sha256).digest()[:16]):
            raise ValueError("authentication tag mismatch")
        return bytes(a ^ b for a, b in zip(ct, _keystream(k, nonce, len(ct))))


# --------------------------------------------------------------------------
# KEM  (Algorithm 2 in the paper: session-key establishment)
# --------------------------------------------------------------------------


@dataclass
class KeyPair:
    public: bytes
    secret: bytes


def kem_keygen() -> KeyPair:
    if BACKEND == "liboqs":
        import oqs

        k = oqs.KeyEncapsulation("ML-KEM-768")
        pub = k.generate_keypair()
        return KeyPair(pub, k.export_secret_key())
    if BACKEND == "pure-python":
        ek, dk = _kem.keygen()
        return KeyPair(ek, dk)
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    sk = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return KeyPair(
        sk.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        sk.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def kem_encaps(public_key: bytes) -> tuple[bytes, bytes]:
    """Returns (shared_secret, ciphertext)."""
    if BACKEND == "liboqs":
        import oqs

        with oqs.KeyEncapsulation("ML-KEM-768") as k:
            ct, ss = k.encap_secret(public_key)
        return ss, ct
    if BACKEND == "pure-python":
        ss, ct = _kem.encaps(public_key)
        return ss, ct
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import serialization, hashes

    pk = serialization.load_der_public_key(public_key)
    ss = os.urandom(32)
    ct = pk.encrypt(
        ss,
        padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None),
    )
    return ss, ct


def kem_decaps(secret_key: bytes, ciphertext: bytes) -> bytes:
    if BACKEND == "liboqs":
        import oqs

        with oqs.KeyEncapsulation("ML-KEM-768", secret_key) as k:
            return k.decap_secret(ciphertext)
    if BACKEND == "pure-python":
        return _kem.decaps(secret_key, ciphertext)
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import serialization, hashes

    sk = serialization.load_der_private_key(secret_key, password=None)
    return sk.decrypt(
        ciphertext, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
    )


# --------------------------------------------------------------------------
# Signatures  (used for the t-of-n finalisation certificate)
# --------------------------------------------------------------------------


def sig_keygen() -> KeyPair:
    if BACKEND == "liboqs":
        import oqs

        s = oqs.Signature("ML-DSA-44")
        pub = s.generate_keypair()
        return KeyPair(pub, s.export_secret_key())
    if BACKEND == "pure-python":
        pk, sk = _sig.keygen()
        return KeyPair(pk, sk)
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization

    sk = ec.generate_private_key(ec.SECP256R1())
    return KeyPair(
        sk.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        sk.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def sign(secret_key: bytes, message: bytes) -> bytes:
    if BACKEND == "liboqs":
        import oqs

        with oqs.Signature("ML-DSA-44", secret_key) as s:
            return s.sign(message)
    if BACKEND == "pure-python":
        return _sig.sign(secret_key, message)
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization, hashes

    sk = serialization.load_der_private_key(secret_key, password=None)
    return sk.sign(message, ec.ECDSA(hashes.SHA256()))


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        if BACKEND == "liboqs":
            import oqs

            with oqs.Signature("ML-DSA-44") as s:
                return bool(s.verify(message, signature, public_key))
        if BACKEND == "pure-python":
            return bool(_sig.verify(public_key, message, signature))
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization, hashes

        pk = serialization.load_der_public_key(public_key)
        pk.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def sha256(*parts) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p if isinstance(p, bytes) else str(p).encode())
    return h.hexdigest()


def backend_info() -> dict:
    kem = kem_keygen()
    ss, ct = kem_encaps(kem.public)
    sg = sig_keygen()
    s = sign(sg.secret, b"probe")
    return {
        "backend": BACKEND,
        "note": BACKEND_NOTE,
        "post_quantum": IS_POST_QUANTUM,
        "kem_name": "ML-KEM-768 (FIPS 203)" if IS_POST_QUANTUM else "RSA-3072 OAEP",
        "sig_name": "ML-DSA-44 (FIPS 204)" if IS_POST_QUANTUM else "ECDSA P-256",
        "symmetric": SYMMETRIC,
        "kem_public_bytes": len(kem.public),
        "kem_ciphertext_bytes": len(ct),
        "sig_public_bytes": len(sg.public),
        "signature_bytes": len(s),
    }


def timeit(fn, repeats: int = 20) -> float:
    """Median milliseconds per call."""
    samples = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)
    samples.sort()
    return samples[len(samples) // 2]
