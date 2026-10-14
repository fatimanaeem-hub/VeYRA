"""
Microbenchmarks: what post-quantum cryptography actually costs a sensor node.

This is the measurement the proposal defence turns on. It answers, with numbers
from the machine it runs on:
  - how long a sensor spends establishing a PQ session key,
  - how many bytes that costs on the air interface,
  - how those two compare with the classical primitives PQC would replace.
"""

from __future__ import annotations

from . import crypto


def _classical_available() -> bool:
    try:
        import cryptography  # noqa: F401

        return True
    except ImportError:
        return False


def run(repeats: int = 15) -> dict:
    out = {"backend": crypto.backend_info(), "rows": [], "repeats": repeats}

    # --- post-quantum / active backend --------------------------------
    kp = crypto.kem_keygen()
    ss, ct = crypto.kem_encaps(kp.public)
    sk = crypto.sig_keygen()
    msg = b"vsn-transaction-hash-probe"
    sig = crypto.sign(sk.secret, msg)

    label = "ML-KEM-768 (Kyber)" if crypto.IS_POST_QUANTUM else "RSA-3072 (fallback)"
    out["rows"].append({
        "family": "KEM / key establishment",
        "algorithm": label,
        "post_quantum": crypto.IS_POST_QUANTUM,
        "keygen_ms": round(crypto.timeit(crypto.kem_keygen, repeats), 3),
        "op1_name": "encapsulate (sensor)",
        "op1_ms": round(crypto.timeit(lambda: crypto.kem_encaps(kp.public), repeats), 3),
        "op2_name": "decapsulate (gateway)",
        "op2_ms": round(crypto.timeit(lambda: crypto.kem_decaps(kp.secret, ct), repeats), 3),
        "public_key_bytes": len(kp.public),
        "wire_bytes": len(ct),
    })

    slabel = "ML-DSA-44 (Dilithium)" if crypto.IS_POST_QUANTUM else "ECDSA P-256 (fallback)"
    out["rows"].append({
        "family": "Signature / finalisation",
        "algorithm": slabel,
        "post_quantum": crypto.IS_POST_QUANTUM,
        "keygen_ms": round(crypto.timeit(crypto.sig_keygen, repeats), 3),
        "op1_name": "sign (gateway)",
        "op1_ms": round(crypto.timeit(lambda: crypto.sign(sk.secret, msg), repeats), 3),
        "op2_name": "verify",
        "op2_ms": round(crypto.timeit(lambda: crypto.verify(sk.public, msg, sig), repeats), 3),
        "public_key_bytes": len(sk.public),
        "wire_bytes": len(sig),
    })

    # --- classical comparators ----------------------------------------
    if _classical_available():
        from cryptography.hazmat.primitives.asymmetric import ec, x25519
        from cryptography.hazmat.primitives import hashes

        # X25519 ECDH - what VSN key exchange uses today
        a = x25519.X25519PrivateKey.generate()
        b = x25519.X25519PrivateKey.generate()
        bpub = b.public_key()
        out["rows"].append({
            "family": "KEM / key establishment",
            "algorithm": "X25519 ECDH (classical, quantum-broken)",
            "post_quantum": False,
            "keygen_ms": round(crypto.timeit(x25519.X25519PrivateKey.generate, repeats), 3),
            "op1_name": "exchange (sensor)",
            "op1_ms": round(crypto.timeit(lambda: a.exchange(bpub), repeats), 3),
            "op2_name": "exchange (gateway)",
            "op2_ms": round(crypto.timeit(lambda: b.exchange(a.public_key()), repeats), 3),
            "public_key_bytes": 32,
            "wire_bytes": 32,
        })

        e = ec.generate_private_key(ec.SECP256R1())
        epub = e.public_key()
        esig = e.sign(msg, ec.ECDSA(hashes.SHA256()))

        def _verify_ec():
            try:
                epub.verify(esig, msg, ec.ECDSA(hashes.SHA256()))
            except Exception:
                pass

        out["rows"].append({
            "family": "Signature / finalisation",
            "algorithm": "ECDSA P-256 (classical, quantum-broken)",
            "post_quantum": False,
            "keygen_ms": round(
                crypto.timeit(lambda: ec.generate_private_key(ec.SECP256R1()), repeats), 3),
            "op1_name": "sign",
            "op1_ms": round(
                crypto.timeit(lambda: e.sign(msg, ec.ECDSA(hashes.SHA256())), repeats), 3),
            "op2_name": "verify",
            "op2_ms": round(crypto.timeit(_verify_ec, repeats), 3),
            "public_key_bytes": 91,
            "wire_bytes": len(esig),
        })

    # --- derived: handshake budget on the air interface ---------------
    pq = out["rows"][0]
    cl = next((r for r in out["rows"] if "X25519" in r["algorithm"]), None)
    out["summary"] = {
        "pq_handshake_wire_bytes": pq["public_key_bytes"] + pq["wire_bytes"],
        "classical_handshake_wire_bytes": (cl["public_key_bytes"] + cl["wire_bytes"])
        if cl else None,
        "wire_overhead_factor": round(
            (pq["public_key_bytes"] + pq["wire_bytes"])
            / (cl["public_key_bytes"] + cl["wire_bytes"]), 1) if cl else None,
        "pq_sensor_side_ms": pq["op1_ms"],
        "classical_sensor_side_ms": cl["op1_ms"] if cl else None,
    }
    return out


if __name__ == "__main__":
    import json

    print(json.dumps(run(), indent=2))
