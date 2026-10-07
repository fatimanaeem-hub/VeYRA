"""Self-check: run this to confirm the prototype is intact before a defence."""
import sys, time, subprocess, json

def check(name, fn):
    try:
        r = fn()
        print(f"  PASS  {name}" + (f"  ({r})" if r else ""))
        return True
    except Exception as e:
        print(f"  FAIL  {name}: {e}")
        return False

print("Verifying PQ-DAG VSN proof of concept\n")
results = []

from pqdag import crypto
results.append(check("crypto backend loads", lambda: crypto.BACKEND))

def kem_roundtrip():
    kp = crypto.kem_keygen(); ss, ct = crypto.kem_encaps(kp.public)
    assert crypto.kem_decaps(kp.secret, ct) == ss, "shared secrets differ"
    return f"{len(kp.public)} B key, {len(ct)} B ciphertext"
results.append(check("KEM round-trip", kem_roundtrip))

def sig_roundtrip():
    kp = crypto.sig_keygen(); s = crypto.sign(kp.secret, b"m")
    assert crypto.verify(kp.public, b"m", s), "valid signature rejected"
    assert not crypto.verify(kp.public, b"m2", s), "forged message accepted"
    return f"{len(s)} B signature"
results.append(check("signature round-trip and forgery rejection", sig_roundtrip))

def aead():
    c = crypto.sym_encrypt(b"k"*32, b"payload")
    assert crypto.sym_decrypt(b"k"*32, c) == b"payload"
    bad = bytearray(c); bad[-1] ^= 1
    try:
        crypto.sym_decrypt(b"k"*32, bytes(bad)); raise AssertionError("tamper accepted")
    except AssertionError: raise
    except Exception: pass
    return crypto.SYMMETRIC
results.append(check("AEAD encrypt/decrypt and tamper detection", aead))

from pqdag.ledger import merkle_root, solve_popqw, check_popqw
def merkle():
    a = merkle_root(["a"*64, "b"*64, "c"*64])
    assert a == merkle_root(["a"*64, "b"*64, "c"*64]), "not deterministic"
    assert a != merkle_root(["a"*64, "b"*64, "d"*64]), "insensitive to input"
    return a[:12]
results.append(check("Merkle root deterministic and input-sensitive", merkle))

def popqw():
    n, h, ms = solve_popqw("ab"*32, "GW", 12)
    assert check_popqw("ab"*32, "GW", n, 12), "own solution rejected"
    assert not check_popqw("ab"*32, "GW", n + 1, 12), "wrong nonce accepted"
    return f"nonce {n} in {ms:.1f} ms"
results.append(check("PoPQW solve and verify", popqw))

from pqdag.simulation import SIM
def pipeline():
    SIM.build(n_gateways=2, sensors_per_gateway=2, difficulty=11, t=2)
    SIM.set_traffic(True, 5.0); time.sleep(6); SIM.set_traffic(False); time.sleep(1)
    s = SIM.snapshot()["stats"]
    assert s["total"] > 0, "no transactions produced"
    assert s["finalized"] > 0, "nothing reached finalisation"
    assert s["rejected"] == 0, f"{s['rejected']} transactions rejected"
    return f"{s['total']} created, {s['finalized']} finalised, 0 rejected"
results.append(check("end-to-end pipeline", pipeline))

def security():
    checks = SIM.run_security_checks()
    failed = [c["check"] for c in checks if not c["pass"]]
    assert not failed, f"accepted bad input: {failed}"
    return f"{len(checks)}/{len(checks)} adversarial inputs rejected"
results.append(check("adversarial checks", security))
SIM.stop()

def fallback():
    code = ("import sys;"
            "sys.modules['kyber_py']=None; sys.modules['oqs']=None;"
            "sys.modules['kyber_py.ml_kem']=None;"
            "import pqdag.crypto as c; print(c.BACKEND, c.IS_POST_QUANTUM)")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         text=True, cwd=".")
    assert "classical-fallback False" in out.stdout, out.stdout + out.stderr
    return "falls back and reports itself as not post-quantum"
results.append(check("classical fallback path", fallback))

print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
