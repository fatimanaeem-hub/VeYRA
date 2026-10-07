"""Sweep 1: PoPQW difficulty and signature cost. Feeds the handbook tables."""
import json, statistics
from pqdag import crypto
from pqdag.ledger import solve_popqw

out = {}
diff = {}
for bits in (8, 10, 12, 14, 16, 18):
    reps = 25 if bits <= 14 else 9
    times = [solve_popqw(crypto.sha256("tx", bits, i), "GW-00", bits)[2]
             for i in range(reps)]
    diff[bits] = {"median_ms": round(statistics.median(times), 2),
                  "mean_ms": round(statistics.mean(times), 2),
                  "expected_hashes": 2 ** bits, "samples": reps}
out["popqw_difficulty"] = diff

keys = [crypto.sig_keygen() for _ in range(9)]
msg = bytes.fromhex(crypto.sha256("tx"))
per_sig = statistics.median(
    [crypto.timeit(lambda: crypto.sign(keys[0].secret, msg), 5) for _ in range(9)])
out["signature_unit"] = {"median_sign_ms": round(per_sig, 1), "signature_bytes": 2420}
out["threshold_t"] = {t: {"cert_bytes": 2420 * t, "est_sign_ms": round(per_sig * t, 1)}
                      for t in (1, 3, 5, 7, 9)}
print(json.dumps(out, indent=1))
