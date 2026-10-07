"""Sweep 2: how network size - and therefore FT - changes the finalised share.

FT is no longer a dial. Per Table III of the paper it follows from the number of
nodes, so the only way to move it is to build a different-sized network. Each row
below reports the size, the band it lands in, and the FT that band implies.
"""
import json, time
from pqdag.simulation import SIM

# (gateways, sensors_per_gateway) -> nodes = gw * (1 + spg)
SIZES = [
    (2, 2),   #  6 nodes - Small  band - FT 3
    (3, 4),   # 15 nodes - Medium band - FT 5
    (5, 4),   # 25 nodes - Large  band - FT 10
    (8, 8),   # 72 nodes - Large  band - FT 10 (the biggest network we can build)
]

rows = {}
for gw, spg in SIZES:
    SIM.build(n_gateways=gw, sensors_per_gateway=spg, difficulty=12, t=3)
    SIM.set_traffic(True, 4.0); time.sleep(12); SIM.set_traffic(False); time.sleep(1.2)
    s = SIM.snapshot()["stats"]
    key = f"{s['network_nodes']}n"
    rows[key] = {"gateways": gw, "sensors_per_gw": spg,
                 "band": s["ft_band"], "FT": s["FT"],
                 "paper_band": s["ft_paper_range"],
                 "created": s["total"], "finalized": s["finalized"],
                 "pct_final": round(100 * s["finalized"] / max(s["total"], 1)),
                 "latency_s": round(s["avg_finalization_latency_s"] or 0, 2),
                 "rejected": s["rejected"], "retries": s["publish_retries"]}
    print(key, rows[key], flush=True)
SIM.stop()
print(json.dumps(rows, indent=1))
