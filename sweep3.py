"""Sweep 3: how DAG speed-up scales with gateway count on this machine."""
import json
from pqdag import experiment

rows = {}
for g in (1, 2, 4, 6):
    r = experiment.run(n_gateways=g, tx_per_gateway=4, difficulty=13, t=3)
    rows[g] = {"dag_tps": r["dag"]["entries_per_s"],
               "lin_tps": r["linear"]["entries_per_s"],
               "speedup": r["speedup"], "cores": r["parameters"]["cpu_cores"],
               "workers": r["parameters"]["worker_processes"]}
    print(g, rows[g], flush=True)
print(json.dumps(rows, indent=1))
