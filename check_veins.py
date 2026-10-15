#!/usr/bin/env python3
"""
CI gate for the OMNeT++/Veins runs made by run_experiments.py.

    python ci/check_veins.py Default Replicated

Reads the newest results/batch-*/runs.csv, re-analyses every run with
analyze_omnet.py, and fails (exit code 1) unless, for every configuration:

  * the run exists (OMNeT++ did not crash),
  * all six attack checks pass (four refused, the in-window replay and the
    compromised car accepted, exactly as the base paper's design implies),
  * at least one transaction reached finality,
  * with one ledger per gateway (Phase 3b): every record finalised at its
    origin is final in every ledger copy at the end,
  * where the BC_ID record is exported (3b-bcid on): the hash chain and the
    inclusion proofs verify.

Writes a results table to the GitHub job summary when run in Actions.
"""

from __future__ import annotations

import csv
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from analyze_omnet import analyse, load_run  # noqa: E402


def main() -> int:
    wanted = sys.argv[1:]
    batches = sorted((ROOT / "results").glob("batch-*"))
    if not batches or not (batches[-1] / "runs.csv").exists():
        print("FAIL: no results/batch-*/runs.csv - run_experiments.py produced nothing")
        return 1
    batch = batches[-1]
    rows = list(csv.DictReader(open(batch / "runs.csv", newline="")))
    print(f"Batch: {batch.name}, {len(rows)} run(s)")

    failures: list[str] = []
    table = ["| Config | Attack checks | Delivery | Finality p50 | False readings final | Ledger copies agree | BC_ID record |",
             "|---|---|---|---|---|---|---|"]
    seen = set()
    for row in rows:
        cfg = row["config"]
        seen.add(cfg)
        a = analyse(load_run(ROOT / "results" / row["run"]))
        bc = a["blockchain"]

        checks = a["attack_checks"]
        passed = sum(1 for c in checks if c["result"].startswith("PASS"))
        if passed != len(checks) or len(checks) < 6:
            bad = [c["attack"] for c in checks if not c["result"].startswith("PASS")]
            failures.append(f"{cfg}: attack checks {passed}/{len(checks)} (failed: {', '.join(bad) or 'missing'})")
        if not bc["tx_finalised"]:
            failures.append(f"{cfg}: no transaction reached finality")

        rep = (a.get("backhaul") or {}).get("replication")
        agree = "shared ledger"
        if rep:
            fin, every = rep.get("finalised_at_origin", 0), rep.get("final_in_every_replica_at_end", 0)
            agree = f"{every}/{fin}"
            if every != fin:
                failures.append(f"{cfg}: only {every} of {fin} final records are final in every ledger copy")

        reg = bc.get("registry")
        bcid = "not exported"
        if reg:
            proofs = reg.get("inclusion_proofs_valid")
            bcid = f"{reg.get('registered')} identities, chain {'valid' if reg.get('chain_valid') else 'BROKEN'}"
            if proofs:
                bcid += f", proofs {proofs}"
            if reg.get("chain_valid") is not True:
                failures.append(f"{cfg}: BC_ID hash chain does not verify")
            if isinstance(proofs, str) and "/" in proofs and len(set(proofs.split("/"))) != 1:
                failures.append(f"{cfg}: only {proofs} BC_ID inclusion proofs verify")

        fin_s = (bc.get("finality_s") or {}).get("p50")
        mal = (bc.get("malicious_readings") or {}).get("finalised")
        dr = (a["network"].get("delivery_ratio") or 0) * 100
        table.append(f"| {cfg} | {passed}/{len(checks)} | {dr:.1f}% | {fin_s} s | {mal} | {agree} | {bcid} |")
        print(f"  {cfg:20s} checks {passed}/{len(checks)}  delivery {dr:.1f}%  finality p50 {fin_s} s  "
              f"false readings final {mal}  copies agree {agree}  BC_ID {bcid}")

    for cfg in wanted:
        if cfg not in seen:
            failures.append(f"{cfg}: no run (OMNeT++ failed - see its log in the uploaded artifact)")

    for f in failures:
        print("  FAIL:", f)
    print("RESULT:", "PASS" if not failures else "FAIL")

    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"### OMNeT++/Veins runs — {'✅ pass' if not failures else '❌ fail'}\n\n")
            fh.write("\n".join(table) + "\n\n")
            fh.write("".join(f"- ❌ {f}\n" for f in failures) + "\n")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
