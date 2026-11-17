#!/usr/bin/env python3
"""
Iteration 2: turn VEYRA runs into the anomaly detector's dataset (see ATTACKS.md).

    python export_dataset.py results/batch-20261120-101500          # a run_experiments.py batch
    python export_dataset.py results/omnet-run-20261120-101530       # one run
    python export_dataset.py results/batch-* --radio-range 600 --out dataset

For every run it takes the READING rows the gateways ACCEPTED (they passed the
post-quantum checks, so only the detector can still catch false data), maps
them to the detector's input format, and computes the 22 features
(detector/candidates.py). Output in --out (default: dataset/):

    <run>.parquet         one row per accepted reading: labels + features (FINAL_22_RATIO)
    all_runs.parquet      everything together
    summary.csv           per run: config, seed, readings, attackers, false readings, manoeuvres
    checks.txt            the coordinate / heading / road checks (read it after the first run)

Conversions (VEYRA -> detector format):
    speed         reported_speed_kmh / 3.6 (m/s)
    position      OMNeT++ (y down) -> y up, as in VeReMi
    heading       Veins convention -> compass (0 = north, clockwise), detected on honest cars
    rcv_dist      claimed position -> the RSU that received the reading (positions from omnetpp.ini)
    rcv_ratio     rcv_dist / radio range (--radio-range, else the 99.5th percentile of honest rcv_dist)
    road_edge     from erlangen.net.xml lane shapes (OMNeT++ -> SUMO: Veins' 25 m margin, y flipped)
    label         1 if truth == "malicious" (the reading carried false data), else 0
Needs: pandas, numpy, scipy, pyarrow.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.spatial import cKDTree

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "detector"))
from candidates import FINAL_22_RATIO, add_rcv_ratio, full_pipeline  # noqa: E402

INI = HERE / "veins_veyra" / "simulations" / "omnetpp.ini"
NET = HERE / "veins_veyra" / "simulations" / "erlangen.net.xml"
VEINS_MARGIN = 25.0     # TraCIScenarioManager default; checked: the RSUs then sit < 1 m from the route


# ------------------------------------------------------------------ inputs
def find_runs(paths: list[str]) -> list[tuple[Path, dict]]:
    """(omnet-run folder, {config, seed}) for batch folders, run folders or results/."""
    out = []
    for p in map(Path, paths):
        if (p / "messages.csv").exists():
            out.append((p, {}))
        elif (p / "runs.csv").exists():                       # a run_experiments.py batch
            for row in csv.DictReader(open(p / "runs.csv", newline="")):
                run = p.parent / row["run"]
                if (run / "messages.csv").exists():
                    out.append((run, {"config": row["config"], "seed": int(row["seed"])}))
        else:
            out += [(r, {}) for r in sorted(p.glob("omnet-run-*")) if (r / "messages.csv").exists()]
    seen, uniq = set(), []
    for r, meta in out:
        if r.resolve() not in seen:
            seen.add(r.resolve()); uniq.append((r, meta))
    return uniq


def ini_rsu_positions(config: str) -> dict[int, tuple[float, float]]:
    """RSU x/y for a config, following 'extends' back to [General]."""
    sections, cur = {}, "General"
    for line in open(INI, encoding="utf-8"):
        line = line.split("#")[0].strip()
        m = re.match(r"\[(?:Config\s+)?([^\]]+)\]", line)
        if m:
            cur = m.group(1).strip(); sections.setdefault(cur, {}); continue
        if "=" in line:
            k, v = (s.strip() for s in line.split("=", 1)); sections.setdefault(cur, {})[k] = v
    chain, todo = [], [config]
    while todo:
        c = todo.pop(0)
        if c in sections and c not in chain:
            chain.append(c)
            todo += [e.strip() for e in sections[c].get("extends", "").split(",") if e.strip()]
    chain.append("General")
    pos: dict[int, dict] = {}
    for c in reversed(chain):                    # later (more specific) sections win
        for k, v in sections.get(c, {}).items():
            m = re.match(r"\*\.rsu\[(\d+)\]\.mobility\.([xy])$", k)
            if m:
                pos.setdefault(int(m.group(1)), {})[m.group(2)] = float(v.split()[0].rstrip("m"))
    return {i: (d["x"], d["y"]) for i, d in pos.items() if "x" in d and "y" in d}


class RoadMap:
    """Distance to the road edge from SUMO lane shapes (no sumolib needed)."""
    def __init__(self, net: Path, step: float = 1.0):
        root = ET.parse(net).getroot()
        self.minx, _, _, self.maxy = map(float, root.find("location").get("convBoundary").split(","))
        pts, half = [], []
        for e in root.findall("edge"):
            for l in e.findall("lane"):
                sh = np.array([[float(v) for v in p.split(",")[:2]] for p in l.get("shape").split()])
                w = float(l.get("width", 3.2)) / 2
                for a, b in zip(sh[:-1], sh[1:]):
                    n = max(1, int(np.ceil(np.hypot(*(b - a)) / step)))
                    seg = a + (b - a) * (np.arange(n + 1)[:, None] / n)
                    pts.append(seg); half.append(np.full(len(seg), w))
        self.tree = cKDTree(np.vstack(pts)); self.half = np.concatenate(half)

    def road_edge(self, x_omnet, y_omnet):
        sx = np.asarray(x_omnet) - VEINS_MARGIN + self.minx
        sy = self.maxy - (np.asarray(y_omnet) - VEINS_MARGIN)
        d, i = self.tree.query(np.c_[sx, sy], k=1)
        return self.half[i] - d                    # > 0 on the road, < 0 off it


# ------------------------------------------------------------------ conversion
HEADING_RULES = {                                  # Veins heading (deg) -> compass in a y-up frame
    "90 - h": lambda h: (90 - h) % 360,
    "90 + h": lambda h: (90 + h) % 360,
    "h": lambda h: h % 360,
    "-h": lambda h: (-h) % 360,
}


def load_run(run: Path, meta: dict) -> pd.DataFrame:
    m = pd.read_csv(run / "messages.csv", dtype=str, keep_default_na=False)
    m = m[(m["type"] == "READING") & (m["reply"] == "ack")].copy()
    info = json.loads((run / "run_info.json").read_text()) if (run / "run_info.json").exists() else {}
    config = meta.get("config") or info.get("config", "?")
    seed = meta.get("seed", info.get("run", ""))
    num = lambda c: pd.to_numeric(m[c], errors="coerce")
    rsu_idx = m["rsu"].str.extract(r"\[(\d+)\]")[0].astype(float)
    rsu = ini_rsu_positions(config)
    rx = rsu_idx.map(lambda i: rsu.get(int(i), (np.nan, np.nan))[0] if i == i else np.nan)
    ry = rsu_idx.map(lambda i: rsu.get(int(i), (np.nan, np.nan))[1] if i == i else np.nan)
    x, y = num("x"), num("y")
    df = pd.DataFrame({
        "run": run.name, "config": config, "seed": seed,
        "sender": run.name + ":" + m["vehicle"], "true_vehicle": run.name + ":" + m["vehicle"],
        "msg_id": num("seq").astype("int64"),
        "t_send": num("sent_s"), "t_rcv": num("arrived_s"),
        "x": x, "y": -y, "x_omnet": x, "y_omnet": y,
        "spd": num("reported_speed_kmh") / 3.6, "acl": num("accel_ms2"), "heading_veins": num("heading_deg"),
        "rcv_dist": np.hypot(x - rx, y - ry), "rsu": m["rsu"],
        "true_speed": num("true_speed_kmh") / 3.6,
        "label": (m["truth"] == "malicious").astype(int),
        "mode": m["mode"], "truth": m["truth"],
        "attack_type": m["attack_type"] if "attack_type" in m else "unknown",
        "event": m["event"] if "event" in m else "",
    })
    return df.reset_index(drop=True)


def pick_heading_rule(df: pd.DataFrame) -> tuple[str, dict]:
    """Which conversion makes honest cars' heading match their movement direction?"""
    h = df[df.label == 0].sort_values(["sender", "t_send"])
    g = h.groupby("sender")
    dx, dy, dt = g.x.diff(), g.y.diff(), g.t_send.diff()
    ok = (dt > 0.5) & (dt < 1.5) & (np.hypot(dx, dy) > 2) & (h.spd > 2)
    bearing = np.degrees(np.arctan2(dx, dy)) % 360
    res = {}
    for name, f in HEADING_RULES.items():
        diff = np.abs((bearing - f(h.heading_veins) + 180) % 360 - 180)
        res[name] = float(np.nanmedian(diff[ok])) if ok.any() else float("nan")
    return min(res, key=lambda k: res[k] if res[k] == res[k] else 1e9), res


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="batch folders, omnet-run folders or results/")
    ap.add_argument("--out", default="dataset")
    ap.add_argument("--radio-range", type=float, default=None, help="metres; default: estimated from honest readings")
    ap.add_argument("--net", default=str(NET), help="SUMO network for road_edge ('' to skip)")
    a = ap.parse_args()

    runs = find_runs(a.paths)
    if not runs:
        sys.exit("No omnet-run folders with messages.csv found.")
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    data = [load_run(r, meta) for r, meta in runs]
    allr = pd.concat(data, ignore_index=True)
    checks = [f"{len(runs)} runs, {len(allr)} accepted readings, {int(allr.label.sum())} false ({allr.label.mean():.1%})"]

    rule, res = pick_heading_rule(allr)
    checks.append("heading conversion (median |movement - heading|, honest cars): "
                  + ", ".join(f"{k}: {v:.1f} deg" for k, v in res.items()) + f"  -> using '{rule}'")
    if not res[rule] < 10:
        checks.append("  WARNING: no conversion matches well (expected ~2-5 deg). Check heading_deg in messages.csv.")

    roads = None
    if a.net and Path(a.net).exists():
        roads = RoadMap(Path(a.net))
        hon = allr.label == 0
        re_h = roads.road_edge(allr.loc[hon, "x_omnet"], allr.loc[hon, "y_omnet"])
        share = float(np.mean(re_h > -1.0))
        checks.append(f"road check: {share:.1%} of honest positions within 1 m of a lane (expected > 95%); "
                      f"median road_edge {np.median(re_h):.2f} m")
        if share < 0.9:
            checks.append("  WARNING: honest cars look off-road - the OMNeT++ -> SUMO conversion may not match.")

    R = a.radio_range or float(allr.loc[allr.label == 0, "rcv_dist"].quantile(0.995))
    checks.append(f"radio range for rcv_ratio: {R:.1f} m ({'given' if a.radio_range else 'estimated from honest readings'})")

    rows, frames = [], []
    for df in data:
        d = df.copy()
        d["hed"] = HEADING_RULES[rule](d.heading_veins)
        d["road_edge"] = roads.road_edge(d.x_omnet, d.y_omnet) if roads else np.nan
        f = add_rcv_ratio(full_pipeline(d), R)
        f.to_parquet(out / f"{df.run.iloc[0]}.parquet", index=False)
        frames.append(f)
        att = f[f.attack_type != "none"]
        rows.append({"run": df.run.iloc[0], "config": df.config.iloc[0], "seed": df.seed.iloc[0],
                     "readings": len(f), "cars": f.sender.nunique(), "attacker_cars": att.sender.nunique(),
                     "false_readings": int(f.label.sum()),
                     "attack_types": "|".join(sorted(set(att.attack_type))),
                     "readings_in_manoeuvres": int((f.event != "").sum())})
    allf = pd.concat(frames, ignore_index=True)
    allf.to_parquet(out / "all_runs.parquet", index=False)
    pd.DataFrame(rows).to_csv(out / "summary.csv", index=False)
    hon = allf[allf.label == 0]
    checks.append(f"honest sanity: median spd_mismatch {hon.spd_mismatch.median():.2f} m/s, "
                  f"median move_hed_diff {hon.move_hed_diff.median():.1f} deg (VeReMi NextGen: 0.27 and 2.7; "
                  f"near 0 means the run had no sensor noise - use the DS-* configs)")
    (out / "checks.txt").write_text("\n".join(checks) + "\n")
    print("\n".join(checks))
    print(f"\nWrote {len(frames)} run tables + all_runs.parquet ({len(allf)} rows, features: {len(FINAL_22_RATIO)}) to {out}/")
    print(pd.DataFrame(rows).to_string(index=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
