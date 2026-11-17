# Iteration 2 — Attack generator and dataset exporter

Phase 3 had one attacker that sent a fake speed. Iteration 2 adds the data attacks a
**registered car with valid keys** can make. The car changes its values *before* the reading is
sealed and signed, so the gateway's post-quantum checks accept it. Only the anomaly detector
can catch these attacks. The attacks and their sizes follow VeReMi NextGen, so the detector
trained on VeReMi sees the same kinds of lies here.

## What changed

| File | Change |
|---|---|
| `veins_veyra/src/veyra/VeyraMessages.msg` | `VeyraReading` gains `attackType` (the sender's configured attack, `"none"` for honest cars) and `honestEvent` (`"hard_brake"` / `"stall"` while an honest car makes an unusual manoeuvre) |
| `veins_veyra/src/veyra/VeyraVehicleApp.ned/.h/.cc` | Attack parameters, attacker selection by fraction, the 10 attacks, honest manoeuvres through TraCI |
| `veins_veyra/src/veyra/VeyraRsuApp.cc` | `messages.csv` gains `attack_type,event`; `vehicles.csv` gains `attack_type,honest_event` |
| `veins_veyra/simulations/omnetpp.ini` | New `[Config Dataset]` and 10 `DS-*` configs (bottom of the file) |
| `run_experiments.py` | `DS-*` configs run 40 cars by default |
| `export_dataset.py` (new) | `messages.csv` → feature tables for the detector |
| `detector/` (new) | `candidates.py`, `features.py` — the same feature code used on VeReMi (v6) |
| `tools/mock_run.py` (new) | Writes a fake run in the real `messages.csv` format, to test the exporter |

The Phase 3 configs behave as before: with `attackType = "fakeSpeed"` and
`attackerFraction = 0` no new random numbers are drawn, so runs with the same seed are identical.

## Sensor noise

Real sensors are not perfect. Without noise, an honest car's speed matches its movement
exactly, so even a tiny lie is trivially easy to spot and the results would be too good to be
true. The `DS-*` configs add Gaussian noise to **every** reading (honest and attacker; attacks
are built on top of the noisy values):

| Parameter | DS-* value | Phase 3 |
|---|---|---|
| `posNoiseStd` | 0.3 m per axis | 0 |
| `speedNoiseStd` | 0.2 m/s | 0 |
| `headingNoiseStd` | 3.5° | 0 |
| `accelNoiseStd` | 0.35 m/s² | 0 |

These values were tuned so that honest cars look like the honest cars in VeReMi NextGen:

| Feature (honest cars, median) | VeReMi NextGen | Tuned VEYRA |
|---|---|---|
| `spd_mismatch` (m/s) | 0.27 | 0.30 |
| `move_hed_diff` (°) | 2.7 | 2.9 |
| `acl_mismatch` (m/s²) | 0.33 | 0.24–0.31 |

The model trained on VeReMi therefore sees familiar honest data.

## The attacks

`attackType` (per car; set by config). `attackerFraction` sets the share of attackers (20% in
the `DS-*` configs, as in VeReMi NextGen).

- **`DS-*` configs** (`attackerSpread = true`): **exactly** 20% of the cars attack (every 5th
  car; the starting car changes with the seed). With 40 cars that is 8 attackers per run.
- **`DS-Mixed`**: those 8 attackers take 8 different attacks, rotating with the seed.
- **`attackerSpread = false`**: each car becomes an attacker with that probability. A first
  test run with this setting got only 3 attackers out of 40.

| attackType | What the attacker reports | Parameters (default) | False readings |
|---|---|---|---|
| `fakeSpeed` | Phase 3: `fakeSpeedKmh` + 0–20 km/h | `fakeSpeedKmh` | all |
| `constSpeedOffset` | true speed + one fixed offset, chosen per car | `speedOffsetMin/Max` 1–7 m/s, random sign | all |
| `randomSpeedOffset` | true speed + a new offset every reading | same | all |
| `constPosOffset` | true position + one fixed shift, chosen per car | `posOffsetMin/Max` 35–90 m, random direction | all |
| `randomPosOffset` | true position + a new shift every reading | same | all |
| `suddenStop` | after a random delay: speed 0 at the position where it "stopped", while it keeps driving | `stopDelayMax` 40 s | after the stop |
| `zeroSpeed` | speed 0, true position | — | all |
| `feignedBraking` | a fake hard deceleration in some readings | `feignedBrakingProb` 0.4, `feignedBrakingMin/Max` 1–10 m/s² | ~40% |
| `dataReplay` | the latest reading of another car it overheard (position, speed, accel, heading), signed with its own key | `replayVictimTimeout` 5 s (then picks a new victim) | when it has a victim |
| `dos` | true values, but `dosFactor` (6) readings per second | `dosFactor` | all (labelled for the flood, the values are true) |

**Honest manoeuvres** (to test false alarms): an honest car makes one, with probability
`honestEventProb` (25% in `DS-*`, 30% in `DS-Honest`). It happens at a random time between
`eventWindowStart` and `eventWindowEnd` (10–80 s in `DS-*`; a car spends only about 2 minutes on
the route, so later manoeuvres would never happen). It makes a `hard_brake` (SUMO slows it to 20% of its speed for `hardBrakeHold`
3 s) or a `stall` (stops for `stallDuration` 15 s). The car reports the truth, so these
readings are labelled honest. They are tagged in the `event` column, and the tag stays for
5 s after the manoeuvre ends.

## Configs

All extend `Dataset`, which extends `Replicated`. They use 40 cars, 8 attackers, attacks from
the start, sensor noise, and 25% of honest cars making a manoeuvre.

`DS-Honest` (no attackers, 30% manoeuvres), `DS-ConstSpeedOffset`, `DS-RandomSpeedOffset`,
`DS-ConstPosOffset`, `DS-RandomPosOffset`, `DS-SuddenStop`, `DS-ZeroSpeed`,
`DS-FeignedBraking`, `DS-DataReplay`, `DS-DoS`, and **`DS-Mixed`**: each attacker picks one of
the 9 data attacks at random (`attackType = "mixed"`), so several attacks happen in the same run.

**Plan: two kinds of runs, several seeds each.** Each seed gives different attackers, offsets
and traffic timing.

- **Single-attack runs** (`DS-Honest` + the 9 `DS-<attack>` configs): clean per-attack results.
- **`DS-Mixed` runs**: the realistic case, where the detector meets several attacks together.

Split by run (seed), never by reading. Train/validate on some seeds and test on others, so
the test cars were never seen in training. A suggested split:

| Use | Seeds |
|---|---|
| Train | 1–6 |
| Validation (threshold at 1% false alarms) | 7–8 |
| Test | 9–10 |

## How to run

```bash
cd veins_veyra && make            # rebuild: the .msg and C++ changed
cd ..
python run_experiments.py --seeds 10 --configs DS-Honest DS-ConstSpeedOffset DS-RandomSpeedOffset \
    DS-ConstPosOffset DS-RandomPosOffset DS-SuddenStop DS-ZeroSpeed DS-FeignedBraking DS-DataReplay DS-DoS DS-Mixed
# quick first check: --seeds 1 --configs DS-Mixed
pip install pandas numpy scipy pyarrow
python export_dataset.py results/batch-<time>          # the folder run_experiments.py printed
```

The exporter writes `dataset/`:

- `<run>.parquet`, one per run: one row per reading the gateway **accepted**.
- `all_runs.parquet`: all runs together.
- `summary.csv`: per run, the config, seed, readings, attacker cars, false readings and readings in manoeuvres.
- `checks.txt`: the checks below.

## Labels

| Column | Meaning |
|---|---|
| `label` | 1 if this reading carried false data (`truth == "malicious"`), else 0. **Train on this.** |
| `attack_type` | the sender's attack (`none` for honest cars); use it for per-attack recall |
| `event` | `hard_brake` / `stall` during an honest manoeuvre; use it to measure false alarms on unusual but honest driving |
| `mode`, `truth`, `true_speed`, `config`, `seed`, `run` | for analysis only — never as features |

An attacker's car can also send true readings (`label` 0). This happens for `feignedBraking`
in about 60% of readings, for `suddenStop` before it "stops", and for `dataReplay` before it
has a victim. This matches VeReMi, which labels per message.

## The checks — read `checks.txt` after the first real run

1. **Heading conversion.** The exporter tests four ways to turn the Veins heading into a
   compass heading on honest cars, then keeps the one that matches their movement. Expect
   2–5°. A warning means `heading_deg` is not what we think.
2. **Road check.** The exporter puts honest positions on the SUMO network (Veins' 25 m
   margin, y flipped). More than 95% should lie within 1 m of a lane. If they don't,
   `road_edge` is wrong; the conversion was checked with the RSUs, which sit 0.2–0.5 m from
   the route.
3. **Radio range for `rcv_ratio`.** It is estimated from honest readings unless you give
   `--radio-range`. Use the same value every time you build a training set.
4. **Honest sanity.** The median `spd_mismatch` should be about 0.3 m/s and `move_hed_diff` about
   3°. If they are near 0, the noise is off. If they are much larger, the units are off.

## First real run (DS-Mixed, seed 1, before the noise and attacker fixes)

- **Heading:** `90 - h` matched exactly (0.0°), so the heading conversion is confirmed.
- **Road:** 100% of honest positions were on a lane.
- **Run time:** 110 s.
- **What it showed:**
  - Speed mismatch was 0.03 m/s and heading error 0.0°, i.e. no noise. This led to the sensor noise above.
  - It had only 3 attackers and 2 attack types. This led to `attackerSpread`.
  - Only 5 readings fell in manoeuvres. This led to the 10–80 s window and the 25% share.

## Tested here

C++ could not be compiled here, so `make` is the first real test. The exporter was tested on
a mock run (`tools/mock_run.py`: 20 cars on route0, with constSpeedOffset, constPosOffset,
dataReplay and a stall):

- **Heading:** detected `90 - h` (0.0° off; the other rules were 88–119° off).
- **Road:** 99.5% of honest positions are on a lane.
- **Features:** all 22 present.
- **Per attack:**
  - Speed offsets raise `spd_mismatch` (1.67 vs 0.14 m/s).
  - Position offsets push `road_edge` to −28 m.
  - Replays set `copies_other` = 1 (honest false-positive rate 0.03%).

## Known limitation

`erlangen.rou.xml` has **one route** (route0, a car every 3 s). Every car drives the same
roads, so the dataset is homogeneous. More routes would make the detector's tests harder and
fairer, e.g. `randomTrips.py -n erlangen.net.xml -r extra.rou.xml --period 3` added to the
`.sumocfg`.
