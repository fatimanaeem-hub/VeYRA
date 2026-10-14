# Phase 3a: real radio with OMNeT++ / Veins

Phase 3a replaces `fake_omnet.py` and `sumo_driver.py` with the real thing.
SUMO drives the cars, **OMNeT++/Veins simulates the 802.11p radio** between
the cars and three RSUs, and each RSU passes what it receives to its gateway
in `gateway_service.py`, which still runs outside OMNeT++ on the same laptop.

```
 SUMO (Erlangen)        OMNeT++ / Veins  (802.11p: distance, buildings, collisions)       Python
 ┌────────────┐ TraCI  ┌─────────────────────────────────────────────────────┐ TCP   ┌──────────────────┐
 │ cars drive │ ─────► │ node[i] (VeyraVehicleApp) ~~~~~~► rsu[0] (bridge) ──┼─9001─►│ GW-00            │
 │ the route  │        │ node[i] (VeyraVehicleApp) ~~~~~~► rsu[1] (bridge) ──┼─9002─►│ GW-01  Server    │
 └────────────┘        │ node[i] (VeyraVehicleApp) ~~~~~~► rsu[2] (bridge) ──┼─9003─►│ GW-02  BC_ID     │
                       │ eve (VeyraAttackerApp): overhears and attacks rsu[0]│       │        DAG       │
                       └─────────────────────────────────────────────────────┘       └──────────────────┘
```

Nothing in `gateway_service.py` changed. The RSUs speak exactly the
protocol in `PROTOCOL.md`, the same one `fake_omnet.py` and `sumo_driver.py`
use.

## What runs where

| Component | Where | What it does |
|---|---|---|
| Cars | SUMO, Erlangen map | Speed, position, traffic lights, queues |
| Car radio + app | OMNeT++ `VeyraVehicleApp` | Hears RSU beacons, picks an RSU, handshake (Alg. 2) over 802.11p, one reading per second |
| RSU radio + app | OMNeT++ `VeyraRsuApp` | Beacons every second, forwards handshakes and readings to its gateway, sends C3 back over the air, ticks every second |
| Attacker | OMNeT++ `VeyraAttackerApp` ("eve") | Parked next to rsu[0]: overhears, then sends attack frames over the same radio |
| Gateways, server, DAG | `gateway_service.py` | All cryptography, Alg. 1–5, unchanged |

## New files

| File | Purpose |
|---|---|
| `veins_veyra/src/veyra/VeyraMessages.msg` | Over-the-air packets: beacon, handshake request (1,125 B), handshake reply C3 (120 B), reading (150 B) |
| `veins_veyra/src/veyra/VeyraVehicleApp.*` | Vehicle app, including the compromised car |
| `veins_veyra/src/veyra/VeyraRsuApp.*` | RSU app: the bridge to `gateway_service.py` |
| `veins_veyra/src/veyra/VeyraAttackerApp.*` | Roadside attacker: unregistered identity, tamper, replay inside and outside the window |
| `veins_veyra/src/veyra/GatewayLink.*` | TCP client and tiny JSON reader (Windows and Linux) |
| `veins_veyra/simulations/omnetpp.ini` | Scenario settings and configurations |
| `veins_veyra/simulations/VeyraScenario.ned` | The network: `rsu[numRsus]` plus `eve` |
| `veins_veyra/simulations/erlangen.*`, `config.xml`, `antenna.xml` | Copied from the Veins example |
| `veins_veyra/configure`, `Makefile`, `run` | Build and run scripts |
| `analyze_omnet.py` | Reads a run's results: attack checks, radio numbers, blockchain numbers |
| `run_experiments.py` | Runs several configurations × seeds and averages them |

## One-time build (Windows)

You need Veins 5.3.1 **built from the OMNeT++ shell** (release mode). If you
only ever built it inside the IDE, do this once:

```bash
# OMNeT++ shell (C:\fyp\omnetpp-6.1.0\mingwenv.cmd)
cd /c/fyp/veins-5.3.1
./configure
make
```

Then build this project. The `configure` script finds Veins at
`C:\fyp\veins-5.3.1` when this folder sits in `C:\fyp\`, e.g.
`C:\fyp\VEYRA-veins-3a\`:

```bash
cd /c/fyp/VEYRA-veins-3a/veins_veyra
./configure          # or: ./configure --with-veins=/c/fyp/veins-5.3.1
make
```

The last line should be `Creating shared library: ...libveyra.dll`.

## Every run: three windows

**Window 1, OMNeT++ shell: SUMO via veins_launchd** (as in Phase 1)

```bash
cd /c/fyp/veins-5.3.1
bin/veins_launchd -vv -c C:/fyp/sumo-1.22.0/bin/sumo.exe
```

Use `sumo.exe` (no GUI) for measurements; `sumo-gui.exe` also works.

**Window 2, Command Prompt: the gateways**

```cmd
cd C:\fyp\VEYRA-veins-3a
python gateway_service.py --vehicles 20
```

`--vehicles 20` must match `maxVehicles` in `omnetpp.ini` (FT is derived
from the network size).

**Window 3, OMNeT++ shell: the simulation**

```bash
cd /c/fyp/VEYRA-veins-3a/veins_veyra
./run -u Cmdenv        # no GUI: about 40-60 s for 240 simulated seconds
./run                  # Qtenv GUI: watch the cars, RSUs and eve
```

At the end the RSUs stop the gateway service and both windows print where
the results went. Then, in window 2:

```cmd
python analyze_omnet.py
```

Each run needs a fresh gateway service; window 1 can stay open.

## What you should see

Output of `analyze_omnet.py` for one `Default` run on the test machine:

```
  Attack checks
  Attack                                     Expected                       Result
  Unregistered vehicle handshakes            REJECT at Alg.2 line 10        PASS
  Unregistered vehicle sends a reading       REJECT at session lookup       PASS
  Reading with one flipped bit               REJECT at AEAD                 PASS
  Captured reading replayed inside window    ACCEPTED (no duplicate check)  PASS (paper gap)
  Captured reading replayed >120 s later     REJECT at freshness            PASS
  Compromised vehicle reports 250+ km/h      ACCEPTED and finalised         PASS (the gap)
                                             -> 153/153 accepted, 108 finalised

  Radio (802.11p, Veins)
  Readings sent / received        2784 / 2661   (delivery 95.6%)
  Readings not sent               1399 out of coverage, 46 during a handover
  Handshake requests sent / recv  102 / 55   (45 retries)
  Sessions / handovers            55 / 35
  Time to session incl. retries   p50 16.4 ms  p95 3433.0 ms  worst 14012.9 ms
  Air delay per reading           p50 0.26 ms  p95 0.26 ms  max 0.57 ms
  Wait for gateway CPU            p50 0.00 ms  p95 51.73 ms  max 511.09 ms
  Reading end-to-end              p50 0.31 ms  p95 52.04 ms  max 511.41 ms
  Gateway tick work               p50 73.19 ms  p95 332.66 ms  max 628.82 ms

  Blockchain (gateway service)
  Transactions published / final  293 / 207   (pending at end 86, rejected 0)
  Time to finality                p50 40.0 s  p95 84.0 s
  Server opened C_j               293 ok, 0 failed
  Honest readings                 accepted 2508, finalised 1870
  False readings (ground truth)   accepted 154, finalised 108   <- the gap VEYRA targets
```

Your numbers will differ, mostly the timings: your laptop's CPU sets
`proc_ms`, and a slower tick means longer waits.

"PASS (paper gap)" and "PASS (the gap)" mean the base paper behaves as
expected: it does **not** stop these two attacks.

## Configurations (`-c` option)

| Config | What changes | Use it for |
|---|---|---|
| `Default` | 3 RSUs, 20 cars, all five attacks | The main run |
| `NoAttacks` | No compromised car, no eve | Clean baseline |
| `ClassicalSizes` | Handshake packets 64 B instead of 1,125 B | Isolating the radio cost of post-quantum sizes |
| `NoCpuModel` | Gateway processing time not turned into delay | Radio-only latency, for comparison |
| `ClassicalSizesNoCpuModel` | Both of the above | Packet size as the only difference from `NoCpuModel` |
| `AllCars` | Every car SUMO inserts takes part | Load test. **Start the service with `--vehicles 60`** |

`./run -u Cmdenv -c NoAttacks --seed-set=2` picks a configuration and a seed.
A seed changes the radio randomness; the traffic is the same Erlangen flow
every time, so configurations are compared on identical traffic.

### Several runs at once

`run_experiments.py` starts the gateway service, runs OMNeT++, waits, and
repeats for every configuration and seed, then prints the averages. Run it
from the OMNeT++ shell with window 1 open. The OMNeT++ shell has its own
Python without VEYRA's packages, so point `--python` at your normal one
(`where python` in a Command Prompt shows the path):

```bash
cd /c/fyp/VEYRA-veins-3a
python run_experiments.py --configs Default NoAttacks --seeds 3 \
    --python C:/Users/<you>/AppData/Local/Programs/Python/Python312/python.exe
```

Write the path with forward slashes, as above. Each run takes about a
minute; 2 configurations × 3 seeds is about 6 minutes.

## How latency is measured

Every reading that reaches an RSU gets one row in `messages.csv`:

| Column | Meaning | Comes from |
|---|---|---|
| `air_ms` | Vehicle hands it to its radio → RSU has it | Veins: queueing, channel access, airtime, propagation |
| `queue_ms` | Waiting because the gateway is still busy | Gateway modelled as one CPU |
| `proc_ms` | Gateway's Alg. 3 checks | Real CPU time in `gateway_service.py` |
| `vehicle_ms` | Vehicle's sealing (Eq. 3–4) | Real CPU time, measured in the service |
| `end_to_end_ms` | Sum of the four: sensor value → buffered at the gateway | |

The handshake reply (C3) is sent over the air **after** the gateway's real
processing time, so post-quantum CPU cost becomes simulated delay. With
`modelGatewayCpu = true` (the default), a reading that arrives while the
gateway is still working on a tick waits its turn. That waiting time is
`queue_ms`.

## Results on the cloud test machine

3 seeds per configuration, 240 simulated seconds, 20 cars, pure-Python
crypto. Mean (min – max over the seeds):

| | Default | ClassicalSizes | NoCpuModel |
|---|---|---|---|
| Attack checks passed | 6/6 in every run | 6/6 | 6/6 |
| Delivery ratio (readings sent → received) | 95.8% | 95.7% | 96.0% |
| Handshake requests sent | 87 (72–102) | 72 (63–90) | 67 (63–72) |
| Handshake retries | 30 (15–45) | 15 (6–33) | 10 (6–15) |
| Time to session p95 (incl. retries) | 2.2 s (1.3–3.4) | 1.6 s (0.7–3.0) | 1.1 s (0.7–1.3) |
| Air delay per reading, p95 | 0.26 ms | 0.26 ms | 0.26 ms |
| Reading end-to-end, p95 | 100 ms (52–171) | 135 ms (49–216) | 0.42 ms |
| Gateway tick work, p95 | 344 ms | 345 ms | 370 ms |
| Time to finality p50 / p95 | 38 s / 78 s | 35 s / 78 s | 33 s / 73 s |
| False readings finalised | 106 | 110 | 114 |

**Run-to-run variation is large.** One car stuck at the edge of coverage can
add 30–50 handshake retries on its own. Compare configurations over several
seeds (`run_experiments.py`), never over single runs.

## Findings

**F7. The radio is not the bottleneck; the gateway is.** A reading spends
about 0.26 ms on the air. The 95th-percentile end-to-end delay (≈100–135 ms)
is almost entirely waiting for the gateway to finish its once-a-second tick
(publishing, PoPQW, ML-DSA signing). With `NoCpuModel` the same p95 is
0.42 ms. This is F4 seen from the network side.

When the gateway is slower, the queue builds quickly. A test run with the
gateway made artificially slower (`--difficulty 19`: tick p50 0.7 s, p95
2.5 s) pushed reading end-to-end delay to **p50 2.7 s and p95 9.5 s**, with
the radio unchanged. In Phase 2 your laptop's tick p95 was 1.48 s, so expect
seconds rather than milliseconds there. Faster signing (liboqs) is the fix.

**F8. The post-quantum handshake size showed no measurable radio penalty at
this load.** The ML-KEM-768 request is 1,125 bytes (≈1.5 ms of airtime at
6 Mbit/s) against ≈64 bytes (≈0.1 ms) for a classical exchange. To isolate
size, `NoCpuModel` was compared with `ClassicalSizesNoCpuModel`, 6 seeds
each, where size is the only difference:

| | 1,125-byte request | 64-byte request |
|---|---|---|
| First handshake attempt reaches the RSU | 91.5% | 89.5% |
| Handshake retries per run | 6–47 | 2–59 |

Failed handshakes come from cars at the edge of coverage or behind
buildings, not from the packet size. With 20 cars the channel is almost
idle, so the extra airtime costs nothing measurable. It may matter with many
more cars (`AllCars`), which is worth testing in the scaling runs.

**F9. Three RSUs leave gaps.** With buildings blocking the signal, cars had a
usable session for only about two thirds of their trip (≈1,400 of ≈4,200
readings could not be sent because no RSU was in usable range). `minRssi`
trades coverage for retries:

| `minRssi` | Time in coverage | Handshake retries |
|---|---|---|
| −89 dBm (default) | 66% | 15–45 (3 runs) |
| −91 dBm | 70% | 20 (1 run) |
| −93 dBm | 71% | 239 (1 run) |

That makes the number and placement of RSUs a design question, which
Phase 3b's scaling runs can answer.

**F1 and F2 hold on a real radio.** Authenticated-but-false readings are
finalised (≈105–118 per run), and a replay inside the window is accepted.

## Handover rule

A car uses the RSU with the strongest beacon it heard in the last 2.5 s,
but only if that beacon is at least `minRssi` (−89 dBm). It switches when
another RSU is `handoverHysteresis` (3 dB) stronger or the current one is
lost. Readings pause while a new handshake is in flight: the gateway side may
already hold the new key, so a reading sealed in that moment could fail at
the old RSU. `handoverPolicy = "distance"` switches to the nearest RSU
instead. In test runs it produced several times more failed handshakes,
because it tries RSUs that can just be heard but are too weak to work with.

## Outputs

`VEYRA\results\omnet-run-<time>\`:

| File | Contents |
|---|---|
| `messages.csv` | One row per handshake, reading and tick the RSUs handled: timings, reply, the check that fired, true vs reported speed, position. It is a **labelled dataset** for the anomaly detector |
| `vehicles.csv` | One row per car: readings sent, not sent, handshakes, retries, handovers, time to session |
| `handshakes.csv` | One row per handshake request: signal strength, distance, size, answered or not |
| `gateway_summary.json` | The gateway service's own summary at the end of the run |
| `run_info.json` | Which configuration and seed produced the folder |
| `analysis.json` | Written by `analyze_omnet.py` |

The service also writes its usual `results\run-<time>\` (trace and summary),
and OMNeT++ writes `.sca`/`.vec` files to `veins_veyra\simulations\results\`.

## Simplifications (state these in the report)

1. **Crypto runs in Python, packets have real sizes.** As in v1 of the
   protocol, `gateway_service.py` does the vehicle's cryptography on its
   behalf; the frames on the radio are padded to the real post-quantum sizes.
2. **One shared DAG.** All gateways share one ledger. Phase 3b gives each
   gateway its own copy and sends transactions between them over simulated
   links.
3. **The RSU → service hop is a local socket**, not counted as latency. A
   real RSU would have the gateway inside it.
4. **Handshake processing time covers both sides** (vehicle and gateway),
   since the service runs both. It slightly overstates the gateway's share.
5. **One queue per gateway CPU**, first come, first served: handshakes,
   readings and the once-a-second tick wait for each other.
6. **Attack frames carry an evaluation label** (`mode`) that the service uses
   to rebuild the attack's bytes. The gateway never uses it to decide.
7. **Same traffic every run.** Seeds change only the radio randomness.

## Troubleshooting

| Problem | Fix |
|---|---|
| `rsu[0] cannot reach the gateway service at 127.0.0.1:9001` | Start `python gateway_service.py --vehicles 20` first (a fresh one for every run) |
| `Connection refused` / TraCI error at start | veins_launchd is not running (window 1) |
| `cannot find -lveins` while building | Build Veins from the OMNeT++ shell first (`cd /c/fyp/veins-5.3.1 && ./configure && make`) |
| `./configure: Permission denied` | Run `python configure` instead; for the run script, `bash run -u Cmdenv` |
| Port 9001 already in use | A gateway service from an earlier run is still open: close that window |
| `Cannot load library ... The specified module could not be found` | Veins is not built in release mode, or `./configure` pointed at another Veins: rebuild Veins from the OMNeT++ shell, then `./configure` and `make` here again |
| `no reply from the gateway service for 60 s` | The gateway service window is paused (its title shows "Select" after a click). Press Esc in it. `--quiet` keeps that window calm |
| Qtenv is slow | Press the **Express** run button (fast-forward), or use `-u Cmdenv` |

Tested with OMNeT++ 6.1, Veins 5.3.1 and SUMO 1.22.0 on Linux. The socket
code was also compiled for Windows with MinGW but has not yet been run on
Windows.
