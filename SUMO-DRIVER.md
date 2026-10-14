# SUMO driver (Phase 2.5, with `--follow` added in 2.6)

`sumo_driver.py` drives the gateway service with **real SUMO traffic** instead
of the made-up straight road in `fake_omnet.py`. It sends exactly the same
messages (see `PROTOCOL.md`), so the gateway service is unchanged.

```
SUMO (Erlangen map) ──TraCI──► sumo_driver.py ──socket──► gateway_service.py
 cars drive the route          acts as 3 RSUs              gateways, server, DAG
```

| | `fake_omnet.py` | `sumo_driver.py` | Phase 3 (OMNeT++) |
|---|---|---|---|
| Cars | Made-up, straight 3 km loop | **SUMO, real Erlangen route** | SUMO |
| Speed | Random drift | **Real acceleration, braking, queues** | SUMO |
| Cars enter / leave | No, always 12 | **Yes** | Yes |
| Which RSU serves a car | Nearest | Nearest (no range limit) | Radio signal |
| Radio delay / loss | None | None | 802.11p |

## Run it

Nothing else may be connected to SUMO, so **do not run `veins_launchd`** for this.

Two Command Prompt windows in this folder:

```cmd
:: window 1
python gateway_service.py --vehicles 20

:: window 2
python sumo_driver.py --sumocfg C:\fyp\veins-5.3.1\examples\veins\erlangen.sumo.cfg
```

Add `--gui` to window 2 to watch it in sumo-gui: tracked cars are blue, the
compromised car turns red, and the RSUs are red markers on the route.

### Watch the attack: `--follow`

```cmd
python sumo_driver.py --sumocfg C:\fyp\veins-5.3.1\examples\veins\erlangen.sumo.cfg --follow
```

sumo-gui opens zoomed in at street level and **follows the compromised car**
(`flow0.3` by default). Before that car enters the map it follows the first
tracked car, and when it leaves it switches to another one. The window
prints `[follow] sumo-gui now following ...` each time it switches.

| On screen | Meaning |
|---|---|
| Blue cars with names (`flow0.2`, …) | Tracked cars sending honest readings |
| **Red car inside a red circle** | The compromised car, circled the moment it starts reporting 250+ km/h |
| Yellow cars | Other SUMO cars the driver does not track |
| Red markers `rsu[0]` … `rsu[2]` | The roadside units |
| Red / blue shapes | Buildings and areas from the Erlangen map |

Cars and RSU markers are drawn 6× larger than life so they are visible
(`--car-size` changes it). `--follow` runs with a 100 ms delay per step so
the movement is watchable; drag the Delay slider in sumo-gui to change it
live. **For measurement runs use plain mode (no `--gui`/`--follow`) or
`--delay 0`**, since the delay stretches wall-clock time.

The first second or two may show the whole map before the view zooms in.

`SUMO_HOME` must point to your SUMO folder (`C:\fyp\sumo-1.22.0`); the driver
uses the TraCI library that ships with it.

## Useful options

| Option | Default | Meaning |
|---|---|---|
| `--sumocfg` | Veins Erlangen example | Any SUMO scenario |
| `--gui` | off | Use sumo-gui |
| `--follow` | off | sumo-gui zooms in and follows the compromised car (implies `--gui`) |
| `--zoom` | 1000 | Zoom used by `--follow`, about 500 m across; higher is closer |
| `--delay` | 100 with GUI, else 0 | sumo-gui delay per step in ms |
| `--car-size` | 6 | How much larger cars and RSU markers are drawn |
| `--max-vehicles` | 20 | Track the first N cars SUMO inserts. **Match the service's `--vehicles`**, since FT is derived from network size |
| `--duration` | 240 | Simulated seconds after the first car departs. Needs ≥ 150 for the old-replay test |
| `--compromised` | 3 | Which tracked car turns malicious (0 = first car) |
| `--fake-speed` | 250 | Speed in km/h the compromised car reports |
| `--attack-start` | 20 | Seconds after its departure that the car starts lying |
| `--rsu` | along the route | Fix RSU positions: `"x,y;x,y;x,y"` |
| `--no-attacks` | off | Honest traffic only, for a clean baseline |

## The Erlangen scenario

The Veins example sends **195 cars along one route**, one every 3 seconds, with
a 14 m/s (about 50 km/h) limit. The driver spreads the three RSUs evenly along
that route, so every car passes all three and hands over twice.

## Outputs

| File | From | Contents |
|---|---|---|
| `results\run-<time>\summary.json`, `trace.csv` | gateway service | As before |
| `results\sumo-run-<time>\readings.csv` | **this driver** | One row per reading: true vs reported speed, position, acceleration, heading, road, CO₂, RSU, ground-truth label, accepted/rejected |

`readings.csv` is a **labelled dataset** for the anomaly-detection work:
honest rows show real driving, and the compromised car's rows show the
reported speed next to its true speed.

## Attack checks

Same six as `fake_omnet.py`, adapted to moving traffic:

| Time (after first departure) | Attack | Expected |
|---|---|---|
| 5 s | Unregistered car handshakes with RSU 0 | Rejected |
| 6 s | Same car sends a reading | Rejected |
| 10 s | A tracked car's reading with one flipped bit | Rejected |
| 12 s | That car's latest packet re-sent | Accepted (paper gap) |
| from 20 s after it departs | Compromised car reports 250+ km/h | Accepted and finalised (the gap) |
| 150 s | A packet captured at an RSU more than 130 s earlier, re-sent there | Rejected |

## Result on the cloud test machine (240 s, 20 cars)

- All 6 checks behaved as the base paper predicts.
- 355 transactions, 280 finalised, 0 rejected; the server opened 355/355 aggregates.
- 4,231 readings accepted. The compromised car had **212 false readings accepted and 165 finalised**.
- Time to finality **p50 30 s, p95 71 s**, slower than with `fake_omnet.py` (18 s).
  With real traffic, cars bunch along the route and some RSUs have nothing to
  publish for a while. Fewer new transactions means slower approval of old
  ones: **in a DAG, finality depends on traffic volume**.
