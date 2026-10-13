# Gateway service: what changed and why

Phase 2 of the OMNeT++/Veins integration: the gateways and the server now run
as a separate program that OMNeT++ talks to over local sockets. The dashboard,
`verify.py` and `testcase.py` behave exactly as before.

## Run it

Two Command Prompt windows, both in this folder:

```cmd
:: window 1 - the gateways and server
python gateway_service.py

:: window 2 - stands in for OMNeT++ until the Veins side exists
python fake_omnet.py
```

`fake_omnet.py` prints a PASS/FAIL table and stops the service when done.
Results land in `results\run-<timestamp>\` (`trace.csv`, `summary.json`).
A full 180-second run takes about a minute on a laptop; `--duration 60` is
quicker but skips the old-replay check.

## New files

| File | Purpose |
|---|---|
| `gateway_service.py` | Server + gateways + DAG behind TCP ports 9001–9003, driven by simulation time |
| `fake_omnet.py` | Stands in for the OMNeT++ RSUs: moving vehicles, handover, scripted attacks, PASS/FAIL table |
| `PROTOCOL.md` | The exact message format between the RSUs and the service |
| `pqdag/clock.py` | One swappable clock: wall clock by default, simulation time in the service |

## Changes to existing files

| File | Change | Why |
|---|---|---|
| `pqdag/ledger.py` | `time.time()` → `clock.now()` | Timestamps and finality on the simulation clock |
| `pqdag/ledger.py` | Pending-transaction index; the finaliser scans only unfinalised txs | Fixes "finalisation gets slower as the ledger grows". Same rule, same results |
| `pqdag/network.py` | `time.time()` → `clock.now()` | Freshness check (Alg. 3 line 6) on the simulation clock |
| `pqdag/network.py` | `SensorNode.seal()` split out of `send()`; optional position (x, y) in the payload | Lets the service build the exact packet the radio carried, and replay or tamper with it |
| `pqdag/network.py` | `Gateway.aggregate(mode="list")` | Option B: D_j is the list of verified readings (who, what, where, when) instead of an average, so a false reading stays traceable |
| `pqdag/network.py` | `Gateway.establish_server_key()`, `Server.accept_gateway_key()` | Sk_j is now negotiated with ML-KEM instead of handed out |
| `pqdag/network.py` | `Server.open_aggregate()` | The server decrypts C_j. Closes "nobody opens the sealed payload" |
| `pqdag/network.py` | Handshake result reports `c2_bytes`, `c3_bytes` | Packet sizes for the radio |

The default code paths are unchanged: `aggregate()` still averages unless
asked for `"list"`, and `publish()` falls back to the old Sk_j behaviour if
`establish_server_key()` was never called.

## Test status

| Suite | Result |
|---|---|
| `verify.py` | 9/9 |
| `testcase.py` | PASS |
| `fake_omnet.py` (180 sim s, 12 vehicles, 3 RSUs) | 6/6 checks; 540 txs, 0 rejected; 540/540 aggregates opened by the server |

## Findings worth reporting

1. **Replay inside the freshness window is accepted.** Alg. 3 checks only that
   the timestamp is within 120 s; it keeps no record of packets already seen.
   A captured reading re-sent within the window is buffered twice. This is base
   paper behaviour, kept on purpose; a seen-packet cache would close it.
2. **Authenticated-but-false data reaches finality.** A registered vehicle
   reporting 250+ km/h passes every check, and its readings are finalised under
   a 3-of-3 post-quantum certificate. This is the gap the anomaly detector
   addresses.
