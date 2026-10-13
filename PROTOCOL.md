# VEYRA RSU ⇄ Gateway protocol (v1)

How an RSU inside OMNeT++/Veins talks to the gateway service outside it.
`fake_omnet.py` speaks exactly this protocol, so anything that works with it
will work with the real `VeyraRsuApp`.

```
 OMNeT++ / Veins                                  gateway_service.py (Python)
 ┌──────────┐  802.11p   ┌──────────┐   TCP, localhost   ┌───────────────────────┐
 │ vehicle  │ ~~~~~~~~~► │  rsu[j]  │ ─────────────────► │ Gateway j · Server ·  │
 │ node[i]  │ ◄~~~~~~~~~ │ (bridge) │ ◄───────────────── │ BC_ID · BC_Data (DAG) │
 └──────────┘            └──────────┘   one JSON line    └───────────────────────┘
```

## Transport

| Item | Value |
|---|---|
| Connection | TCP, one connection per RSU |
| Ports | `9001` → GW-00, `9002` → GW-01, `9003` → GW-02 (set with `--ports`) |
| Framing | One JSON object per line, UTF-8, ending in `\n` |
| Pattern | Request → reply. Send one request, wait for its reply, then send the next |
| `id` | Optional on requests; echoed on the reply so the RSU can match them |
| `sim_time` | **Required on every request**: OMNeT++ `simTime()` in seconds |

## Time

- The service keeps one clock: the **largest `sim_time` it has seen**. It never runs backwards.
- That clock is used for the freshness check (Alg. 3 line 6), transaction timestamps and time to finality.
- CPU cost of the cryptography is measured on the real clock and returned as **`proc_ms`**.
- **The RSU should send its over-the-air reply `proc_ms` milliseconds later in simulation time** (`scheduleAt(simTime() + proc_ms/1000, ...)`). That puts the real cost of post-quantum processing into the simulated latency.
- `reg_ms` (registration) is *not* added: the paper registers sensors over a separate secure channel, not over the air.

## Messages

### `HELLO` (once, when the RSU connects)
```json
{"type":"HELLO","rsu":"rsu[0]","sim_time":0.0,"protocol_version":1}
```
Reply `HELLO_OK`: the gateway this port maps to and the run configuration
(`FT`, `ft_band`, `difficulty_bits`, `threshold_t`, `crypto_backend`, …).

### `HANDSHAKE`: vehicle reached this RSU (Alg. 1 on first contact, then Alg. 2)
Send it when a vehicle first comes into range and **again on every handover**
to a different RSU.
```json
{"type":"HANDSHAKE","vehicle":"flow0.12","sim_time":12.4,"mode":"normal"}
```
| Reply | Meaning | RSU should |
|---|---|---|
| `HANDSHAKE_OK` | Registered (if new) and session key Sk_ij agreed | Send C3 back over the air after `proc_ms`, sized `bytes_down` |
| `REJECT` (`stage: "Alg.2 line 10"`) | Identity not on BC_ID | Send nothing; the vehicle has no session |

Fields on `HANDSHAKE_OK`: `pd`, `gateway`, `handover`, `proc_ms`, `reg_ms`,
`bytes_up` (C1‖C2), `bytes_down` (C3), `session` (key digest, for logs only).

### `READING`: one sensor reading arrived over the air (Eq. 3–4, Alg. 3)
```json
{"type":"READING","vehicle":"flow0.12","sim_time":13.0,
 "speed":47.3,"x":1520.4,"y":880.1,"mode":"normal","truth":"honest"}
```
| Reply | Meaning |
|---|---|
| `ACK` | Passed all four gateway checks; now in the buffer (pipeline step B7) |
| `REJECT` | Refused; `stage` says which check caught it |

`stage` values: `Alg.3 session lookup`, `Alg.3 line 6 (freshness)`,
`Alg.3 line 7 (AEAD)`, `Alg.3 line 8 (hash)`.

`ACK` carries `risk_score: null`. The field is **reserved for the anomaly
detector**, so adding it later does not change the protocol.

### `TICK`: once per simulated second, per RSU (Eq. 6–7, Alg. 4, Alg. 5)
```json
{"type":"TICK","sim_time":14.0}
```
The gateway publishes everything buffered since its last tick as one DAG
transaction (evidence list, sealed for the server), then the ledger finalises
whatever has reached FT.

Reply `TICK_OK`: `published` (`tx_id`, `readings`, `c_j_bytes`, `parents`,
`popqw_ms`, `server_opened`) or `null`; `finalised` (list of `tx_id`,
`latency_s`, `cert_bytes`, `malicious_readings`); `pending`; `total`; `proc_ms`.

### `STATS`, `BYE`, `SHUTDOWN`
- `STATS` returns the full run summary (the same content as `summary.json`).
- `BYE` acknowledges; the RSU can then close its connection.
- `SHUTDOWN` stops the service, which writes `summary.json` and exits.

## Packet sizes to use inside OMNeT++ (v1)

In v1 the cryptography runs in Python, so OMNeT++ sends packets **padded to the
real post-quantum sizes**. Exact values come back in each reply (`bytes_up`,
`bytes_down`); these defaults are close enough to size packets before sending:

| Air packet | Contents | Bytes |
|---|---|---|
| `HandshakeReq` (vehicle → RSU) | C1 (ML-KEM-768 ciphertext, 1088) ‖ C2 (12 + len(PD) + 16) | **≈ 1125** |
| `HandshakeResp` (RSU → vehicle) | C3 = AES-GCM(R_j ‖ H_j ‖ Nn) | **120** |
| `ReadingMsg` (vehicle → RSU) | C_ij ‖ tso ‖ PD_ij, with position | **≈ 150** |

For comparison, a classical (X25519) handshake would be about 32 bytes each way.

## `mode` and `truth`

`mode` tells the service how the vehicle behaves. `truth` is **ground truth for
evaluation only**: the gateway never uses it to decide anything. It exists so
results can count how many malicious readings the baseline let through to
finality.

| `mode` | Used on | What the vehicle does | Base paper outcome |
|---|---|---|---|
| `normal` | both | Honest | Accepted |
| `unregistered` | HANDSHAKE | Identity never registered | REJECT at Alg. 2 line 10 |
| `tamper` | READING | One bit flipped in transit | REJECT at AEAD |
| `replay_fresh` | READING | Re-sends its latest captured packet | **ACCEPTED**: paper gap, no duplicate check inside the window |
| `replay_old` | READING | Re-sends its oldest captured packet | REJECT at freshness, if older than the window |
| `compromised` | READING | Registered, valid keys, false values | **ACCEPTED and finalised**: the gap VEYRA targets |

A reading from a vehicle with no session is refused at the session lookup,
whatever its `mode`.

## Results

Each run of the service writes to `results/run-<timestamp>/`:

| File | Contents |
|---|---|
| `trace.csv` | One row per event: handshake, reading, publish, finalise, with `proc_ms`, bytes, outcome, the check that fired, `truth` |
| `summary.json` | Totals, p50/p95/p99 processing times, bytes, time to finality (sim s), server-opened count, honest vs malicious readings accepted / published / finalised |

## Mapping to the paper

| Message | Paper |
|---|---|
| HANDSHAKE (first contact) | Alg. 1: registration, with our proof-of-possession |
| HANDSHAKE | Alg. 2: C1‖C2 up, C3 down, Sk_ij = R_j ‖ R_ij |
| READING | Eq. 3–4 (vehicle side), Alg. 3 (gateway checks) |
| TICK | Eq. 6 (aggregate, evidence list), Eq. 7 (seal for server), Alg. 4 (tx, Merkle, PoPQW, parent checks), Alg. 5 (references, tPQ-Sig) |

## v1 simplifications (state these)

1. Vehicle-side cryptography (Alg. 2 lines 5–7 and 17–21, Eq. 3–4) runs in the service on the vehicle's behalf. Packets on the air have the real sizes. v2 moves it into the C++ vehicle app.
2. All gateways share one ledger object in one process. Gossip between separate ledgers comes with the three-laptop setup.
3. The RSU → service hop is a local socket. It does not exist in a real RSU, so it is not counted as radio latency.
