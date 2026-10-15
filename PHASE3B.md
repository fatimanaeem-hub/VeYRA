# Phase 3b: one ledger per gateway, over a simulated backhaul

Phase 3a put the radio into OMNeT++/Veins but kept one shared DAG: a
transaction was visible to every gateway the instant it was created, and the
three signatures of a finality certificate were made in one place. Phase 3b
removes that shortcut. **Each gateway keeps its own copy of BC_Data**, and
the gateways keep their copies in step over **wired backhaul links simulated
in OMNeT++**, with a delay, a data rate and a packet loss rate you choose.

```
                    OMNeT++ / Veins                                         Python (gateway_service.py)
  cars ~~802.11p~~► rsu[0] ──TCP 9001──────────────────────────────────────► GW-00 + its own DAG replica
                     │  ╲ backhaul (DatarateChannel: delay, Mbit/s, loss)
                     │   ╲
  cars ~~802.11p~~► rsu[1] ──TCP 9002──────────────────────────────────────► GW-01 + its own DAG replica
                     │   ╱
                     │  ╱
  cars ~~802.11p~~► rsu[2] ──TCP 9003──────────────────────────────────────► GW-02 + its own DAG replica
                     ╲ │ ╱
                     server  (receives every transaction and certificate)
```

The Phase 3a configurations (`Default`, `NoAttacks`, ...) are unchanged and
still use one shared ledger, so they are the control for everything here.

## What happens to a transaction

1. **Publish.** At its tick, GW-j aggregates and seals its readings and
   creates a transaction against **its own replica** (Alg. 4: parents chosen
   from what *it* has seen). Ids are now `TX-<gateway>-<n>`, unique across
   replicas.
2. **Gossip.** rsu[j] sends the transaction (about 1.1 KB at 20 cars, most of it C_j) over the
   backhaul to every other RSU and to the server, as soon as the gateway has
   produced it.
3. **Re-check.** Each receiving gateway checks the transaction itself (header
   hash, Merkle root, PoPQW) before adding it to its replica. If a parent has
   not arrived yet, the transaction waits in an **orphan buffer** until it
   does. This work queues behind the receiving gateway's CPU like any other.
4. **Approvals are counted per replica.** When a transaction reaches FT
   approvals **in GW-k's own replica**, GW-k signs one share of the
   certificate at its next tick (one ML-DSA-44 signature, 2,420 bytes) and
   sends it to the transaction's origin. The origin keeps its own share.
5. **Finality.** With t = 3 valid shares the origin finalises the transaction
   and sends the certificate (`FINAL`, 7,316 bytes) to every other gateway
   and the server. Each verifies the three signatures and marks the
   transaction final in its replica.

The backhaul is **reliable but not ordered**, like TCP connections between
sites would be: every packet is acknowledged and resent after a timeout
(doubling each time) until it gets through. A lost packet therefore costs
delay and bytes, not correctness.

## New and changed files

| File | What |
|---|---|
| `pqdag/replica.py` | **New.** `ReplicaLedger`: one gateway's replica, gossip receive with orphan buffer, per-replica approval counting, share signing and certificate application; wire sizes |
| `gateway_service.py` | Protocol v2. Ledger mode chosen by the RSUs' `HELLO`; `GOSSIP`, `SIG_SHARE`, `FINAL` handlers; `outbox` in replies; replication metrics; finality split into "waiting for approvals" and "certificate"; `--seed`; **registry export** (`bc_id.json`, `bc_id.csv`, `registry` in the summary) |
| `pqdag/ledger.py` | Records when each transaction first reaches FT (for the finality split). Behaviour unchanged |
| `veins_veyra/src/veyra/VeyraBackhaulPort.*` | **New.** Wired port of an RSU or the server: per-link queue, ACK + retransmission, `backhaul.csv` |
| `veins_veyra/src/veyra/VeyraServerApp.*` | **New.** The server node on the backhaul |
| `veins_veyra/src/veyra/VeyraBackhaulPort.ned` | **New.** `VeyraBackhaulPort`, `VeyraRSU` (Veins RSU + port), `VeyraServer` |
| `veins_veyra/simulations/VeyraScenario3b.ned` | **New.** The Phase 3a scenario plus a full mesh of backhaul links between RSUs and to the server |
| `veins_veyra/src/veyra/VeyraRsuApp.*` | `ledger` parameter; sends the reply's outbox over the backhaul when the gateway has produced each message; hands arriving backhaul packets to its gateway; `tickStagger` |
| `veins_veyra/src/veyra/VeyraMessages.msg` | `VeyraBackhaulPkt` |
| `veins_veyra/src/veyra/GatewayLink.*` | `jsonObjects()` to read the outbox |
| `veins_veyra/simulations/omnetpp.ini` | The `Replicated*` configurations below |
| `analyze_omnet.py` | New "Backhaul and replicas" section; gateway CPU busy %; finality split; "Registered identities" lines |
| `run_experiments.py` | Knows how many RSUs each configuration has; Phase 3b metrics in the summary; passes `--seed` |
| `PROTOCOL.md` | v2 messages |

## Build (once)

New C++ files were added, so **run `./configure` again** before `make`:

```bash
# OMNeT++ shell
cd /c/fyp/VEYRA-veins-3b/veins_veyra
./configure          # or: ./configure --with-veins=/c/fyp/veins-5.3.1
make
```

## Run

Same three windows as Phase 3a (`PHASE3A.md`). Only the configuration name
changes, and for 6 or 10 RSUs the gateway service needs that many ports:

```bash
# window 2 (Command Prompt), a fresh one every run
python gateway_service.py --vehicles 20
#   for Replicated6:  python gateway_service.py --vehicles 20 --ports 9001,9002,9003,9004,9005,9006
#   for Replicated10: python gateway_service.py --vehicles 20 --ports 9001,9002,9003,9004,9005,9006,9007,9008,9009,9010

# window 3 (OMNeT++ shell)
cd /c/fyp/VEYRA-veins-3b/veins_veyra
./run -u Cmdenv -c Replicated
```

Then `python analyze_omnet.py` as before. Batches (from the OMNeT++ shell,
window 1 open; `--python` as in Phase 3a):

```bash
cd /c/fyp/VEYRA-veins-3b
python run_experiments.py --configs Default Replicated Replicated4G ReplicatedLossy --seeds 5 --python C:/.../python.exe
python run_experiments.py --configs Replicated6 Replicated10 --seeds 3 --python C:/.../python.exe
```

`run_experiments.py` starts the service with the right number of ports
itself. Replicated10 is slow on pure-Python crypto (about 12 minutes per run
on the test machine; see F12).

## Configurations

| Config | Ledger | Backhaul (each link) | RSUs | Use it for |
|---|---|---|---|---|
| `Default` | shared | – | 3 | Phase 3a control |
| `Replicated` | one per gateway | fibre: 2 ms, 1 Gbit/s, no loss | 3 | The main Phase 3b run |
| `Replicated4G` | one per gateway | 4G-like: 35 ms, 20 Mbit/s, no loss | 3 | Slower links |
| `ReplicatedLossy` | one per gateway | 35 ms, 20 Mbit/s, **5% packet loss** | 3 | Loss and retransmission |
| `ReplicatedNoCpuModel` | one per gateway | fibre | 3 | Backhaul delay without gateway CPU queueing |
| `ReplicatedStaggered` / `DefaultStaggered` | one per gateway / shared | fibre | 3 | RSUs tick one after another instead of all at once (see F10) |
| `Replicated6`, `Replicated10` | one per gateway | fibre | 6, 10 | Scaling. **FT becomes 10** (26 / 30 nodes, Table III) |
| `ReplicatedGui` | one per gateway | fibre | 3 | `Replicated` with the sumo-gui visuals of `Gui` |

Change the link profile for any run on the command line, e.g.
`./run -u Cmdenv -c Replicated --*.backhaulDelay=10ms --*.backhaulPer=0.01`.

## What you should see

The usual output of `analyze_omnet.py`, plus a new section:

```
  Time to finality                p50 38.1 s  p95 82.0 s
    of which waiting for FT       p50 37.0 s  p95 81.0 s
    of which certificate          p50 1.13 s  p95 1.34 s
  ...
  Ledger                          replicated  (one replica per gateway)

  Backhaul and replicas (Phase 3b)
  Link profile                    2.0 ms one way, 1000 Mbit/s, packet loss 0.000
  Transactions (GOSSIP)              879 delivered   link delay p50 2.01 ms  p95 2.02 ms
  Signature shares                   443 delivered   link delay p50 2.02 ms  p95 2.02 ms
  Certificates (FINAL)               663 delivered   link delay p50 2.06 ms  p95 2.06 ms
  Lost on a link / retransmitted  0 / 0   (gave up 0)
  Bytes on the backhaul           7,063,100 data + 103,220 ACK   busiest link 78.4 kbit/s
  Publish -> in another replica   p50 76.0 ms  p95 304.0 ms  max 445.0 ms
  Publish -> in every replica     p50 87.0 ms  p95 317.0 ms
  Orphans (parent not there yet)  0 resolved, 0 at the end
  Approvals of already-final tx   0 (parent final in the receiver's replica, not yet in the creator's)
  Signature shares                670 signed, 443 received by the origin, 0 arrived after finality
  Replicas agree at the end       293 of 294 tx in every replica; 221 of 221 final everywhere
```

## Registered identities (BC_ID record)

Every run now saves the registration chain (BC_ID, Alg. 1) so you can show
who was registered and prove the record was not altered. At the end of the
run the gateway service writes, next to `summary.json` in `results\run-<time>\`:

| File | Contents |
|---|---|
| `bc_id.json` | Count by role, identity root, `chain_valid`, one entry per block (index, pseudonymous identity, role, simulated time registered, public-key digest, block hash, previous hash, identity root after the block), refused handshakes (identity, car, gateway, time, reason) and rejected registrations |
| `bc_id.csv` | The blocks as a table: `index, identity, role, registered_sim_s, pubkey_digest, block_hash, prev_hash, identity_root_after` |

The same content is in `gateway_summary.json` under `registry`, and
`analyze_omnet.py` prints:

```
  Registered identities (BC_ID)   23 (3 gateways, 20 sensors); hash chain intact; identity root b7882aa0541716fa
  Refused at handshake            SN-intruder-eve
```

`chain_valid` is computed, not assumed: each block's hash is recomputed as
`sha256(index, pd, role, pubkey_digest, prev, id_root)` and each `prev` must
equal the previous block's hash (the genesis block is `sha256("bcid-genesis")`).
Change any field of any block and the check reports the chain as broken.
Identities are the pseudonyms the cars registered with, not SUMO names; the
`vehicle` field of a refused handshake gives the SUMO car for reference.

## How it is measured

| Number | Meaning |
|---|---|
| Link delay (per message kind) | First send → delivered at the other RSU (`backhaul.csv`). Includes queueing on the link and any retransmissions |
| Publish → in another replica | Transaction created at its origin → added to another gateway's replica. Includes the origin finishing its tick, the link, and waiting for the receiving gateway's CPU |
| Orphans | Received transactions whose parent had not arrived yet, and how long they waited |
| Approvals of already-final tx | A received transaction approves one that the receiver has already finalised (the creator could not know) |
| Signature shares | Signed / received by the origin / arrived after the transaction was already final (wasted) |
| Replicas agree at the end | Transactions present in, and final in, every replica when the run stops |
| Gateway CPU busy | Sum of each gateway's processing time over the run ÷ simulated time |
| Finality split | Time to finality = created → FT approvals in the origin's ledger + FT reached → certificate complete |

## Results on the cloud test machine

240 simulated seconds, 20 cars, pure-Python crypto, the same SUMO traffic in
every run. Mean over seeds, (min – max). All six attack checks passed in all
51 batch runs. Compare configurations **within one table**: each table is one batch,
and the machine's speed (and so every CPU-derived delay) varies between
batches.

**Shared vs replicated ledger** (5 seeds each; parent selection seeded with
`--seed`, so seed n starts from the same random sequence in every configuration):

| | Default (shared) | DefaultStaggered | Replicated | ReplicatedStaggered |
|---|---|---|---|---|
| Time to finality p50 | 36.4 s (30.0–43.0) | 36.6 s (30.0–43.8) | 38.3 s (35.2–40.1) | 37.4 s (30.8–44.7) |
| … waiting for FT approvals, p50 | 36.4 s | 36.6 s | 37.2 s | 36.7 s |
| … certificate, p50 | 0 | 0 | **1.12 s** (1.11–1.13) | **0.71 s** (0.70–0.71) |
| Time to finality p95 | 78.4 s | 78.5 s | 80.4 s | 79.3 s |
| Transactions published / final | 294 / 219 | 293 / 219 | 294 / 215 | 293 / 217 |
| Gateway tick work, p95 | 562 ms | 573 ms | **249 ms** | 257 ms |
| Reading end-to-end, p95 | 235 ms (191–322) | 241 ms | **31 ms** (12–73) | 27 ms (18–38) |
| Busiest gateway CPU | 10.1% | 10.5% | 8.3% | 8.5% |
| Publish → in another replica, p50 | – | – | 72 ms (64–76) | **8.6 ms** (7–10) |
| Publish → in every replica, p95 | – | – | 303 ms | 58 ms |
| False readings finalised | 114 | 114 | 111 | 113 |

**Link profiles** (5 seeds each, separate batch; parent selection not seeded;
`Default` in this batch: finality p50 33.8 s (31–38)):

| | Replicated (fibre) | Replicated4G | ReplicatedLossy | ReplicatedNoCpuModel |
|---|---|---|---|---|
| Link delay p95: transaction / certificate | 2.0 / 2.1 ms | 35.8 / 37.9 ms | 36–265 / 233–267 ms (a resend waits ≈ 230 ms) | 2.0 / 2.1 ms |
| Packets lost on a link (all recovered) | 0 | 0 | 208 (191–224) | 0 |
| Publish → in another replica, p50 | 60 ms (52–66) | 71 ms (64–82) | 77 ms (67–93) | 2.0 ms |
| Publish → in every replica, p95 | 250 ms | 281 ms | 296 ms | 2.0 ms |
| Time to finality p50 | 38.2 s (36.2–42.1) | 36.8 s (34.2–39.4) | 38.8 s (35.2–45.1) | 38.4 s (34.0–41.0) |
| Time to finality p95 | 78.2 s | 78.9 s | 80.4 s | 79.4 s |
| Reading end-to-end, p95 | 26 ms | 26 ms | 21 ms | 0.45 ms |
| Backhaul data per run / busiest link | 6.7 MB / 75 kbit/s | 6.9 MB / 77 kbit/s | 7.5 MB / 84 kbit/s | 6.8 MB / 76 kbit/s |
| Orphans / approvals of already-final tx | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| Final in every replica at the end | 100% | 100% | 100% | 100% |

**Scaling** (fibre; 3 RSUs from the link-profile batch, 6 and 10 RSUs 3 seeds each):

| | 3 RSUs | 6 RSUs | 10 RSUs |
|---|---|---|---|
| FT (Table III: gateways + 20 cars) | 5 (23 nodes) | **10** (26 nodes) | **10** (30 nodes) |
| Share of the trip in coverage | 66.6% | 99.8% | 99.8% |
| Handshake requests sent | 78 | 111 | 186 |
| Transactions published / final | 293 / 206 | 520 / 334 | 723 / 511 |
| Time to finality p50 / p95 | 38.2 / 78.2 s | 39.2 / 75.7 s | 31.1 / 57.7 s |
| Signature shares sent to an origin / arrived after finality | ≈ 420 / 0 | ≈ 1,660 / ≈ 990 (60%) | ≈ 4,480 / ≈ 3,440 (77%) |
| Busiest gateway CPU | 7.0% | 12.7% | 19.5% |
| Gateway tick work, p95 | 212 ms | 379 ms | 545 ms |
| Reading end-to-end, p95 | 26 ms | 162 ms | 255 ms |
| Publish → in another replica, p50 | 60 ms | 176 ms | 306 ms |
| Backhaul data per run | 6.7 MB | 22.4 MB | 55.2 MB |
| False readings finalised | 110 | 138 | 150 |
| Wall time per run (test machine) | ≈ 70 s | ≈ 4 min | ≈ 12 min |

**Seed-to-seed variation is large** (finality p50 30–45 s within one
configuration). A difference of a few seconds between configurations is not
a result unless it shows up in a directly measured part, such as the
certificate time.

## Findings

Numbering continues from Phase 3a (F1–F9).

**F10. Separate ledgers cost about one tick of finality, and the link
quality costs nothing measurable.** The certificate round (shares signed at
each gateway's next tick, sent to the origin, verified) adds a measured
**1.1 s** to every transaction. The total median rises from 36.4 s to 38.3 s,
which is inside the seed-to-seed spread. Fibre, 4G-like and lossy links give
the same finality (36.8–38.8 s): a backhaul hop takes 2–270 ms, while a
transaction needs 30–40 s of new traffic to collect FT approvals. At this load
the approval rate, not the network, sets finality.

**F11. Spreading the certificate across the gateways removes most of the
gateway queueing seen in Phase 3a (F4, F7).** With one shared ledger, the
gateway whose tick finds a transaction at FT signs all three shares itself.
With replicas each gateway signs only its own. Gateway tick p95 fell from
562 ms to 249 ms and reading end-to-end p95 from 235 ms to 31 ms, on the same
machine in the same batch.

**F12. Gateway scheduling, not the link, sets how fast replicas converge.**
On a 2 ms link a new transaction took 72 ms (p50) to reach another replica.
All gateways tick at the same instant, so an arriving transaction waits for
the receiver's own tick to finish. Ticking one after another
(`ReplicatedStaggered`) cut this to 8.6 ms and the certificate round from
1.12 s to 0.71 s. A deployment should not let gateways run their heavy work in
lock-step.

**F13. The backhaul load is small and dominated by certificates.** Three RSUs
exchange about 7 MB per 240 s (busiest link ≈ 77 kbit/s). Certificates are
two thirds of it: every 7,316-byte certificate goes to every other gateway
and to the server (compare F5). With 5% loss per link, about 208 packets per
run were lost and all were recovered by retransmission; every replica ended
with the same final transactions. No orphans and no approvals of
already-final transactions occurred: even a lossy 4G hop is faster than the
1-second tick, so transactions never arrive out of order. These effects
would appear with slower links or more frequent publishing.

**F14. Every gateway signing every transaction does not scale.** With t = 3,
gateways beyond the first three only add work: at 6 RSUs 60% and at 10 RSUs
77% of the shares arrive after the certificate is already complete. The
busiest gateway's CPU rises from 7% to 13% to 20%, backhaul traffic from 6.7
to 22 to 55 MB per run, and reading end-to-end p95 from 26 to 162 to 255 ms.
A signing committee per transaction (for example the origin and the next
t − 1 gateways), with a fallback when one does not answer, would keep the cost
flat. This is a design decision for Iteration 2.

**F15. More RSUs close the coverage gap of F9, and finality still holds at the
higher threshold.** Six or ten RSUs give coverage on 99.8% of the trip
(66.6% with three). The extra gateways move the network into Table III's large
band (FT 10). Finality nevertheless stayed at 39 s (6 RSUs) and fell to 31 s
(10 RSUs), because more gateways publish more transactions (520 and 723
against 293) and these approve each other sooner. F1 holds at every scale:
138–150 false readings were finalised.

**F1 and F2 hold with separate ledgers**, as expected: replication changes
where the ledger lives, not what it accepts.

## Simplifications (state these in the report)

1. **Payloads stay in Python.** As for the radio, OMNeT++ carries packets of
   the real size; the transaction, share or certificate itself is applied by
   `gateway_service.py` when OMNeT++ says it has arrived.
2. **Every gateway signs every transaction that reaches FT in its replica**
   (t-of-n with n ≥ t). With n > t the shares that arrive after the first t
   are wasted (F12).
3. **Full mesh.** Every RSU has a direct link to every other RSU and to the
   server, all with the same profile. Real backhauls are often star- or
   ring-shaped.
4. **The server only receives.** Opening C_j (Eq. 7) is still done in the
   service when the transaction is published, as in Phase 3a; the server link
   carries the real traffic but its processing is not modelled.
5. **No Byzantine gateways.** Gateways follow the protocol; a gateway that
   withholds shares or forks its replica is FYP-2 work.
6. **Reliable transport is idealised:** ACKs (52 bytes) and timeouts, no
   congestion control.

## Troubleshooting

| Problem | Fix |
|---|---|
| `Class "VeyraBackhaulPort" not found` / `VeyraScenario3b` not found | Run `./configure` again (new files), then `make` |
| `ledger = "replicated" needs RSUs with a backhaul` | You set `ledger` on the Phase 3a network. Use a `Replicated*` configuration |
| `the gateway service refused HELLO ... already uses shared` | The service was used by an earlier run. Start a fresh one for every run |
| `rsu[3] cannot reach the gateway service at 127.0.0.1:9004` | 6/10 RSUs: start the service with that many `--ports` (see Run) |

Tested with OMNeT++ 6.1, Veins 5.3.1 and SUMO 1.22.0 on Linux.
