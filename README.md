# Post-Quantum DAG Blockchain for Vehicular Sensor Networks — Proposal-Stage PoC

A small, honest feasibility proof for the FYP proposal defence. It is **not** an MVP
and not a product. Its only job is to test the riskiest assumption in the proposal
and to report what that test actually showed.

Based on: Ahmed, Tariq, Khan & Chauhdary, *Post-Quantum DAG-based Blockchain for
Securing Vehicular Sensor Networks*, IEEE Transactions on Consumer Electronics,
DOI 10.1109/TCE.2026.3688933.

---

## Run it

```bash
pip install -r requirements.txt
python run.py
```

The dashboard opens at <http://127.0.0.1:8000>.

No database, no Docker, no build step. The web server is Python's standard
library, so the only dependency is the post-quantum library itself. If that
library is missing the prototype still runs, on a classical fallback that is
labelled in red on every screen.

To produce the evidence file without the GUI:

```bash
python run.py --headless      # writes evidence/report.json
```

---

## What is being tested

> **The risky assumption:** NIST post-quantum cryptography is cheap enough for
> constrained vehicular sensor nodes, *and* a DAG ledger absorbs that cost
> better than the linear chain it replaces.

If either half is false, the proposed architecture does not stand — so this is
the thing worth testing before the design is approved.

## What is real

| Component | Implementation |
|---|---|
| Key establishment | **ML-KEM-768** (FIPS 203, formerly CRYSTALS-Kyber-768) |
| Signatures | **ML-DSA-44** (FIPS 204, formerly CRYSTALS-Dilithium-2) |
| Session encryption | AES-256-GCM |
| Registration chain (`BC_ID`) | Hash-linked ledger, Algorithm 1 |
| Session handshake | Algorithm 2, Equations 1–4 |
| Gateway verify + aggregate | Algorithm 3, Equations 5–7 |
| DAG transaction | Algorithm 4, Equations 10–11 |
| Merkle root, PoPQW, finalisation | Algorithm 5, Equations 8–9 |
| tPQ-Sig certificate | Equation 12, as a t-of-n multi-signature |

Key and signature **sizes** are the exact NIST values and do not depend on the
implementation. Timings depend on the machine and on whether the compiled
`liboqs` backend or the pure-Python backend is in use — the dashboard says which.

## The finalisation threshold is derived, not chosen

FT is not a dial. The paper states it "is decided based on the size of the
network" and gives reference values in Table III, so the prototype computes it
at build time from the node count (gateways + sensors) and offers no way to
override it — not through the UI, not through the API, not through the ledger
constructor.

Table III's bands start at 10, 100 and 1,000 nodes. This prototype tops out at
72 nodes (8 gateways × 8 sensors), so using those numbers literally would park
every possible network in the smallest band and FT would be 3 forever. Instead
we keep the paper's **scale** — three geometric bands carrying its published
thresholds — and compress the axis onto the range we can actually build:

| Nodes here | Band | Paper's band | FT |
| --- | --- | --- | --- |
| 2–8 | Small DAG | 10–100 nodes | 3 approvals |
| 9–24 | Medium DAG | 101–1,000 nodes | 5 approvals |
| 25–72 | Large DAG | 1,001+ nodes | 10 approvals |

The exact geometric boundaries for 2–72 are 6.6 and 21.8 (ratio 3.30); we
rounded to 8 and 24 for legibility. **The thresholds 3, 5 and 10 are the
paper's; the node counts that select between them are ours.** The default build
(3 gateways × 4 sensors = 15 nodes) is Medium, so FT is 5.

## Finalisation counts approvals, not just direct children

Algorithm 5 line 25 scans *every* transaction in the DAG asking whether it
references `Tx` — not only `Tx`'s direct children — so `Reference_Count` is the
transitive approval count, which is also how DAG ledgers define confirmation in
practice. The prototype implements it that way, and it matters:

Every publish creates one transaction and hands out exactly two direct
references, so the mean direct-reference count is pinned at 2 regardless of
network size or traffic. Counting only direct children, references are
Poisson(2) — FT=5 would finalise about 5% of traffic and FT=10 essentially
none. We measured 7% and 0% against a predicted 5.3% and 0.005%. Counting
approvals transitively removes that ceiling, and all three of the paper's
thresholds behave as intended:

| Network | FT | Finalised | Mean latency |
| --- | --- | --- | --- |
| 6 nodes | 3 | 55% | 3.1 s |
| 15 nodes | 5 | 37% | 4.2 s |
| 25 nodes | 10 | 16% | 4.3 s |
| 72 nodes | 10 | 11% | 5.5 s |

(8-second runs; the finalised share is bounded by run length, since transactions
created near the end have not accumulated approvals yet.) The trend is the
security/performance trade-off the paper describes: a higher threshold means
more confirmations, a smaller finalised share and longer time to finality.

## What is deliberately not real

Stated up front, because a proof of concept that hides its simplifications is
not evidence. All are shown in the GUI under *Known limitations*.

0. **The node counts that select FT are rescaled.** The thresholds are the
   paper's; the band boundaries are our compression of its scale onto 2–72
   nodes, and that is stated wherever the threshold is shown.
1. **tPQ-Sig is a t-of-n multi-signature, not a compact threshold signature.**
   No threshold variant of ML-DSA is standardised today. Security is preserved
   (t honest gateways must agree); compactness is not — the certificate grows
   linearly with t.
2. **PoPQW is a SHA-256 puzzle**, per Eq. 8–9 of the paper. That is not strongly
   post-quantum: Grover's algorithm gives a quadratic speed-up, so the
   difficulty target must be squared to keep the intended margin.
3. **Single-process simulation.** Radio latency, packet loss and clock skew are
   not modelled. This measures cryptographic and consensus cost, not radio cost.

---

## Using it in the defence

1. **Build network** — registers every node on `BC_ID` and runs a real
   post-quantum handshake per sensor. The build time shown is real.
2. **Send a reading** from any IoT device panel — encrypted on the device,
   decrypted and hash-verified at the gateway, visible in the event log.
3. **Start sensor traffic**, then watch the DAG grow. Each gateway has its own
   lane, so parallel publication is visible. Numbers inside pending nodes are
   approval counts; nodes turn green at the finalisation threshold.
4. **Evidence tab** — run the three experiments. Each prints the numbers you
   will be asked for.
5. **The five PoC questions tab** — fills itself in from those runs. Read it to
   the panel.

## Layout

```
run.py                    entry point
requirements.txt
pqdag/
  crypto.py               PQC backend selection, KEM, signatures, AEAD
  ledger.py               DAG, Merkle root, PoPQW, finalisation, tPQ-Sig
  linear.py               linear PSN chain (the control condition)
  network.py              Sensor, Gateway, Server; Algorithms 1-3
  simulation.py           live simulation + adversarial checks
  benchmarks.py           Experiment 1: cost of PQC
  experiment.py           Experiment 2: DAG vs linear
  webapp.py               stdlib HTTP server
  static/index.html       dashboard
evidence/report.json      written by --headless
```
