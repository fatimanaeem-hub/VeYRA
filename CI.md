# CI/CD pipeline

GitHub Actions tests every push to every branch. When we ask it to, it publishes a release of an iteration, but only if that commit passes every check first.

```
push to any branch ──► CI ─┬─ Lint
                           ├─ Tests            Linux + Windows, Python 3.11 and 3.13
                           ├─ Service smoke    gateway_service.py + fake_omnet.py   (iteration 2 on)
                           ├─ SUMO smoke       gateway_service.py + real Erlangen traffic (2.5 on)
                           └─ Veins            OMNeT++ 6.1 + Veins 5.3.1, 802.11p runs (3a on)

Actions ► Release ► Run workflow ──► the same CI ──► passes? ──► tag + GitHub Release
                                                                  (source zip + CI results zip)
```

## Files

| File | What it does |
|---|---|
| `.github/workflows/ci.yml` | The CI pipeline. Runs on every push, on pull requests, and by hand. |
| `.github/workflows/release.yml` | The CD pipeline. Re-runs CI, then creates the tag and the GitHub Release. |
| `ci/smoke_service.py` | Starts the gateway service, drives it with `fake_omnet.py` or `sumo_driver.py`, and checks the result. |
| `ci/check_veins.py` | Pass/fail gate for the OMNeT++/Veins runs. |
| `ci/build_toolchain.sh` | Builds OMNeT++ 6.1 (command line only) and Veins 5.3.1 on the Linux runner. The result is cached. |

The same files work on every branch. A first job, *Detect project parts*, checks which parts the branch contains and starts only the jobs that apply. On `main` (the proof of concept) only Lint and Tests run; on `iter-3b-bcid` everything runs.

## What makes a run fail

| Job | Fails when |
|---|---|
| Lint | A Python file has a syntax error or uses an undefined name |
| Tests | `verify.py` (9 self-checks), `testcase.py` (TC-01) or `run.py --headless` fails |
| Service smoke | An attack check fails, the service crashes, or `summary.json` is missing. From 3b-bcid on, it also fails if the BC_ID hash chain does not verify. |
| SUMO smoke | Same checks, with real SUMO traffic (150 simulated seconds) |
| Veins | OMNeT++ does not build or run, any of the 6 attack checks fails, no record reaches finality, the ledger copies disagree (3b on), or the BC_ID record does not verify (3b-bcid on) |

"Pass" means the system behaves the way the base paper's design says it should. That includes the two gaps: the in-window replay is **accepted**, and the compromised car's false readings are **accepted and finalised**. The pipeline checks for both, so if FYP-2's detector later starts blocking those readings, these two expectations need updating.

## How long it takes

| Job | Time |
|---|---|
| Lint, Tests | 1–2 min |
| Service smoke, SUMO smoke | about 2 min each |
| Veins, first run on a branch | about 12–15 min (builds OMNeT++ and Veins once, then caches them, about 70 MB) |
| Veins, later runs | about 4 min (build veins_veyra + 2 runs of about 1 min each) |

The jobs run in parallel. The cache belongs to one branch. A branch can also use `main`'s cache, but `main` never builds OMNeT++, so each iteration branch builds it once.

## Reading the results

Open **Actions** and click a run.
- The **summary** page shows a table for each job: attack checks, delivery ratio, finality, false readings finalised, whether the ledger copies agree, and the BC_ID record.
- **Artifacts**, at the bottom of the summary page, are downloadable zips:
  - `poc-evidence`: `evidence/report.json`
  - `service-smoke-*` and `sumo-smoke`: the service's run folder (trace, `summary.json`, `bc_id.csv`) plus logs
  - `veins-runs`: the OMNeT++ result folders, `runs.csv` and the logs

## Making a release

Go to **Actions → Release → Run workflow**, choose the branch, type a tag (for example `v3.1-3b-bcid`) and click **Run workflow**. The release appears under **Releases** with two files:
- `VEYRA-<tag>-source.zip`: the code
- `VEYRA-<tag>-ci-results.zip`: the CI evidence

Badge for the README (replace OWNER/REPO):

```markdown
![CI](https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg?branch=iter-3b-bcid)
```
