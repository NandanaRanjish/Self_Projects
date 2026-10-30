# Complete experimental matrix — unified four-mode release

**Primary research question:** Is randomized/offline bank-guided scheduling
alone sufficient to protect a command against a timing-informed cooperative
UNTRUSTED worker? What additional protection comes from guarding the command
buffer's publication-to-TX interval?

## Primary fixed-rate ablation — 40 runs

| Rate | Mode | Guidance | Guard | Attacker prior | Replicates |
|---|---|---|---|---|---|
| 20 ms | NONE | Off | Off | 20 ms | 5 |
| 20 ms | SHUFFLER ONLY | On | Off | 20 ms | 5 |
| 20 ms | GUARD ONLY | Off | On | 20 ms | 5 |
| 20 ms | COMBINED | On | On | 20 ms | 5 |
| 25 ms | NONE | Off | Off | 25 ms | 5 |
| 25 ms | SHUFFLER ONLY | On | Off | 25 ms | 5 |
| 25 ms | GUARD ONLY | Off | On | 25 ms | 5 |
| 25 ms | COMBINED | On | On | 25 ms | 5 |

Command (fresh IDs):

```bash
$PY repro/experiment.py matrix --start 201 --count 5
```

Each 3-second run has 150 host motor command exchanges. The real-time firmware
may execute more worker jobs than the host command count; the 600 ms captures
are separately checked. The physical actuator MUST remain disconnected.

## Clean checks — 3 runs

```bash
$PY repro/experiment.py clean --rate 20 --id 100
$PY repro/experiment.py clean --rate 25 --id 100
$PY repro/experiment.py clean --rate ALT --id 100
```

## Optional mixed-rate exploratory test — 8 runs

For both attacker priors 20/25 ms, test all four modes at controller ALT.
`ALT` switches the CONTROL/TX period at 600 ms boundaries. Because the attacker
uses one fixed prior, this does not simulate a fully adaptive adversary.

```bash
for PRIOR in 20 25; do
  for MODE in none guide guard both; do
    $PY repro/experiment.py alt --prior "$PRIOR" --mode "$MODE" --id 501
  done
done
```

## Required measurements

For each trial: firmware hash, verified guide/guard flag pair, attack attempt
count, transmitted command corruption fraction, tracking RMSE, zero/positive
captured exposure overlap, release/completion counts, deadline miss counts,
PROTOSTAT rejection counter, grant-budget warnings, AEW and cleanup status.

## Acceptance and reporting

- Do not count any run with missing CMD, partial CSV, lost capture records,
  incomplete job audit, reported scheduler budget overrun or missing board mode
  confirmation.
- A zero corruption rate with no attacker attempts is inconclusive.
- Compare complete **paired trial blocks** to avoid counting commands in one
  trial as statistically independent experimental replicates.
- NONE still has TaskShuffler cooperative shuffling enabled; SHUFFLER ONLY
  means **offline schedule-bank guidance** without guarding.
- This ablation can demonstrate that guidance-only still permits attack under
  your attacker model; it does not prove all possible randomized scheduling is
  ineffective, nor that the guard is physical memory isolation.

## User interface

- Page 1: four-mode attack outcomes for 20 and 25 ms.
- Page 2: true recorded scheduling timeline, publication/TX windows.
- Page 3: motor speed, setpoint, calculated/applied voltage.

Generate everything with:

```bash
$PY repro/experiment.py graphs
```
