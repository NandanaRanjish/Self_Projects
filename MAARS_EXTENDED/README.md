# MAARS — Extended Four-Mode Implementation & Multi-Milestone Evaluation

This submission contains an integrated ESP32-S3 research prototype with
independent GUIDE and GUARD controls, extended with dynamic runtime defense
transitions, multi-target attack evaluation, and side-channel leakage audits.
It includes the updated hardware-verified firmware, original and extension
host scripts, offline models, validation datasets, and five milestone suites.

## What is inside

- `main/`, `tools/`, `CMakeLists.txt`, `sdkconfig`: maintained firmware and host source.
  `main/` contains the hardware-verified firmware with 4 KiB UART buffering, in-window
  attacker retries, and dynamic alert-triggered guard activation.
- `firmware/MAARS_ESP32S3_Unified.bin`: baseline prebuilt flash image (Oct 30 build).
  To run the milestone extensions, build and flash from `main/` using `idf.py`.
- `milestones/`: complete empirical suites for all five initial and extension milestones:
  - `initial_m1_adaptive_attacker/`: exploratory baseline on schedule ladder learning.
  - `initial_m3_load_starvation/`: exploratory baseline on synthetic CPU load sweeps (50%, 75%, 90%).
  - `extension_m1_alert_cycling/`: dynamic Normal↔Alert cycling with on-chip deferrals.
  - `extension_m2_m3_anterior_multivictim/`: Anterior vs. Posterior attack surface & multi-victim SVI.
  - `extension_m4_guard_leakage/`: side-channel delay mutual information leakage audit.
- `reports/`: consolidated research reports, publication figures, 800-run baseline logs
  (`batch_800/`), and validation datasets (`validation/`).
- `repro/experiment.py`: controller for original hardware runs, audits, summary and UI.
- `dashboard/site/index.html`: generated locally; 3 pages: **Results**, **Task
  Timeline**, **Motor Response**.
- `model/`: verified offline-model schedules and ideal-model stability certificate.
- `environment.json`, `EXPERIMENT_MATRIX.md`, `SHA256SUMS.txt`: environment specifications
  and regenerated checksum manifests.

**This project uses a simulated motor running on the host computer. The guard is
cooperative scheduling protection, not unauthorized-write memory isolation.**

## How `main/` differs from the original reference firmware

The embedded firmware in `main/` retains the full original protocol, TaskShuffler scheduling,
offline bank guidance, and chi-squared shadow detector of `Self_Projects-main`, with the
following concrete enhancements:

1. **4 KiB Interrupt-Driven UART0 RX Buffer (`main/main.c`)**:
   The original firmware relied on a 10 ms polling loop reading directly from the ESP32-S3's
   128-byte hardware FIFO. Under high CPU load or preemption, host bytes were dropped, causing
   garbled serial packets (~900+ `ERR` lines per run). We installed the ESP-IDF UART driver
   (`esp_driver_uart`) with a 4096-byte ring buffer (`uart_driver_install`), completely
   eliminating dropped packets (`0 ERR lines`).
2. **In-Window Attacker Firing & Continuous Retries (`main/main.c`)**:
   In the original firmware, the attacker task fired unconditionally on every single job
   regardless of its inferred phase. In the updated firmware, the attacker fires only inside
   its predicted execution window and retries continuously throughout that window.
3. **Dynamic Alert-Triggered Guard Activation (`main/main.c`)**:
   While `S11,ON/OFF/MODE` command handlers existed in the original code, an incoming host
   alert signal did not previously engage the guard. The firmware was modified so that an
   alert trigger dynamically turns on SchedGuard (`guard = 1`) on the board without requiring
   a reboot (Milestone 1).
4. **Multi-Target and Multi-Victim Serial Commands (`main/main.c`)**:
   Added thread-safe command handlers (`actuator_mux`) for:
   - `ATTACK,TARGET,CONTROL` / `ATTACK,TARGET,SAFETY`: switches the victim task between
     primary control and safety-critical monitoring to evaluate multi-victim Schedule
     Vulnerability Index (Milestone 3).
   - `ATTACK,MODE,POSTERIOR` / `ATTACK,MODE,ANTERIOR`: switches between actuator command
     buffer corruption (posterior) and sensor measurement buffer corruption (anterior) to
     quantify the sensor exposure gap (Milestone 2).
5. **New Telemetry and Experimental Control Commands (`main/main.c`)**:
   - `ATKPRIOR,ADAPTIVE`: selects the online rate-adaptive dual-ladder attacker prior.
   - LOAD,<pct>: sets UNTRUSTED work duration to 2 ms (50%), 6 ms (75%), or 10 ms (90%) for CPU load and starvation sweeps (Milestone 3).
   - RESP: emits per-job execution telemetry (RESP,<mode>,<load_pct>,UNTRUSTED,<planned_us>,<resp_us>,<deadline_us>,<miss>) used by M1 alert cycling and M3 load sweep. (Note: M4 parses OWN scheduling grant lines, not RESP).
   - `POST_SKIP`: telemetry counter in `ATKSTAT` tracking posterior attack opportunities
     skipped when outside the predicted attack window.

## 1. Requirements

Linux or Windows; compatible ESP32-S3 and USB data cable; ESP-IDF (v5.x/v6.x) installed;
Python 3 with `pyserial`, `numpy`, `scipy`, `matplotlib`. The original firmware build
environment is recorded in `environment.json`. Change `PORT` if needed.

```bash
cd MAARS_EXTENDED
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
export PY="$PWD/.venv/bin/python"
export PORT=/dev/ttyACM0    # On Windows: set PORT=COM8
$PY repro/experiment.py doctor
```

## 2. Model-only reproducibility (board not needed)

```bash
$PY repro/experiment.py offline
$PY repro/experiment.py graphs
xdg-open dashboard/site/index.html    # On Windows: start dashboard/site/index.html
```

The offline model's common quadratic stability certificate **does not** certify
USB delays, motor saturation or the live host's nominal 20 ms integration step.

## 3. Flash firmware (only if the board needs flashing)

To run the milestone extensions, build and flash the updated milestone firmware from source:

```bash
idf.py build
idf.py -p "$PORT" flash
```

*(Note: The prebuilt image `firmware/MAARS_ESP32S3_Unified.bin` is the legacy baseline build
from Oct 30 and does not contain the milestone extension handlers. Build from `main/` using `idf.py`).*

Back up board flash first if it contains anything important. Keep the physical actuator disconnected.

## 4. First ESP32 test, attacker disabled

```bash
$PY repro/experiment.py clean --rate 20 --id 100
$PY repro/experiment.py clean --rate 25 --id 100
$PY repro/experiment.py clean --rate ALT --id 100
$PY repro/experiment.py graphs
```

Inspect clean scheduling captures and the actual 20/25 rate trace.

## 5. Baseline experiment: the four-way attack ablation

All four modes use `TS,ON` and the same configured controller rate, workload,
attacker prior and host motor. Guidance and guard are **separate switches**.

| Mode | Offline bank guidance | Command-exposure guard | Attacker |
|---|---|---|---|
| NONE | OFF | OFF | ON |
| SHUFFLER ONLY (`guide`) | ON | OFF | ON |
| GUARD ONLY (`guard`) | OFF | ON | ON |
| COMBINED (`both`) | ON | ON | ON |

`NONE` still uses the basic cooperative TaskShuffler random dispatcher: the
additional offline **bank guidance** is disabled. This is not a comparison to a
perfectly fixed-priority dispatcher.

One full four-condition trial at each period:

```bash
$PY repro/experiment.py ablation --rate 20 --id 101
$PY repro/experiment.py ablation --rate 25 --id 101
$PY repro/experiment.py graphs
xdg-open dashboard/site/index.html
```

**Main repeated experiment:** five independent matched blocks at each rate
(2 rates × 4 conditions × 5 trials = **40 attack-on runs**):

```bash
$PY repro/experiment.py matrix --start 201 --count 5
$PY repro/experiment.py graphs
```

Or run the whole study, including clean and ALT conditions:

```bash
$PY repro/experiment.py suite --start 301 --count 5
```

The complete suite has 3 clean runs + 40 fixed-rate attack runs + 8 ALT
attack-prior/mode runs = **51 runs**. No software runs in the background; the
suite stops on the first failure. **Never restart a stopped batch blindly**:
inspect the saved partial run, then use a new unused trial ID for that block.

## 6. Optional ALT attack experiments

```bash
$PY repro/experiment.py alt --prior 20 --mode guide --id 401
$PY repro/experiment.py alt --prior 20 --mode guard --id 401
$PY repro/experiment.py alt --prior 25 --mode guide --id 402
$PY repro/experiment.py alt --prior 25 --mode both --id 402
```

Each attacker has one fixed prior, so these are **exploratory**, not a fully
adaptive rate-aware attacker evaluation.

## 7. Milestone Experiments (Initial & Extension)

The `milestones/` directory contains the standalone reproduction scripts and
empirical traces for both the initial and extended research milestones:

### Extension M1: Normal↔Alert Dynamic Cycling
Evaluates real-time transition from uncorrupted normal operation to active attack, host
detector alarm firing, and on-chip SchedGuard engagement across 8 consecutive cycles.
- **Results**: Corruption before alert: **22.0%** (53/241) → after alert: **0.0%** (0/927).
  **915 on-chip deferrals**, 100% detection rate (mean latency 1656 ms), 0 false alarms.
  Fisher's exact test: $p = 3.21 \times 10^{-39}$.
```bash
cd milestones/extension_m1_alert_cycling
$PY m1_cyclic_driver.py --port "$PORT" --cycles 8 --out data/m1_raw.csv
$PY m1_cyclic_analyze.py data/m1_raw.csv --plot reports/m1_alert_cycling.png
```

### Extension M2 & M3: Anterior vs. Posterior & Multi-Victim SVI
Evaluates attack penetration across anterior (sensor) and posterior (actuator) buffers,
and computes the multi-victim Schedule Vulnerability Index (SVI) across CONTROL and SAFETY.
- **Results (Milestone 2 - Guard Blind Spot)**:
  - Posterior Unguarded: **21.53%** (31/144) vs. Posterior Guarded: **0.00%** (0/150).
  - Anterior Unguarded: **10.80%** (19/176) vs. Anterior Guarded: **28.74%** (48/167).
  - Fisher exact test (Posterior Guarded vs. Anterior Guarded): $p = 1.198 \times 10^{-15}$.
  - *Key Finding*: SchedGuard effectively protects the posterior command buffer ($0.00\%$),
    but anterior attacks bypass the guard completely ($28.74\%$), revealing the temporal guard blind spot.
- **Results (Milestone 3 - Multi-Victim SVI)**:
  - CONTROL AP: **20.53%** (31/151) | SAFETY AP: **19.12%** (48/251).
  - Criticalities ($2:1$ ratio): CONTROL = 0.667, SAFETY = 0.333.
  - Multi-Victim $\text{SVI} = 0.667 \times 0.2053 + 0.333 \times 0.1912 = \mathbf{0.2006}\ (20.06\%)$.
  - *(Note: No guarded SAFETY run was executed; SVI reflects the multi-victim baseline vulnerability).*
```bash
cd milestones/extension_m2_m3_anterior_multivictim
$PY run_m2_m3_experiments.py --port "$PORT" --duration 10
$PY m2_m3_analyze.py m2 --posterior data/post.csv --anterior data/ant.csv
$PY m2_m3_analyze.py m3 --control data/ctrl.csv --safety data/safety.csv --crit 2 1
```

### Extension M4: Guard Delay Side-Channel Leakage
Evaluates whether SchedGuard preemption deferrals introduce timing side-channel leakage
by measuring start and finish delay mutual information against CONTROL task release phase.
- **Results**: Baseline start delay leakage: $I = 0.3367\text{ bits}$ vs. Guarded: $I = 0.3400\text{ bits}$.
  Information delta $\Delta I = +0.0032\text{ bits}$ ($<1\%$, bootstrap 95% CI $[-0.058, +0.065]$).
  Kolmogorov-Smirnov test: $D = 0.043, p = 0.426$ (fail to reject null hypothesis; zero added leakage).
```bash
cd milestones/extension_m4_guard_leakage
$PY m4_collector.py --port "$PORT" --mode none --duration 40 --out data/cap_none.csv
$PY m4_collector.py --port "$PORT" --mode guard --duration 40 --out data/cap_guard.csv
$PY m4_delay_leakage.py none=data/cap_none.csv guard=data/cap_guard.csv --plot reports/m4_delay_leakage.png
```

### Initial M1 & M3: Exploratory Baselines
- **Initial M1 (Schedule Ladder Learning — Exploratory)**: Evaluated fixed prior (19.35%) vs.
  rate-adaptive attacker (30.39%) vs. guarded (0.00%).
  *Caveat*: Conducted on initial firmware where both attacker variants shared similar firing
  behavior, and the detector tracked plant tracking error. Retained as exploratory data.
```bash
cd milestones/initial_m1_adaptive_attacker
$PY run_m1_experiments.py --port "$PORT" --duration 8
```
- **Initial M3 (CPU Load Sweep — Exploratory)**: Sweeps background load across 50%, 75%, and 90%
  utilization under Always-On, Adaptive, and Guide-Only modes (0 deadline misses observed).
```bash
cd milestones/initial_m3_load_starvation
$PY run_m3_load_sweep.py --port "$PORT" --duration 9
```

## 8. View and export results

```bash
$PY repro/experiment.py summary
$PY repro/experiment.py graphs
xdg-open dashboard/site/index.html
```

**Results:** Four bars per rate, run counts, attempts, corruption fraction.
**Task Timeline:** Replay real firmware worker grants and command windows.
**Motor Response:** Host-simulated speed and calculated/applied voltages.
**Research Reports:** Academic synthesis in `reports/FULL_RESEARCH_REPORT.md`,
`reports/m1_m4_research_report.md`, and `reports/m2_m3_research_report.md`.

## 9. Evidence / acceptance requirements

- Exactly 150 consecutive host CMD samples per 3-second fixed-rate run.
- Attack attempts nonzero for every attack-on run.
- Board confirms guide/guard mode bits on GUIDE/GUARD/BOTH runs.
- A valid, loss-free 600 ms scheduling capture (97 jobs at 20 ms, 85 at 25 ms).
- Zero observed deadline misses, zero protocol rejections, zero scheduler
  diagnostics for a strict PASS.
- On GUARDED runs: zero corrupted transmitted commands and zero overlaps in
  complete captured command-exposure intervals.
- On DYNAMIC ALERT runs (M1): post-alert corruption must collapse to 0.0% with
  statistically significant mitigation ($p < 10^{-5}$) and non-zero hardware deferrals.
- On LEAKAGE audits (M4): guard start delay distribution must not significantly
  differ from baseline ($p > 0.05$ on two-sample KS test).
- **Firmware Provenance Rule**: Comparisons must not mix different firmware image hashes.
  Milestone 2 and 3 data were acquired on Laptop 2 using firmware hash `2aca30...` (which
  implemented anterior/posterior modes and multi-victim targets). Milestone 1 dynamic alert
  cycling and Milestone 4 delay leakage were evaluated on Laptop 1 using the consolidated
  firmware hash (with the 4 KiB UART buffer and continuous in-window retries). Each
  milestone's reported comparisons are evaluated strictly within its own firmware build.
- Partial, unverified, failed and warned runs are excluded from accepted means.

Inspect `reports/ablation_inventory.csv` (every run), `reports/ablation_by_mode.csv`
(descriptive pooled command fractions), and `reports/matched_four_way_trials.csv`
(only complete four-condition matched blocks).

## 10. Limitations

1. **Serial Output Bandwidth Limit**: In Milestone 1, only 41% of commands (2,669 of 6,588
   sequence numbers) appear in the serial log due to 115200 baud UART output bandwidth
   limits (logging throttled to prevent backpressure on real-time task dispatching; input
   parsing had zero dropped lines with `0 ERR lines`).
2. **Single-Run per Condition Scope**: The milestone extension datasets represent high-fidelity
   single runs per experimental condition (e.g. 40–160 seconds, hundreds to thousands of commands
   per run), rather than multi-trial randomized block suites.
3. **Exploratory Status of Initial Runs**: Initial M1 and M3 used early firmware builds and
   are retained as exploratory baselines rather than definitive claims.

## If a command fails

Preserve `traces/<run>.log`, `<run>.csv`, `reports/validation/<run>.json`,
and the captured audit directory. Do not delete a partial run or simply increase
a protocol timeout. Diagnose rejected sensors via `PROTOSTAT` and scheduling
anomalies via `TSDIAG`.

## Use of AI tools
AI coding assistants were used to support firmware driver integration, statistical analysis script development, and README formatting.
