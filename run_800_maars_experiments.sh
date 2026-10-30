#!/usr/bin/env bash
# MAARS: 100 matched trial IDs per sampling rate and mode (800 attempted runs).
# Run from the cleaned MAARS project root; uses the existing validated runner.
set -uo pipefail

cd "$(dirname "$(realpath "$0")")" 2>/dev/null || exit 1
PY="$PWD/.venv/bin/python"
RUNNER="repro/experiment.py"
PORT="${PORT:-/dev/ttyACM0}"
START_ID="${1:-10001}"
REPETITIONS="${2:-100}"
LOGDIR="reports/batch_800"
mkdir -p "$LOGDIR"

if ! [[ "$START_ID" =~ ^[1-9][0-9]*$ && "$REPETITIONS" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: starting ID and repetition count must be positive integers." >&2
  exit 1
fi
if (( REPETITIONS > 100 )); then
  echo "ERROR: maximum repetitions for this batch is 100." >&2
  exit 1
fi
if [[ ! -x "$PY" || ! -f "$RUNNER" ]]; then
  echo "ERROR: open this script from the MAARS submission folder and install .venv first." >&2
  exit 1
fi
if [[ ! -e "$PORT" ]]; then
  echo "ERROR: ESP32 serial device $PORT not found." >&2
  exit 1
fi
export PORT

echo "Checking Python syntax and firmware-source preflight..."
"$PY" -m compileall -q repro tools model dashboard || exit 1
"$PY" "$RUNNER" doctor > "$LOGDIR/preflight.log" 2>&1 || {
  cat "$LOGDIR/preflight.log"
  echo "STOP: Fix preflight errors before collecting data." >&2
  exit 1
}

TOTAL=$((REPETITIONS * 8))
ATTEMPTED=0
PASSED=0
FAILED=0
SKIPPED=0
SUMMARY="$LOGDIR/run_index.csv"
if [[ ! -e "$SUMMARY" ]]; then
  printf 'trial_id,rate_ms,mode,status,validation_file,log_file\n' > "$SUMMARY"
fi

for ((trial=START_ID; trial<START_ID+REPETITIONS; trial++)); do
  for rate in 20 25; do
    for mode in none guide guard both; do
      stem="maars_${rate}_${mode}_r${trial}"
      metadata="reports/validation/${stem}.json"
      logfile="$LOGDIR/${stem}.log"

      # Always preserve existing or incomplete runs; never overwrite data.
      if [[ -e "$metadata" ]] || compgen -G "traces/${stem}*" >/dev/null; then
        printf 'SKIP existing: %s\n' "$stem"
        printf '%s,%s,%s,SKIPPED_EXISTING,%s,%s\n' "$trial" "$rate" "$mode" "$metadata" "$logfile" >> "$SUMMARY"
        ((SKIPPED+=1))
        continue
      fi

      ((ATTEMPTED+=1))
      printf '[%d/%d] Running %s ... ' "$((ATTEMPTED+SKIPPED))" "$TOTAL" "$stem"
      if "$PY" "$RUNNER" one --rate "$rate" --mode "$mode" --id "$trial" > "$logfile" 2>&1; then
        ((PASSED+=1))
        status=PASS
      else
        ((FAILED+=1))
        status=FAILED_OR_WARNING
      fi
      printf '%s\n' "$status"
      printf '%s,%s,%s,%s,%s,%s\n' "$trial" "$rate" "$mode" "$status" "$metadata" "$logfile" >> "$SUMMARY"
    done
  done
  echo "Completed trial ID $trial: new PASS=$PASSED, new errors=$FAILED, pre-existing=$SKIPPED"
done

"$PY" "$RUNNER" summary > "$LOGDIR/project_summary.log" 2>&1 || {
  echo "WARNING: summary generation failed; see $LOGDIR/project_summary.log" >&2
}

echo
echo "Requested: $TOTAL runs ($REPETITIONS per rate/mode)"
echo "Newly PASS: $PASSED; failures: $FAILED; pre-existing skipped: $SKIPPED"
echo "Batch index: $SUMMARY"
echo "Raw data: traces/"
echo "Strict verification: reports/validation/"
echo "Review $LOGDIR and accepted counts before reporting final percentages."
