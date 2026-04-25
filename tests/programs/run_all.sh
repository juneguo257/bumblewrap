#!/usr/bin/env bash
# Meta-runner: executed INSIDE the sandbox by the daemon.
# Runs every test_*.sh script and writes per-test results to a shared
# results directory, then drops a DONE marker so the outer harness knows
# all tests have finished.

RESULTS_DIR="/tmp/bumblewrap_test_results"
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "$RESULTS_DIR"

for test_script in "$TEST_DIR"/test_*.sh; do
    test_name=$(basename "$test_script" .sh)
    result=$(timeout 10 bash "$test_script" 2>/dev/null)
    rc=$?
    if [[ $rc -eq 124 ]]; then
        result="FAIL:timed out after 10s"
    elif [[ -z "$result" ]]; then
        result="FAIL:no output (exit code $rc)"
    fi
    echo "$result" > "$RESULTS_DIR/$test_name"
done

echo "done" > "$RESULTS_DIR/DONE"
