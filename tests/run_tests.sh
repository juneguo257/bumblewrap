#!/usr/bin/env bash
# ==========================================================================
#  Bumblewrap Sandbox — Automated Test Suite
#
#  Starts the cgroups daemon once, runs a battery of escape / access tests
#  inside the sandbox, then collects and reports results.
#
#  Must be run as root:  sudo bash tests/run_tests.sh
# ==========================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="/tmp/bumblewrap_test_results"
TEST_STAGING="/tmp/bumblewrap_tests"
DAEMON_PID=""

die() { echo "FATAL: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "must be run as root (sudo $0)"

# ── Setup ─────────────────────────────────────────────────────────────────
setup() {
    rm -rf "$RESULTS_DIR" "$TEST_STAGING"
    mkdir -p "$RESULTS_DIR" "$TEST_STAGING"

    # Stage test scripts under /tmp/ so the sandbox can read them
    cp "$SCRIPT_DIR"/programs/*.sh "$TEST_STAGING/"
    chmod +x "$TEST_STAGING"/*.sh

    # Create a fixture file in a NON-whitelisted directory
    mkdir -p /opt/bumblewrap_test
    echo "SECRET_OPT_DATA" > /opt/bumblewrap_test/secret.txt
    chmod 644 /opt/bumblewrap_test/secret.txt
}

# ── Cleanup (runs on EXIT) ───────────────────────────────────────────────
cleanup() {
    if [[ -n "${DAEMON_PID:-}" ]]; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -rf /opt/bumblewrap_test "$TEST_STAGING" "$RESULTS_DIR"
}
trap cleanup EXIT

# ── Main ──────────────────────────────────────────────────────────────────
setup

echo "=== Bumblewrap Sandbox Test Suite ==="
echo ""
echo "Setting up daemon (BPF compilation may take a moment) ..."

cd "$PROJECT_DIR"
python3 cgroups_daemon.py bash "$TEST_STAGING/run_all.sh" > /dev/null 2>&1 &
DAEMON_PID=$!

# Wait for the DONE marker (timeout 120s — BPF compilation can be slow)
TIMEOUT=120
while [[ ! -f "$RESULTS_DIR/DONE" ]] && [[ $TIMEOUT -gt 0 ]]; do
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo ""
        die "daemon exited before tests finished"
    fi
    sleep 1
    TIMEOUT=$((TIMEOUT - 1))
done

if [[ ! -f "$RESULTS_DIR/DONE" ]]; then
    echo ""
    die "tests timed out after 120 seconds"
fi

# ── Collect results ───────────────────────────────────────────────────────
PASSED=0
FAILED=0
TOTAL=0

for result_file in "$RESULTS_DIR"/test_*; do
    [[ -f "$result_file" ]] || continue
    test_name=$(basename "$result_file")
    result=$(cat "$result_file")
    TOTAL=$((TOTAL + 1))

    if [[ "$result" == "PASS" ]]; then
        printf "  \033[32mPASS\033[0m  %s\n" "$test_name"
        PASSED=$((PASSED + 1))
    else
        detail="${result#FAIL:}"
        printf "  \033[31mFAIL\033[0m  %s — %s\n" "$test_name" "$detail"
        FAILED=$((FAILED + 1))
    fi
done

echo ""
echo "Results: $PASSED passed, $FAILED failed (out of $TOTAL)"

# Kill the daemon now that we're done
kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""

[[ $FAILED -eq 0 ]] && exit 0 || exit 1
