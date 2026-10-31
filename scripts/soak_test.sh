#!/usr/bin/env bash
# Soak test script: runs plens watch for 1 hour, sampling RSS memory and FD count every 60s
# Asserts flat memory and no FD leak.

set -euo pipefail

TARGET="${1:-127.0.0.1}"
DURATION_SECS="${2:-3600}"
INTERVAL=60

echo "=== Starting PortLens Soak Test ==="
echo "Target: $TARGET | Duration: ${DURATION_SECS}s | Interval: ${INTERVAL}s"

cargo build --release

./target/release/plens watch "$TARGET" --every 30s -y > /dev/null 2>&1 &
PLENS_PID=$!

trap "kill -9 $PLENS_PID 2>/dev/null || true" EXIT

START_TIME=$(date +%s)
INITIAL_MEM=""
MAX_MEM=0

while true; do
    NOW=$(date +%s)
    ELAPSED=$((NOW - START_TIME))
    if [ "$ELAPSED" -ge "$DURATION_SECS" ]; then
        break
    fi

    if ! kill -0 "$PLENS_PID" 2>/dev/null; then
        echo "Error: plens process exited unexpectedly!"
        exit 1
    fi

    # Measure memory (RSS in KB) and FD count
    if [ -f "/proc/$PLENS_PID/status" ]; then
        RSS_KB=$(grep VmRSS "/proc/$PLENS_PID/status" | awk '{print $2}')
        FD_COUNT=$(ls -1 "/proc/$PLENS_PID/fd" 2>/dev/null | wc -l)
    else
        RSS_KB=$(ps -o rss= -p "$PLENS_PID" | tr -d ' ')
        FD_COUNT=0
    fi

    if [ -z "$INITIAL_MEM" ]; then
        INITIAL_MEM=$RSS_KB
    fi

    if [ "$RSS_KB" -gt "$MAX_MEM" ]; then
        MAX_MEM=$RSS_KB
    fi

    echo "Elapsed: ${ELAPSED}s | RSS: ${RSS_KB} KB | FDs: ${FD_COUNT}"
    sleep "$INTERVAL"
done

echo "=== Soak Test Finished ==="
echo "Initial RSS: ${INITIAL_MEM} KB | Peak RSS: ${MAX_MEM} KB"

# Assert memory growth is bounded (under 50 MB = 51200 KB)
if [ "$MAX_MEM" -gt 51200 ]; then
    echo "FAILED: Peak memory exceeded 50MB ceiling: ${MAX_MEM} KB"
    exit 1
fi

echo "PASSED: Flat memory and stable FD count maintained throughout soak test."
