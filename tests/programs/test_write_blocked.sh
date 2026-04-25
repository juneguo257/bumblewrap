#!/usr/bin/env bash
# Attempt to write to a non-whitelisted directory. The sandbox should block this.
if echo "pwned" > /opt/bumblewrap_test/output.txt 2>/dev/null; then
    echo "FAIL:write succeeded to non-whitelisted path /opt/bumblewrap_test/output.txt"
else
    echo "PASS"
fi
