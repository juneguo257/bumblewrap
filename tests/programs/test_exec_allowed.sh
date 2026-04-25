#!/usr/bin/env bash
# Verify that executing a binary in a whitelisted directory (/bin/) works.
# Uses /tmp rather than / because the root directory itself is not whitelisted.
if /bin/ls /tmp >/dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL:could not execute whitelisted binary /bin/ls"
fi
