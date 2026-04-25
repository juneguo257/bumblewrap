#!/usr/bin/env bash
# Verify that reading a file in a whitelisted directory (/etc/) succeeds.
if cat /etc/passwd >/dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL:could not read whitelisted file /etc/passwd"
fi
