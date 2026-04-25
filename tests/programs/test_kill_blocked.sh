#!/usr/bin/env bash
# The daemon removes "kill" from the allowed syscall set, so sending any
# signal (even signal 0 to ourselves) should fail with EACCES.
if kill -0 $$ 2>/dev/null; then
    echo "FAIL:kill syscall was not blocked"
else
    echo "PASS"
fi
