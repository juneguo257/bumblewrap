#!/usr/bin/env bash
# Verify that writing to a whitelisted directory (/tmp/) succeeds.
TESTFILE="/tmp/bumblewrap_write_test_$$"
if echo "hello" > "$TESTFILE" 2>&1; then
    rm -f "$TESTFILE"
    echo "PASS"
else
    echo "FAIL:could not write to whitelisted path $TESTFILE"
fi
