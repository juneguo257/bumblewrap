#!/usr/bin/env bash
# Attempt to read a file outside the whitelist. The sandbox should block this.
if content=$(cat /opt/bumblewrap_test/secret.txt 2>&1); then
    echo "FAIL:read succeeded on non-whitelisted path, got: $content"
else
    echo "PASS"
fi
