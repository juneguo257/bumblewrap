#!/usr/bin/env bash
# Attempt to escape the sandbox using ".." path components.
# /tmp/ is whitelisted, so the BPF checker sees the /tmp/ prefix and allows
# the open — but the kernel resolves ".." and accesses the real target.
if content=$(cat /tmp/../opt/bumblewrap_test/secret.txt 2>&1); then
    echo "FAIL:path traversal escaped sandbox, read: $content"
else
    echo "PASS"
fi
