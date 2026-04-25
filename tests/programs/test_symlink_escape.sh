#!/usr/bin/env bash
# Create a symlink inside /tmp/ (whitelisted) pointing to a file outside the
# whitelist. The BPF checker only sees the symlink path, not the resolved
# target, so the open may succeed — revealing a sandbox escape.
LINK="/tmp/bumblewrap_symlink_escape_$$"
ln -sf /opt/bumblewrap_test/secret.txt "$LINK" 2>/dev/null

if content=$(cat "$LINK" 2>&1); then
    rm -f "$LINK"
    echo "FAIL:symlink escape succeeded, read: $content"
else
    rm -f "$LINK"
    echo "PASS"
fi
