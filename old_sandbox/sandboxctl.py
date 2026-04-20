#!/usr/bin/env python3
"""
Bumblewrap Sandbox Controller

Sends commands to a running bumblewrap sandbox to dynamically modify
its file-access rules while the sandboxed process is still running.

Usage:
    sudo python3 sandboxctl.py allow  /path/to/dir/
    sudo python3 sandboxctl.py deny   /path/to/dir/
    sudo python3 sandboxctl.py remove /path/
    sudo python3 sandboxctl.py list
"""

import os
import sys
import time

CTL_FIFO = "/tmp/bumblewrap_ctl"
RESP_FILE = "/tmp/bumblewrap_resp"


def usage():
    print("Usage: sudo python3 sandboxctl.py <command> [path]")
    print()
    print("Commands:")
    print("  allow  <path>  Whitelist a path (make it accessible)")
    print("  deny   <path>  Blacklist a path (block it, overrides parent allow)")
    print("  remove <path>  Delete a path from all rules")
    print("  list           Show all current rules")
    print()
    print("Paths ending with '/' are directory prefixes (match everything under them).")
    print("Other paths are exact-match entries.")
    sys.exit(1)


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        usage()

    action = sys.argv[1].lower()

    if action in ("allow", "deny", "remove"):
        if len(sys.argv) < 3:
            print(f"Error: '{action}' requires a path argument")
            sys.exit(1)
        path = sys.argv[2]
        cmd = f"{action} {path}"
    elif action == "list":
        cmd = "list"
    else:
        print(f"Unknown command: {action}")
        usage()

    if not os.path.exists(CTL_FIFO):
        print(f"Error: control FIFO not found at {CTL_FIFO}")
        print("Is the sandbox running?  (Start it with: sudo python3 sandbox.py)")
        sys.exit(1)

    with open(CTL_FIFO, "w") as fifo:
        fifo.write(cmd + "\n")

    print(f"Sent: {cmd}")

    if action == "list":
        time.sleep(0.3)
        if os.path.exists(RESP_FILE):
            with open(RESP_FILE) as f:
                content = f.read().strip()
            if content:
                print(content)
        else:
            print("(check the sandbox terminal for output)")


if __name__ == "__main__":
    main()
