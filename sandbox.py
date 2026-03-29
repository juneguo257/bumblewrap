#!/usr/bin/env python3
"""
Bumblewrap Sandbox (Milestone 2)

Sets up an eBPF-based sandbox with whitelist-based file access control,
then runs an interactive bash shell under the sandbox.  Only absolute
paths listed in the whitelist (or under a whitelisted directory prefix)
are accessible.  Relative paths are not filtered.

Usage:
    sudo python3 sandbox.py [whitelist_file]

The whitelist file defaults to whitelist.txt in the same directory as
this script.  See whitelist.txt for format documentation.
"""

import os
import sys
import signal
import ctypes as ct
from bcc import BPF


def parse_whitelist(filepath):
    """Parse the whitelist file.

    Blank lines and lines starting with '#' are ignored.
    Paths ending with '/' are treated as directory prefixes (everything
    underneath is allowed).  Other paths are exact-match entries.
    """
    paths = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            paths.append(line)
    return paths


def populate_whitelist(b, paths):
    """Insert whitelist entries into the eBPF allowed_paths hash map."""
    allowed = b.get_table("allowed_paths")
    count = 0
    for path in paths:
        key = allowed.Key()
        key.path = path.encode()
        allowed[key] = ct.c_uint32(1)
        count += 1

        # For directory prefixes, also allow accessing the directory node
        # itself without the trailing slash (e.g. openat("/usr", O_DIRECTORY)).
        if path.endswith("/") and len(path) > 1:
            key2 = allowed.Key()
            key2.path = path.rstrip("/").encode()
            allowed[key2] = ct.c_uint32(1)
            count += 1

    return count


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    whitelist_file = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        script_dir, "whitelist.txt"
    )

    if not os.path.exists(whitelist_file):
        print(f"Error: whitelist file '{whitelist_file}' not found")
        sys.exit(1)

    whitelist = parse_whitelist(whitelist_file)
    if not whitelist:
        print(
            "Warning: whitelist is empty — all absolute-path access will be blocked"
        )

    ebpf_path = os.path.join(script_dir, "ebpf_sandbox.c")
    with open(ebpf_path) as f:
        bpf_text = f.read()

    print("Loading eBPF sandbox program...")
    b = BPF(text=bpf_text)

    fnname = b.get_syscall_prefix().decode() + "openat"
    b.attach_kprobe(event=fnname, fn_name="syscall__openat")

    count = populate_whitelist(b, whitelist)
    print(f"Loaded {count} whitelist entries from {whitelist_file}")

    # Pipe used to synchronise: the child waits until the parent has added
    # its PID to the sandboxed_pids map before exec-ing bash.
    read_fd, write_fd = os.pipe()
    child_pid = os.fork()

    if child_pid == 0:
        # ---------- child ----------
        os.close(write_fd)
        os.read(read_fd, 1)
        os.close(read_fd)
        os.environ["PS1"] = "(sandbox) $ "
        os.execvp("bash", ["bash", "--norc", "--noprofile"])
    else:
        # ---------- parent ----------
        os.close(read_fd)

        sandboxed = b.get_table("sandboxed_pids")
        sandboxed[ct.c_uint32(child_pid)] = ct.c_uint32(1)

        # Let the child proceed now that its PID is tracked.
        os.write(write_fd, b"x")
        os.close(write_fd)

        print(f"Sandbox active for PID {child_pid} and its children")
        print(f"Access restricted to {len(whitelist)} whitelisted path prefixes")
        print("Type 'exit' to leave the sandbox.\n")

        try:
            _, status = os.waitpid(child_pid, 0)
        except KeyboardInterrupt:
            print("\nStopping sandbox...")
            try:
                os.kill(child_pid, signal.SIGTERM)
                os.waitpid(child_pid, 0)
            except (ProcessLookupError, ChildProcessError):
                pass

        print("Sandbox stopped.")


if __name__ == "__main__":
    main()
