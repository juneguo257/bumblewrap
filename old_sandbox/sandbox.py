#!/usr/bin/env python3
"""
Bumblewrap Sandbox (Milestone 3)

Sets up an eBPF-based sandbox with whitelist-based file access control,
then runs an interactive bash shell under the sandbox.  Only absolute
paths listed in the whitelist (or under a whitelisted directory prefix)
are accessible.  Relative paths are resolved via a best-effort CWD walk.

While the sandbox is running, rules can be modified dynamically via the
companion tool sandboxctl.py (which writes commands to a named FIFO).

Usage:
    sudo python3 sandbox.py [whitelist_file]
"""

import os
import sys
import signal
import threading
import subprocess
import ctypes as ct
from bcc import BPF

CTL_FIFO = "/tmp/bumblewrap_ctl"
RESP_FILE = "/tmp/bumblewrap_resp"


# bpf map helpers

def add_path_to_map(allowed_table, path, value):
    """Insert a path into the BPF map.  value: 1 = allow, 0 = deny."""
    key = allowed_table.Key()
    key.path = path.encode()
    allowed_table[key] = ct.c_uint32(value)

    if path.endswith("/") and len(path) > 1:
        key2 = allowed_table.Key()
        key2.path = path.rstrip("/").encode()
        allowed_table[key2] = ct.c_uint32(value)


def remove_path_from_map(allowed_table, path):
    """Delete a path (and its no-trailing-slash variant) from the BPF map."""
    key = allowed_table.Key()
    key.path = path.encode()
    try:
        del allowed_table[key]
    except KeyError:
        pass

    if path.endswith("/") and len(path) > 1:
        key2 = allowed_table.Key()
        key2.path = path.rstrip("/").encode()
        try:
            del allowed_table[key2]
        except KeyError:
            pass


def list_paths(allowed_table):
    """Return a sorted, human-readable listing of every map entry."""
    lines = []
    for key, value in allowed_table.items():
        path = key.path.decode("utf-8", errors="replace").rstrip("\x00")
        tag = "ALLOW" if value.value == 1 else " DENY"
        lines.append(f"  {tag}  {path}")
    lines.sort()
    return "\n".join(lines) if lines else "  (empty)"


# whitelist helpers

def parse_whitelist(filepath):
    paths = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            paths.append(line)
    return paths


def populate_whitelist(b, paths):
    allowed = b.get_table("allowed_paths")
    count = 0
    for path in paths:
        add_path_to_map(allowed, path, 1)
        count += 1
        if path.endswith("/") and len(path) > 1:
            count += 1
    return count


# control loop (runs in a separate thread)

def control_loop(b):
    """Read newline-delimited commands from CTL_FIFO and modify BPF maps.

    Supported commands (case-insensitive):
        allow  <path>   — add path as allowed (value 1)
        deny   <path>   — add path as denied  (value 0, overrides parent allow)
        remove <path>   — delete path from map entirely
        list            — dump current rules to RESP_FILE + stdout
    """
    allowed = b.get_table("allowed_paths")

    while True:
        try:
            # open() blocks until a writer connects
            with open(CTL_FIFO, "r") as fifo:
                for raw_line in fifo:
                    line = raw_line.strip()
                    if not line:
                        continue
                    parts = line.split(None, 1)
                    action = parts[0].lower()
                    path = parts[1] if len(parts) > 1 else ""

                    if action == "allow" and path:
                        add_path_to_map(allowed, path, 1)
                        msg = f"ALLOWED: {path}"
                    elif action == "deny" and path:
                        add_path_to_map(allowed, path, 0)
                        msg = f"DENIED:  {path}"
                    elif action == "remove" and path:
                        remove_path_from_map(allowed, path)
                        msg = f"REMOVED: {path}"
                    elif action == "list":
                        listing = list_paths(allowed)
                        msg = f"Current rules:\n{listing}"
                        try:
                            with open(RESP_FILE, "w") as rf:
                                rf.write(listing + "\n")
                        except OSError:
                            pass
                    else:
                        msg = f"Unknown command: {line}"

                    print(f"\n[sandbox] {msg}", flush=True)
        except OSError:
            break
        except Exception as e:
            print(f"\n[sandbox] Control error: {e}", flush=True)

def cleanup_fifo():
    for p in (CTL_FIFO, RESP_FILE):
        try:
            os.unlink(p)
        except OSError:
            pass


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

    kernel_release = subprocess.check_output(["uname", "-r"]).decode().strip()
    header_dir = f"/usr/src/linux-headers-{kernel_release}/include"

    print(f"Loading eBPF sandbox program (kernel {kernel_release})...")
    b = BPF(text=bpf_text, cflags=[f"-I{header_dir}"])

    fnname = b.get_syscall_prefix().decode() + "openat"
    b.attach_kprobe(event=fnname, fn_name="syscall__openat")

    count = populate_whitelist(b, whitelist)
    print(f"Loaded {count} whitelist entries from {whitelist_file}")

    # ---- control FIFO ----
    cleanup_fifo()
    os.mkfifo(CTL_FIFO)

    ctl_thread = threading.Thread(target=control_loop, args=(b,), daemon=True)
    ctl_thread.start()

    # ---- fork sandboxed shell ----
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

        os.write(write_fd, b"x")
        os.close(write_fd)

        print(f"Sandbox active for PID {child_pid} and its children")
        print(f"Access restricted to {len(whitelist)} whitelisted path prefixes")
        print(f"Control FIFO: {CTL_FIFO}")
        print("Use sandboxctl.py in another terminal to modify rules at runtime.")
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

        cleanup_fifo()
        print("Sandbox stopped.")


if __name__ == "__main__":
    main()
