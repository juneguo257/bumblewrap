#!/usr/bin/env python3
"""Control client for a running bumblewrap.py.

Connects to the daemon's Unix socket and sends commands to dynamically
modify sandbox path rules while the sandboxed shell is still running.

Usage:
    sudo ./bumblewrapctl.py containers
    sudo ./bumblewrapctl.py list
    sudo ./bumblewrapctl.py allow  /home/user/project/
    sudo ./bumblewrapctl.py deny   /etc/shadow
    sudo ./bumblewrapctl.py remove /home/user/project/
    sudo ./bumblewrapctl.py syscall list
    sudo ./bumblewrapctl.py syscall allow kill
    sudo ./bumblewrapctl.py syscall deny kill
    sudo ./bumblewrapctl.py --id 1 list

`--id` defaults to 0 (the initial container spawned by the daemon).
"""
import argparse
import socket
import sys
from constants import bumblewrap_socket_path as SOCK_PATH

RECV_TIMEOUT = 5.0


def send_command(cmd: str) -> str:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(RECV_TIMEOUT)
    try:
        sock.connect(SOCK_PATH)
    except (FileNotFoundError, ConnectionRefusedError) as exc:
        print(
            f"error: could not connect to daemon at {SOCK_PATH}: {exc}",
            file=sys.stderr,
        )
        print("is cgroups_daemon.py running?", file=sys.stderr)
        sys.exit(1)

    try:
        sock.sendall((cmd + "\n").encode())
        sock.shutdown(socket.SHUT_WR)

        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    finally:
        sock.close()

    return b"".join(chunks).decode(errors="replace")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Dynamically modify sandbox rules in a running cgroups_daemon.",
    )
    p.add_argument(
        "--id",
        type=int,
        default=0,
        dest="container_id",
        help="container id to operate on (default: 0)",
    )
    sub = p.add_subparsers(dest="action", required=True)

    sub.add_parser("containers", help="list all active sandboxed containers")
    sub.add_parser("list", help="list path rules for a container")

    for name, desc in (
        ("allow", "whitelist a path (make it accessible)"),
        ("deny", "blacklist a path (overrides parent allow)"),
        ("remove", "delete a path from all rules"),
    ):
        s = sub.add_parser(name, help=desc)
        s.add_argument("path", help="path to apply the rule to")
    
    sub_sys = sub.add_parser("syscall", help="manage syscall rules").add_subparsers(dest="syscall_action", required=True)
    sub_sys.add_parser("list", help="list syscall rules for a container")
    for name, desc in (
        ("allow", "whitelist a syscall (make it accessible)"),
        ("deny", "blacklist a syscall (overrides parent allow)"),
    ):
        s = sub_sys.add_parser(name, help=desc)
        s.add_argument("syscall", help="syscall to apply the rule to")

    return p


def main() -> None:
    args = build_parser().parse_args()

    if args.action == "containers":
        cmd = "containers"
    elif args.action == "list":
        cmd = f"list {args.container_id}"
    elif args.action == "syscall":
        if args.syscall_action == "list":
            cmd = f"syscall list {args.container_id}"
        else:
            cmd = f"syscall {args.syscall_action} {args.container_id} {args.syscall}"
    else:
        cmd = f"{args.action} {args.container_id} {args.path}"

    response = send_command(cmd)
    sys.stdout.write(response)
    if not response.endswith("\n"):
        sys.stdout.write("\n")

    if response.startswith("ERROR:"):
        sys.exit(2)


if __name__ == "__main__":
    main()
