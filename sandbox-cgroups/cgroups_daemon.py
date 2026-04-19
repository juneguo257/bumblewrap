import sys
from bcc import BPF
import ctypes as ct
import os
import subprocess
import random
import time
from typing import Dict, Iterable, List

SLEEP_TIME = 1

bpf_pid_hash = None

class sandbox_params(ct.Structure):
    _fields_ = [("t", ct.c_uint64)]

class sandbox_config:
    """
    Tracks allow/deny path policies similar to sandbox.py and provides
    stubs for syncing rules into BPF maps.
    """

    def __init__(self, allow_paths: Iterable[str] | None = None, deny_paths: Iterable[str] | None = None) -> None:
        self._path_rules: Dict[str, int] = {}
        if allow_paths:
            self.allow_paths(allow_paths)
        if deny_paths:
            self.deny_paths(deny_paths)

    @staticmethod
    def parse_whitelist(filepath: str) -> List[str]:
        paths: List[str] = []
        with open(filepath) as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                paths.append(line)
        return paths

    def allow_paths(self, paths: Iterable[str]) -> None:
        for path in paths:
            self.allow_path(path)

    def deny_paths(self, paths: Iterable[str]) -> None:
        for path in paths:
            self.deny_path(path)

    def allow_path(self, path: str) -> None:
        for variant in self._expand_path_variants(path):
            self._path_rules[variant] = 1
            self._bpf_add_or_update_path(variant, 1)

    def deny_path(self, path: str) -> None:
        for variant in self._expand_path_variants(path):
            self._path_rules[variant] = 0
            self._bpf_add_or_update_path(variant, 0)

    def remove_path(self, path: str) -> None:
        for variant in self._expand_path_variants(path):
            if variant in self._path_rules:
                del self._path_rules[variant]
            self._bpf_remove_path(variant)

    def list_paths(self) -> str:
        lines: List[str] = []
        for path, value in self._path_rules.items():
            tag = "ALLOW" if value == 1 else " DENY"
            lines.append(f"  {tag}  {path}")
        lines.sort()
        return "\n".join(lines) if lines else "  (empty)"

    def _expand_path_variants(self, path: str) -> List[str]:
        if path.endswith("/") and len(path) > 1:
            return [path, path.rstrip("/")]
        return [path]

    def create_sandbox_params(self) -> sandbox_params:
        # Stub for BPF map integration.
        raise NotImplementedError()

    def _bpf_add_or_update_path(self, path: str, value: int) -> None:
        if self.file_list_index is None:
            return
        # Stub for BPF map integration.
        raise NotImplementedError()

    def _bpf_remove_path(self, path: str) -> None:
        if self.file_list_index is None:
            return
        # Stub for BPF map integration.
        raise NotImplementedError()


# creates a cgroup and returns the cgroup path
def create_cgroup(program_to_run: List[str], params: sandbox_params) -> str:
    # -d means use the callers cwd ??? i dunno actually
    # --slice=machine.slice means run the scope in the machine.slice slice (used for containers)
    # --unit=<NAME> specifies the unit name

    unit_name = f"bumblewrap_container_{random.randint(0, 18446744073709551615)}.scope"

    # create pipes
    (read_fd_1, write_fd_1) = os.pipe()
    os.set_inheritable(write_fd_1, True)

    (read_fd_2, write_fd_2) = os.pipe()
    os.set_inheritable(read_fd_2, True)

    # run process
    subprocess.Popen(["systemd-run", "--slice=machine.slice", f"--unit={unit_name}", "--scope", "python3", "cgroup_harness.py", f"{write_fd_1}", f"{read_fd_2}"] + program_to_run, close_fds=False)

    # close unnecessary file descriptors
    os.close(read_fd_2)
    os.close(write_fd_1)

    # recieve pid from child process
    pid = 0
    with os.fdopen(read_fd_1, 'r') as read_pipe:
        pid = int(read_pipe.read())

    # add pid to the pid hash map
    bpf_pid_hash.items_update_batch((ct.c_uint64 * 1)(ct.c_uint64(pid)), (sandbox_params * 1)(params))

    # signal to child process to continue
    os.close(write_fd_2)
    
    return f"machine.slice/{unit_name}"


def main():
    global bpf_pid_hash
    kernel_release = subprocess.check_output(["uname", "-r"]).decode().strip()
    b = BPF(src_file = "cgroups.c", cflags=["-I/usr/lib/modules/6.19.11-arch1-1/build/include", f"-I/usr/src/linux-headers-{kernel_release}/include"])
    fnname_openat = b.get_syscall_prefix().decode() + 'openat'
    b.attach_kprobe(event=fnname_openat, fn_name="syscall__openat")
    b.attach_kprobe(event=b.get_syscall_prefix().decode() + 'execve', fn_name="syscall__execve")

    bpf_pid_hash = b["pid_to_params"]
    print(bpf_pid_hash)

    create_cgroup(["echo", "\"100\""], sandbox_params(t = ct.c_uint64(1)))
    b.trace_print()

if __name__ == "__main__":
    main()

