import sys
from bcc import BPF
import ctypes as ct
import os
import subprocess
import random
import time
from typing import Dict, Iterable, List
from pathlib import Path

SLEEP_TIME = 1

bpf_pid_hash = None
last_file_list_index = 0

pid_to_cgroups_hash = None

cgid_map: dict[int, int] = {}

curr_idx = 0

class sandbox_params(ct.Structure):
    _fields_ = [("file_list_index", ct.c_uint64)]

class sandbox_config:
    """
    Tracks allow/deny path policies similar to sandbox.py and provides
    stubs for syncing rules into BPF maps.
    """

    def __init__(
        self,
        allow_paths: Iterable[str] | None = None,
        deny_paths: Iterable[str] | None = None,
    ) -> None:
        self._path_rules: Dict[str, int] = {}
        self.file_list_index: int | None = None
        self.file_list_table = None
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

    def create_sandbox_params(self, bpf: BPF) -> sandbox_params:
        global last_file_list_index
        if last_file_list_index >= 16:
            raise IndexError("oops! all file lists exhausted")

        self.file_list_index = last_file_list_index
        last_file_list_index += 1

        file_lists_table = bpf.get_table("file_lists")

        self.file_list_table = bpf.get_table(f"file_list{self.file_list_index}")
        file_lists_table[ct.c_uint64(self.file_list_index)] = ct.c_int(self.file_list_table.get_fd())

        for variant, rule in self._path_rules.items():
            self._bpf_add_or_update_path(variant, rule)

        return sandbox_params(file_list_index=ct.c_uint64(self.file_list_index))

    def _bpf_add_or_update_path(self, path: str, value: int) -> None:
        if self.file_list_table is None:
            return
        key = self.file_list_table.Key()
        key.path = path.encode()
        self.file_list_table[key] = ct.c_uint32(value)

    def _bpf_remove_path(self, path: str) -> None:
        if self.file_list_table is None:
            return
        key = self.file_list_table.Key()
        key.path = path.encode()
        try:
            del self.file_list_table[key]
        except KeyError:
            pass


# creates a cgroup and returns the cgroup path
def create_cgroup(program_to_run: List[str], params: sandbox_params) -> str:
    global curr_idx
    # -d means use the callers cwd ??? i dunno actually
    # --slice=machine.slice means run the scope in the machine.slice slice (used for containers)
    # --unit=<NAME> specifies the unit name

    unit_name = f"bumblewrap_container_{random.randint(0, 18446744073709551615)}.scope"

    # create pipes
    (read_fd_1, write_fd_1) = os.pipe()
    os.set_inheritable(write_fd_1, True)

    (read_fd_2, write_fd_2) = os.pipe()
    os.set_inheritable(read_fd_2, True)

    (read_fd_3, write_fd_3) = os.pipe()
    os.set_inheritable(write_fd_3, True)

    harness_file = os.path.dirname(os.path.abspath(__file__)) + "/cgroup_harness.py"

    # run process
    subprocess.Popen(["systemd-run", "--slice=machine.slice", f"--unit={unit_name}", "--scope", "python3", harness_file, f"{write_fd_1}", f"{read_fd_2}", f"{write_fd_3}"] + program_to_run, close_fds=False)

    # close unnecessary file descriptors
    os.close(read_fd_2)
    os.close(write_fd_1)
    os.close(write_fd_3)

    # recieve pid from child process
    pid = 0
    with os.fdopen(read_fd_1, 'r') as read_pipe:
        pid = int(read_pipe.read())

    # add pid to the pid hash map
    bpf_pid_hash.items_update_batch((ct.c_uint64 * 1)(ct.c_uint64(pid)), (sandbox_params * 1)(params))

    # signal to child process to continue
    os.close(write_fd_2)

    with os.fdopen(read_fd_3, 'r') as read_pipe:
        read_pipe.read()
    
    # pid -> cgroup
    cgid = int(pid_to_cgroups_hash[ct.c_uint64(pid)].value)

    cgid_map[curr_idx] = cgid

    curr_idx += 1

    print(cgid)

    
    return f"machine.slice/{unit_name}"


def main():
    global bpf_pid_hash
    global pid_to_cgroups_hash
    kernel_release = subprocess.check_output(["uname", "-r"]).decode().strip()
    b = BPF(src_file = "cgroups.c", cflags=["-I/usr/lib/modules/6.19.11-arch1-1/build/include", f"-I/usr/src/linux-headers-{kernel_release}/include"])
    fnname_openat = b.get_syscall_prefix().decode() + 'openat'
    b.attach_kprobe(event=fnname_openat, fn_name="syscall__openat")
    b.attach_kprobe(event=b.get_syscall_prefix().decode() + 'execve', fn_name="syscall__execve")

    bpf_pid_hash = b["pid_to_params"]
    pid_to_cgroups_hash = b["pid_to_cgroups"]
    print(bpf_pid_hash)

    paths = sandbox_config.parse_whitelist((Path(__file__).parent / "whitelist.txt").resolve())
    paths.append(str((Path(__file__).parent / "cgroup_harness2.py").resolve()))
    config = sandbox_config(allow_paths=paths)
    params = config.create_sandbox_params(b)
    create_cgroup(["sh"], params)
    b.trace_print()

if __name__ == "__main__":
    main()

