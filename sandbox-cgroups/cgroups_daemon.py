import sys
from bcc import BPF
import ctypes as ct
import os
import subprocess
import random
import time

SLEEP_TIME = 1

bpf_pid_hash = None

class sandbox_params(ct.Structure):
    _fields_ = [("t", ct.c_uint64)]

# creates a cgroup and returns the cgroup path
def create_cgroup(program_to_run: List[str]) -> str:
    # -d means use the callers cwd ??? i dunno actually
    # --slice=machine.slice means run the scope in the machine.slice slice (used for containers)
    # --unit=<NAME> specifies the unit name

    unit_name = f"bumblewrap_container_{random.randint(0, 18446744073709551615)}.scope"

    subprocess.Popen(["systemd-run", "--slice=machine.slice", f"--unit={unit_name}", "--scope", "python3", "cgroup_harness.py"] + program_to_run)

    time.sleep(0.5)

    # get pid of cgroup_harness process
    f = open(f"/sys/fs/cgroup/machine.slice/{unit_name}/cgroup.procs", "r")
    pid = int(f.readline())
    f.close()

    # add pid to the pid hash map
    params = sandbox_params(t = ct.c_uint64(1))
    bpf_pid_hash.items_update_batch((ct.c_uint64 * 1)(ct.c_uint64(pid)), (sandbox_params * 1)(params))


    return f"machine.slice/{unit_name}"


def main():
    global bpf_pid_hash
    b = BPF(src_file = "cgroups.c", cflags=["-I/usr/lib/modules/6.19.11-arch1-1/build/include"])
    fnname_openat = b.get_syscall_prefix().decode() + 'openat'
    b.attach_kprobe(event=fnname_openat, fn_name="syscall__openat")
    b.attach_kprobe(event=b.get_syscall_prefix().decode() + 'execve', fn_name="syscall__execve")

    bpf_pid_hash = b["pid_to_params"]
    print(bpf_pid_hash)

    create_cgroup(["echo", "\"100\""])
    b.trace_print()

if __name__ == "__main__":
    main()

