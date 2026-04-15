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

class abstract_sandbox_param:
    def add_to_params(self, params: sandbox_params):
        """
        adds this parameter to the sandbox_params
        """
        raise NotImplementedError()
    
    def is_subset_of(self, other_param) -> bool:
        """
        Whether this sandbox param object is a subset of the provided sandbox param object
        """ 
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
    b = BPF(src_file = "cgroups.c", cflags=["-I/usr/lib/modules/6.19.11-arch1-1/build/include"])
    fnname_openat = b.get_syscall_prefix().decode() + 'openat'
    b.attach_kprobe(event=fnname_openat, fn_name="syscall__openat")
    b.attach_kprobe(event=b.get_syscall_prefix().decode() + 'execve', fn_name="syscall__execve")

    bpf_pid_hash = b["pid_to_params"]
    print(bpf_pid_hash)

    create_cgroup(["echo", "\"100\""], sandbox_params(t = ct.c_uint64(1)))
    b.trace_print()

if __name__ == "__main__":
    main()

