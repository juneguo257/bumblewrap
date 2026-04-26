import sys
from bcc import BPF
import ctypes as ct
import os
import socket
import subprocess
import random
import threading
import time
from typing import Dict, Iterable, List, Optional
from pathlib import Path
from constants import patched_syscalls, bumblewrap_socket_path as SOCK_PATH

SLEEP_TIME = 1

bpf_pid_hash = None
last_file_list_index = 0

pid_to_cgroups_hash = None

cgid_map: dict[int, int] = {}

curr_idx = 0

containers: dict[int, dict] = {}
containers_lock = threading.Lock()

class sandbox_params(ct.Structure):
    _fields_ = [
        ("file_list_index", ct.c_uint64),
        ("syscall_filter0", ct.c_uint64),
        ("syscall_filter1", ct.c_uint64),
        ("syscall_filter2", ct.c_uint64),
        ("syscall_filter3", ct.c_uint64),
        ("syscall_filter4", ct.c_uint64),
        ("syscall_filter5", ct.c_uint64),
    ]

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
        self._bpf = None
        self.file_list_index: int | None = None
        self.file_list_table = None
        if allow_paths:
            self.allow_paths(allow_paths)
        if deny_paths:
            self.deny_paths(deny_paths)
        self.syscall_filter = set(patched_syscalls)

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

    def _setup_file_list(self, bpf: BPF):
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

    def _create_params(self) -> sandbox_params:
        syscall_bitsets = [0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF]
        for i, syscall in enumerate(patched_syscalls):
            if syscall not in self.syscall_filter:
                bit_index = i % 64
                array_index = i // 64
                syscall_bitsets[array_index] &= ~(1 << bit_index)

        return sandbox_params(
            file_list_index=ct.c_uint64(self.file_list_index),
            syscall_filter0=ct.c_uint64(syscall_bitsets[0]),
            syscall_filter1=ct.c_uint64(syscall_bitsets[1]),
            syscall_filter2=ct.c_uint64(syscall_bitsets[2]),
            syscall_filter3=ct.c_uint64(syscall_bitsets[3]),
            syscall_filter4=ct.c_uint64(syscall_bitsets[4]),
            syscall_filter5=ct.c_uint64(syscall_bitsets[5]),
        )

    def install(self, bpf: BPF, pid: int) -> None:
        self._setup_file_list(bpf)

        global bpf_pid_hash        
        bpf_pid_hash[ct.c_uint64(pid)] = self._create_params()

        self._bpf = bpf
        
    def update(self, cgid: int) -> None:
        self._bpf["sandboxed_cgroups"][ct.c_uint64(cgid)] = self._create_params()

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
    
    def allow_syscall(self, syscall: str) -> None:
        if syscall in patched_syscalls:
            self.syscall_filter.add(syscall)
        else:
            raise ValueError(f"syscall {syscall} is not in the patched syscall list")
    
    def deny_syscall(self, syscall: str) -> None:
        if syscall in patched_syscalls:
            self.syscall_filter.discard(syscall)
        else:
            raise ValueError(f"syscall {syscall} is not in the patched syscall list")


# creates a cgroup and returns the cgroup path
def create_cgroup(b: BPF, program_to_run: List[str], config: sandbox_config) -> str:
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
    config.install(b, pid)

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


HELP_TEXT = """\
commands:
  containers                      list active sandboxed containers
  list <id>                       list path rules for a container
  allow <id> <path>               add allow rule
  deny <id> <path>                add deny rule (overrides parent allow)
  remove <id> <path>              remove a rule
  syscall allow <id> <syscall>    allow a syscall
  syscall deny <id> <syscall>     deny a syscall
  syscall list <id>               list allowed syscalls for a container
  help                            show this help"""


def _parse_container_id(token: str) -> int:
    return int(token)


def _handle_command(cmd: str) -> str:
    parts = cmd.strip().split(None, 2)
    if not parts:
        return "ERROR: empty command"

    action = parts[0].lower()

    if action in ("help", "-h", "--help"):
        return HELP_TEXT

    if action == "containers":
        with containers_lock:
            if not containers:
                return "(no active containers)"
            lines = [f"{'ID':<4} {'CGID':<22} {'PROGRAM':<20} UNIT"]
            for cid, info in sorted(containers.items()):
                program = " ".join(info.get("program", []))
                lines.append(
                    f"{cid:<4} {info['cgid']:<22} {program:<20} {info['unit_name']}"
                )
            return "\n".join(lines)

    if action == "list":
        if len(parts) < 2:
            return "ERROR: usage: list <id>"
        try:
            cid = _parse_container_id(parts[1])
        except ValueError:
            return f"ERROR: invalid container id: {parts[1]}"
        with containers_lock:
            info = containers.get(cid)
        if info is None:
            return f"ERROR: container {cid} not found"
        return f"rules for container {cid}:\n{info['config'].list_paths()}"

    if action in ("allow", "deny", "remove"):
        if len(parts) < 3:
            return f"ERROR: usage: {action} <id> <path>"
        try:
            cid = _parse_container_id(parts[1])
        except ValueError:
            return f"ERROR: invalid container id: {parts[1]}"
        path = parts[2].strip()
        if not path:
            return "ERROR: empty path"
        with containers_lock:
            info = containers.get(cid)
        if info is None:
            return f"ERROR: container {cid} not found"
        config = info["config"]
        if action == "allow":
            config.allow_path(path)
            return f"ALLOWED: {path} (container {cid})"
        if action == "deny":
            config.deny_path(path)
            return f"DENIED:  {path} (container {cid})"
        config.remove_path(path)
        return f"REMOVED: {path} (container {cid})"

    if action == "syscall":
        parts = cmd.strip().split(None, 3)
        subaction = parts[1].lower() if len(parts) > 1 else ""
        if subaction not in ("allow", "deny", "list") or len(parts) < 3:
            return "ERROR: usage: syscall <allow|deny|list> <id> [syscall]"
        try:
            cid = _parse_container_id(parts[2])
        except ValueError:
            return f"ERROR: invalid container id: {parts[2]}"
        with containers_lock:
            info = containers.get(cid)
        if info is None:
            return f"ERROR: container {cid} not found"
        config = info["config"]
        if subaction == "list":
            if len(parts) < 3:
                return "ERROR: usage: syscall list <id>"
            try:
                cid = _parse_container_id(parts[2])
            except ValueError:
                return f"ERROR: invalid container id: {parts[2]}"
            with containers_lock:
                info = containers.get(cid)
            if info is None:
                return f"ERROR: container {cid} not found"
            config = info["config"]
            allowed_syscalls = sorted(config.syscall_filter)
            if not allowed_syscalls:
                return f"(no allowed syscalls for container {cid})"
            return f"allowed syscalls for container {cid}:\n  " + "\n  ".join(allowed_syscalls)
        if len(parts) < 4:
            return f"ERROR: usage: syscall {subaction} <id> <syscall>"
        syscall = parts[3].strip()
        if not syscall:
            return "ERROR: empty syscall"
        try:
            if subaction == "allow":
                config.allow_syscall(syscall)
                config.update(info["cgid"])
                return f"ALLOWED: {syscall} (container {cid})"
            else:
                config.deny_syscall(syscall)
                config.update(info["cgid"])
                return f"DENIED:  {syscall} (container {cid})"
        except ValueError as exc:
            return f"ERROR: {exc}"

    return f"ERROR: unknown command: {action!r}  (try 'help')"


def _cleanup_socket() -> None:
    try:
        os.unlink(SOCK_PATH)
    except FileNotFoundError:
        pass


def control_server() -> None:
    """Accept Unix-socket connections and dispatch sandbox control commands."""
    _cleanup_socket()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(SOCK_PATH)
    os.chmod(SOCK_PATH, 0o666)
    sock.listen(8)

    while True:
        try:
            conn, _ = sock.accept()
        except OSError:
            break

        with conn:
            try:
                chunks = []
                while True:
                    buf = conn.recv(4096)
                    if not buf:
                        break
                    chunks.append(buf)
                    if b"\n" in buf:
                        break
                cmd = b"".join(chunks).decode(errors="replace").strip()
                response = _handle_command(cmd) if cmd else "ERROR: empty command"
            except Exception as exc:
                response = f"ERROR: {exc}"

            try:
                conn.sendall((response + "\n").encode())
            except OSError:
                pass


def launch_container(b: BPF, program: List[str], baseline_paths: List[str]) -> int:
    """Create a sandboxed cgroup running `program` and register it."""
    config = sandbox_config(allow_paths=baseline_paths)
    config.syscall_filter.difference_update(["kill", "rename", "renameat", "renameat2", "symlink", "symlinkat", "link", "linkat"])

    container_id = curr_idx  # snapshot before create_cgroup increments it
    cgroup_path = create_cgroup(b, program, config)
    cgid = cgid_map[container_id]
    unit_name = cgroup_path.split("/", 1)[1] if "/" in cgroup_path else cgroup_path

    with containers_lock:
        containers[container_id] = {
            "config": config,
            "cgid": cgid,
            "unit_name": unit_name,
            "program": list(program),
        }
    return container_id


def main():
    global bpf_pid_hash
    global pid_to_cgroups_hash
    kernel_release = subprocess.check_output(["uname", "-r"]).decode().strip()
    with open("cgroups.c") as src_file:
        bpf_text = src_file.read()
    
    for i, syscall in enumerate(patched_syscalls):
        array_index = i // 64
        bit_index = i % 64
        bpf_text += "\n"
        bpf_text += """
            int syscall_dyn_{syscall}(struct pt_regs *ctx) {
                struct sandbox_params_t *params = get_current_sandbox_params();
                if (!params) return 0;

                if ((params->syscall_filter{array_index} & (1ULL << {bit_index})) == 0) {
                    bpf_trace_printk("blocked syscall {syscall}!");
                    bpf_override_return(ctx, -EACCES);
                }

                return 0;
            }
        """.replace("{syscall}", syscall).replace("{array_index}", str(array_index)).replace("{bit_index}", str(bit_index))

    b = BPF(text=bpf_text, cflags=["-I/usr/lib/modules/6.19.11-arch1-1/build/include", f"-I/usr/src/linux-headers-{kernel_release}/include"])
    prefix = b.get_syscall_prefix().decode()
    b.attach_kprobe(event=prefix + "openat", fn_name="syscall__openat")
    b.attach_kprobe(event=prefix + 'execve', fn_name="syscall__execve")
    for syscall in patched_syscalls:
        try:
            b.attach_kprobe(event=prefix + syscall, fn_name=f"syscall_dyn_{syscall}")
        except Exception:
            print(f"[warn] skipping unavailable syscall: {syscall}")

    bpf_pid_hash = b["pid_to_params"]
    pid_to_cgroups_hash = b["pid_to_cgroups"]

    baseline = sandbox_config.parse_whitelist(
        (Path(__file__).parent / "whitelist.txt").resolve()
    )
    baseline.append(str((Path(__file__).parent / "cgroup_harness2.py").resolve()))

    program = sys.argv[1:] if len(sys.argv) > 1 else ["sh"]
    cid = launch_container(b, program, baseline)

    ctl_thread = threading.Thread(target=control_server, daemon=True)
    ctl_thread.start()

    info = containers[cid]
    print(
        f"[daemon] container {cid} running '{' '.join(program)}' "
        f"(cgid={info['cgid']}, unit={info['unit_name']})"
    )
    print(f"[daemon] control socket: {SOCK_PATH}")
    print("[daemon] run `sudo python3 cgroupctl.py ...` in another terminal to update rules")

    try:
        b.trace_print()
    except KeyboardInterrupt:
        print("\n[daemon] shutting down")
    finally:
        _cleanup_socket()

if __name__ == "__main__":
    main()

