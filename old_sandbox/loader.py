# how to run:
# sudo python3 loader.py

import sys
from bcc import BPF
import ctypes as ct

# Helper function to add a secret file to the map
def add_secret_file(map, file):
    key = map.Key()
    key.fname = file[0].encode()
    value = ct.c_int(file[1])
    # Update the map with the new entry
    map[key] = value

def main():
    # get which files to protect
    protection_list = []
    with open("blacklist.txt") as f:
        for line in f.readlines():
            if line and line.split(","):
                file_path, security_level = line.split(",")
                protection_list.append((file_path, int(security_level)))

    # Read BPF Program
    with open("ebpf_program.c") as f:
        bpf_program = f.read()
    # Load BPF program
    b = BPF(text=bpf_program)
    # Attach the kprobe defined in the eBPF program to the clone system call.
    fnname_openat = b.get_syscall_prefix().decode() + 'openat'
    b.attach_kprobe(event=fnname_openat, fn_name="syscall__openat")
    # Get thee map
    secret_files = b.get_table("secret_files")
    # Add the secret files to the map
    for file in protection_list:
        add_secret_file(secret_files, file)
    try:
        print("Attaching kprobe to sys_openat... Press Ctrl+C to exit.")
        b.trace_print()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
