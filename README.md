# `bumblewrap`

> [!WARNING]
> Bumblewrap and Bumblewrap OS are experimental and **contain numerous security, performance, and stability issues.** They are **not production-grade software** and should not be used as such. Bumblewrap **cannot be relied upon to sandbox untrusted code securely.**

Many mechanisms exist to sandbox processes running on Linux, but current solutions are either limited in what they can support or require virtualizing significant operating system services, which can prevent some use cases. Our goal with `bumblewrap` is to implement a sandboxing solution similar to that offered by [bubblewrap](https://github.com/containers/bubblewrap), but rather than using namespaces or tools like FUSE, we want to use eBPF to provide sandboxing with maximal control and performance.

## Target Users & Use Cases
Our project will be for expert Linux users that want more customization in sandboxing.


Our hope is that our project can act as a tool to resolve many of the current pain points in sandboxing. For example:


* Containerized apps, such as Flatpaks, often need to bundle their own GPU drivers instead of using the ones afforded by the system, or need to rely on virtualized graphics entirely. This creates significant incompatibilities, as the drivers provided by the Flatpak need to match the graphics capabilities of the system.

* Existing systems have limited customizability and can be resource-intensive. For example, Firejail allows users to filter syscalls through seccomp-bpf, but its use of classical BPF prevents users from benefitting from the ease of use and additional power of eBPF.

* Many approaches to sandboxing require upfront knowledge of sandboxing policies, with little ability to adjust things on the fly. For example, Firejail attempts to mount over every blacklisted file path before running a sandboxed process, which restricts its ability to make dynamic sandboxing policy decisions. Current solutions to this problem, like FUSE, present performance tradeoffs that may make them unsuitable for use with critical applications.

* Using eBPF could allow a sandboxed process to use capabilities traditionally difficult to implement in a sandboxed manner, such as nesting namespaces.

## Supported Environments

> [!WARNING]
> We strongly recommend running `bumblewrap` in a virtual machine. Running it on bare metal is untested and may cause unexpected behavior. Running it in a container is unlikely to work.

There are two main environments Bumblewrap supports:

### Bumblewrap OS

The easiest way to try out Bumblewrap is with **Bumblewrap OS**, a minimal Arch Linux-based live image with Bumblewrap pre-installed. To run it, [download the ISO](https://github.com/juneguo257/bumblewrap/releases/download/2026-04-29/bumblewrap-os-2026.04.29-x86_64.iso) and fire it up in your favorite hypervisor. We've tested it on QEMU, but in theory there is no reason it shouldn't work on VirtualBox, Hyper-V, Xen, or similar software.

Bumblewrap OS should run fine with just 4 GB of RAM. It does not use persistent storage, so there is no need to allocate a virtual disk other than the ISO. It comes with a bare-bones version of GNOME 50, Ptyxis as a terminal emulator, and `vim` for text editing.

The Bumblewrap repository is pre-cloned and installed in `/opt/bumblewrap`. To run Bumblewrap, use:
```sh
sudo bumblewrap
```

To control Bumblewrap:
```sh
sudo bumblewrapctl [args]
```

See the **Running `bumblewrap`** section for more specifics on arguments and configuration.

The image is live and does not persist the filesystem across reboots. If you'd like to install additional software regardless, set up `pacman` by running:
```sh
sudo pacman-key --init
sudo pacman-key --populate
sudo pacman -Sy
```

Some software may require you to increase the size of the RAM disk. Instructions on doing so can be found on the [Arch Linux wiki](https://wiki.archlinux.org/title/Archiso#Adjusting_the_size_of_the_root_file_system).

### Ubuntu 26.04

`bumblewrap` runs well on Ubuntu 26.04, but you will need to do either one of two things:

* Add `lsm=landlock,lockdown,yama,integrity,apparmor,bpf` to the kernel's boot arguments
* Use `bumblewrap` without LSM hooks, by checking out the `no-lsm` branch

### Other Distros

`bumblewrap` is not well-tested on other Linux distros, although recent versions of Arch Linux are known to work. You may experience compiler errors if you attempt to run `bumblewrap` on a different distribution.

## Running `bumblewrap`

Once you set your configuration for `bumblewrap` in `whitelist.txt`, run the following command to get put into a shell sandboxed under `bumblewrap`:
```
sudo python3 bumblewrap.py
```

To run a program sandboxed with `bumblewrap`, run:
```
sudo python3 bumblewrap.py [PROGRAM_NAME]
```

`bumblewrap` outputs debug logs via the kernel's tracing system. To display these logs as they are produced, run `sudo cat /sys/kernel/tracing/trace_pipe` in a different terminal.

## bumblewrapctl

`bumblewrapctl.py` allows you to change the permission settings of your sandbox on the fly after initialization! Here are the possible commands:

```
sudo ./bumblewrapctl.py containers
sudo ./bumblewrapctl.py list
sudo ./bumblewrapctl.py allow  /home/user/project/
sudo ./bumblewrapctl.py deny   /etc/shadow
sudo ./bumblewrapctl.py remove /home/user/project/
sudo ./bumblewrapctl.py syscall list
sudo ./bumblewrapctl.py syscall allow kill
sudo ./bumblewrapctl.py syscall deny kill
```

> [!NOTE]
> When adding a directory, make sure the path ends in a trailing slash (e.g. `/home/user/project/`).

There are a few other options to tweak as well-- see `bumblewrapctl.py` for more information.

## Tests

To run the tests, run:
```
sudo bash tests/run_tests.sh
```

For more information, reference `tests/README.md`.

## bumblewrapsh

`demo/bumblewrapsh.c` contains a small wrapper program to run Bumblewrap from an unprivileged environment, intended to be compiled as a setuid binary (this is how we did our live demo). The code assumes that Bumblewrap is cloned in `/opt/bumblewrap`.
