# `bumblewrap`

Many mechanisms exist to sandbox processes running on Linux, but current solutions are either limited in what they can support or require virtualizing significant operating system services, which can prevent some use cases. Our goal with `bumblewrap` is to implement a sandboxing solution similar to that offered by bubblewrap (https://github.com/containers/bubblewrap), but rather than using namespaces or tools like FUSE, we want to use eBPF to provide sandboxing with maximal control and performance.

## Target Users & Use Cases
Our project will be for expert Linux users that want more customization in sandboxing.


Our hope is that our project can act as a tool to resolve many of the current pain points in sandboxing. For example:


Containerized apps, such as Flatpaks, often need to bundle their own GPU drivers instead of using the ones afforded by the system, or need to rely on virtualized graphics entirely. This creates significant incompatibilities, as the drivers provided by the Flatpak need to match the graphics capabilities of the system.

Existing systems have limited customizability and can be resource-intensive. For example, Firejail allows users to filter syscalls through seccomp-bpf, but its use of classical BPF prevents users from benefitting from the ease of use and additional power of eBPF.

Many approaches to sandboxing require upfront knowledge of sandboxing policies, with little ability to adjust things on the fly. For example, Firejail attempts to mount over every blacklisted file path before running a sandboxed process, which restricts its ability to make dynamic sandboxing policy decisions. Current solutions to this problem, like FUSE, present performance tradeoffs that may make them unsuitable for use with critical applications.

Using eBPF could allow a sandboxed process to use capabilities traditionally difficult to implement in a sandboxed manner, such as nesting namespaces.

## Compatability

Due to the `bumblewrap`'s requirements when compiling, running `bumblewrap` may behave across different Linux distributions. Here's the current information we've garnered on compatability:

- Arch Linux - Works
- Ubuntu - Does not work, but works for a build without LSM (see `origin/no-lsm`)

## Running `bumblewrap`

To run `bumblewrap`, set up a **Linux VM** (Arch Linux is proven to work with our bcc requirements, but ymmv).

Once you set your configuration for `bumblewrap` in `whitelist.txt`, run the following command to get put into a shell sandboxed under `bumblewrap`:
```
sudo python3 bumblewrap.py
```

To run a program sandboxed with `bumblewrap`, run:
```
sudo python3 bumblewrap.py [PROGRAM_NAME]
```

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

There are a few other options to tweak as well-- see `bumblewrapctl.py` for more information.

## Tests

To run the tests, run:
```
sudo bash tests/run_tests.sh
```

For more information, reference `tests/README.md`.