# Bumblewrap Sandbox Test Suite

Automated tests that run programs inside the eBPF/cgroup sandbox and verify
that access controls are enforced correctly.

## Prerequisites

- Linux with BPF/kprobe support (the same environment used to run `cgroups_daemon.py`)
- `systemd` with `systemd-run` available
- Root privileges

## Running the tests

From the project root:

```bash
sudo bash tests/run_tests.sh
```

The runner will:

1. Stage test scripts under `/tmp/` (a whitelisted path) so the sandbox can access them.
2. Create fixture files in `/opt/bumblewrap_test/` (a **non**-whitelisted path).
3. Start `cgroups_daemon.py` once with a meta-runner as the sandboxed program.
4. Execute every `tests/programs/test_*.sh` script inside the sandbox.
5. Collect results and print a pass/fail summary.
6. Clean up all fixtures and stop the daemon.

Exit code is **0** if all tests pass, **1** otherwise.

## Test inventory

| Test | What it checks |
|------|----------------|
| `test_read_allowed` | Reading `/etc/passwd` (whitelisted) succeeds |
| `test_read_blocked` | Reading `/opt/…/secret.txt` (not whitelisted) is denied |
| `test_write_allowed` | Writing to `/tmp/` (whitelisted) succeeds |
| `test_write_blocked` | Writing to `/opt/…` (not whitelisted) is denied |
| `test_exec_allowed` | Executing `/bin/ls` (whitelisted) succeeds |
| `test_kill_blocked` | `kill` syscall (removed from allowed set by daemon) is denied |
| `test_path_traversal` | Using `..` components (`/tmp/../opt/…`) to escape the whitelist |
| `test_symlink_escape` | Symlinking from `/tmp/` to a non-whitelisted target |

The last two tests probe **known weakness vectors** — if they report FAIL, the
sandbox's BPF path checker is not normalizing paths before comparison.

## Adding a new test

Create `tests/programs/test_<name>.sh`. The script must:

- Print exactly `PASS` (one line) if the expected behaviour is observed.
- Print `FAIL:<reason>` if the sandbox did not behave as expected.
- Finish within 10 seconds (enforced by `timeout`).

The meta-runner (`run_all.sh`) automatically picks up any file matching
`test_*.sh` in the `programs/` directory.
