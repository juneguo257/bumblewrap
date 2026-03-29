#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_PATH_LEN 128

struct path_key_t {
    char path[MAX_PATH_LEN];
};

BPF_HASH(sandboxed_pids, u32, u32);
BPF_HASH(allowed_paths, struct path_key_t, u32);

int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename,
                    int flags) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    u32 *sandboxed = sandboxed_pids.lookup(&tgid);
    if (!sandboxed)
        return 0;

    struct path_key_t key = {};
    bpf_probe_read_user_str(key.path, sizeof(key.path), (void *)filename);

    if (key.path[0] != '/')
        return 0;

    u32 *val = allowed_paths.lookup(&key);
    if (val)
        return 0;

    u32 len = 0;
    #pragma unroll
    for (u32 i = 0; i < MAX_PATH_LEN; i++) {
        if (key.path[i] != '\0')
            len = i + 1;
    }

    /*
     * Walk backwards through the path, zeroing one byte at a time.
     * At each '/' boundary we check whether the resulting directory prefix
     * exists in allowed_paths.  Because we zero from the end, the key is
     * always properly null-padded and matches what Python inserted.
     *
     * The loop avoids early-exit (break/return) so that #pragma unroll
     * can fully unroll it — necessary for kernels without bounded-loop
     * support.
     */
    int allowed = 0;
    #pragma unroll
    for (u32 j = 1; j < MAX_PATH_LEN; j++) {
        if (!allowed) {
            int i = (int)len - (int)j;
            if (i >= 1 && i < MAX_PATH_LEN) {
                key.path[i] = '\0';
                if (key.path[i - 1] == '/') {
                    u32 *pval = allowed_paths.lookup(&key);
                    if (pval)
                        allowed = 1;
                }
            }
        }
    }
    if (allowed)
        return 0;

    bpf_override_return(ctx, -EACCES);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_fork) {
    u32 parent_tgid = bpf_get_current_pid_tgid() >> 32;

    u32 *sandboxed = sandboxed_pids.lookup(&parent_tgid);
    if (sandboxed) {
        u32 child_pid = args->child_pid;
        u32 val = 1;
        sandboxed_pids.update(&child_pid, &val);
    }
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 tid = pid_tgid & 0xFFFFFFFF;

    if (tid == tgid)
        sandboxed_pids.delete(&tgid);
    return 0;
}
