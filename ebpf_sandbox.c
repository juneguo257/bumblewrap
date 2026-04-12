#include <uapi/linux/ptrace.h>
#include <linux/dcache.h>
#include <linux/fs_struct.h>
#include <linux/sched.h>
#include <linux/path.h>
#include <linux/fcntl.h>

#define MAX_PATH_LEN 128
#define MAX_DNAME_LEN 32

struct path_key_t {
    char path[MAX_PATH_LEN];
};

BPF_HASH(sandboxed_pids, u32, u32);
BPF_HASH(allowed_paths, struct path_key_t, u32);

static __always_inline int read_cwd(char *buf, int buf_len, char **out_start,
                                    int *out_len) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct fs_struct *fs = NULL;
    struct path pwd = {};
    struct dentry *dentry = NULL;
    int off = buf_len;

    bpf_probe_read_kernel(&fs, sizeof(fs), &task->fs);
    if (!fs) {
        bpf_trace_printk("read_cwd: fs NULL\n");
        return -1;
    }

    bpf_probe_read_kernel(&pwd, sizeof(pwd), &fs->pwd);
    bpf_probe_read_kernel(&dentry, sizeof(dentry), &pwd.dentry);
    if (!dentry) {
        bpf_trace_printk("read_cwd: dentry NULL\n");
        return -1;
    }

    #pragma unroll
    for (int i = 0; i < MAX_PATH_LEN; i++)
        buf[i] = '\0';

    /*
     * Partial dentry walk: builds a best-effort path without mount handling.
     * Stops at the root dentry or when out of space.
     */
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        struct dentry *parent = NULL;
        struct qstr d_name = {};
        int name_len = 0;

        if (!dentry) {
            bpf_trace_printk("read_cwd: dentry NULL in loop\n");
            break;
        }

        bpf_probe_read_kernel(&parent, sizeof(parent), &dentry->d_parent);
        if (parent == dentry)
            break;

        bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);
        name_len = d_name.len;
        if (name_len <= 0 || name_len > MAX_PATH_LEN - 1) {
            bpf_trace_printk("read_cwd: bad name_len=%d\n", name_len);
            break;
        }
        if (name_len > MAX_DNAME_LEN)
            name_len = MAX_DNAME_LEN;

        if (off <= 1 || off > MAX_PATH_LEN) {
            bpf_trace_printk("read_cwd: bad off=%d\n", off);
            break;
        }
        if (off - name_len - 1 <= 0) {
            bpf_trace_printk("read_cwd: no space off=%d name_len=%d\n", off,
                             name_len);
            break;
        }

        off -= name_len;
        #pragma unroll
        for (int k = 0; k < MAX_DNAME_LEN; k++) {
            if (k < name_len) {
                char c = '\0';
                bpf_probe_read_kernel(&c, sizeof(c), (void *)(d_name.name + k));
                if (off + k < MAX_PATH_LEN)
                    buf[off + k] = c;
            }
        }
        off--;
        buf[off] = '/';

        dentry = parent;
    }

    if (off == buf_len) {
        bpf_trace_printk("read_cwd: empty path\n");
        return -1;
    }

    if (buf[off] != '/') {
        off--;
        if (off < 0) {
            bpf_trace_printk("read_cwd: underflow\n");
            return -1;
        }
        buf[off] = '/';
    }

    *out_start = &buf[off];
    *out_len = buf_len - off;
    if (*out_len <= 0) {
        bpf_trace_printk("read_cwd: out_len=%d\n", *out_len);
        return -1;
    }

    return 0;
}

static __always_inline int build_abs_path(const char *rel,
                                          struct path_key_t *out_key) {
    char *cwd = NULL;
    int cwd_len = 0;
    int base_len = 0;
    int done = 0;

    if (read_cwd(out_key->path, MAX_PATH_LEN, &cwd, &cwd_len) < 0)
        return -1;

    bpf_trace_printk("cwd=%s\n", cwd);

    #pragma unroll
    for (int i = 0; i < MAX_PATH_LEN; i++) {
        if (i < cwd_len && i < MAX_PATH_LEN - 1) {
            out_key->path[i] = cwd[i];
            base_len = i + 1;
        } else {
            out_key->path[i] = '\0';
        }
    }

    if (base_len > 0 && out_key->path[base_len - 1] != '/' &&
        base_len < MAX_PATH_LEN - 1) {
        out_key->path[base_len] = '/';
        base_len++;
    }

    #pragma unroll
    for (int i = 0; i < MAX_PATH_LEN; i++) {
        int dst = base_len + i;
        if (dst < MAX_PATH_LEN - 1) {
            if (!done) {
                char c = rel[i];
                out_key->path[dst] = c;
                if (c == '\0')
                    done = 1;
            }
        }
    }

    return 0;
}

int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename,
                    int flags) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    u32 *sandboxed = sandboxed_pids.lookup(&tgid);
    if (!sandboxed)
        return 0;

    struct path_key_t rel_key = {};
    struct path_key_t key = {};
    bpf_probe_read_user_str(rel_key.path, sizeof(rel_key.path), (void *)filename);

    bpf_trace_printk("dfd=%d, rel=%s\n", dfd, rel_key.path);

    if (rel_key.path[0] != '/') {
        if (dfd != AT_FDCWD) {
            bpf_trace_printk("non-AT_FDCWD dfd not supported\n");
            goto deny;
        }
        if (build_abs_path(rel_key.path, &key) < 0) {
            bpf_trace_printk("failed to build abs path\n");
            goto deny;
        }
    } else {
        key = rel_key;
    }

    bpf_trace_printk("abs=%s\n", key.path);

    if (key.path[0] != '/')
        goto deny;

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

deny:
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
