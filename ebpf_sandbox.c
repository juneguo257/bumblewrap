#include <uapi/linux/ptrace.h>
#include <linux/dcache.h>
#include <linux/fs_struct.h>
#include <linux/sched.h>
#include <linux/path.h>
#include <linux/fcntl.h>

#define MAX_PATH_LEN 128
#define MAX_DNAME_LEN 32
#define MAX_DEPTH 4

struct path_key_t {
    char path[MAX_PATH_LEN];
};

BPF_HASH(sandboxed_pids, u32, u32);
BPF_HASH(allowed_paths, struct path_key_t, u32);

/*
 * Two scratch slots used as working buffers.  Slot 0 holds the CWD
 * built right-to-left; slot 1 holds the final absolute path used for
 * whitelist lookups.  Using a per-cpu map instead of the BPF stack
 * avoids the verifier's "subtraction from stack pointer prohibited"
 * restriction that is triggered by right-to-left pointer arithmetic.
 */
BPF_PERCPU_ARRAY(scratch, struct path_key_t, 2);

/*
 * Build the CWD path by walking the dentry tree right-to-left into
 * a per-cpu map buffer.
 *
 * Returns 0 on success, setting *out_off to the byte index where the
 * CWD string starts inside buf->path, and *out_len to the number of
 * valid bytes (including any leading '/').
 */
static __always_inline int read_cwd(struct path_key_t *buf,
                                    long *out_off, int *out_len) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct fs_struct *fs = NULL;
    struct path pwd = {};
    struct dentry *dentry = NULL;
    long off = (long)MAX_PATH_LEN;

    /*
     * volatile write_off launders the offset before pointer arithmetic.
     * Without it the compiler computes  buf->path + off  as
     * (buf->path + 128) − name_len, producing a NEGATIVE unsigned
     * variable offset on the map-value pointer.  The BPF verifier
     * rejects any pointer whose umax_value >= BPF_MAX_VAR_OFF (2^29),
     * and −name_len has huge unsigned value.
     *
     * Storing through volatile forces the compiler to treat the
     * reloaded value as opaque, so the address becomes
     * buf->path + write_off  (simple non-negative addition).
     */
    volatile long write_off;

    bpf_probe_read_kernel(&fs, sizeof(fs), &task->fs);
    if (!fs)
        return -1;

    bpf_probe_read_kernel(&pwd, sizeof(pwd), &fs->pwd);
    bpf_probe_read_kernel(&dentry, sizeof(dentry), &pwd.dentry);
    if (!dentry)
        return -1;

    #pragma unroll
    for (int i = 0; i < MAX_PATH_LEN; i++)
        buf->path[i] = '\0';

    #pragma unroll
    for (int i = 0; i < MAX_DEPTH; i++) {
        struct dentry *parent = NULL;
        struct qstr d_name = {};

        if (!dentry)
            break;

        bpf_probe_read_kernel(&parent, sizeof(parent), &dentry->d_parent);
        if (parent == dentry)
            break;

        bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);

        /* Load name_len through a helper so the compiler cannot see
           the algebraic link  off = old_off − name_len  and cannot
           remove the bounds checks the verifier needs. */
        long name_len = 0;
        bpf_probe_read_kernel(&name_len, 4, &d_name.len);
        if (name_len > MAX_DNAME_LEN)
            name_len = MAX_DNAME_LEN;
        if (name_len < 1)
            break;
        if (off <= 1 || off > MAX_PATH_LEN)
            break;
        if (off - name_len - 1 <= 0)
            break;

        off -= name_len;
        if (off < 0 || off >= MAX_PATH_LEN)
            break;

        long copy_len = name_len;
        if (copy_len <= 0 || copy_len > MAX_DNAME_LEN)
            break;

        /* Read the dentry name into a fixed-size stack temp.
           We cannot bpf_probe_read_kernel directly into the map
           buffer at a variable offset with variable size: the
           verifier checks max(off) + max(size) independently and
           rejects the call even though we proved off+size ≤ 128.
           A stack destination with a known allocation size works. */
        char tmp[MAX_DNAME_LEN];
        __builtin_memset(tmp, 0, sizeof(tmp));
        bpf_probe_read_kernel(tmp, copy_len, (void *)d_name.name);

        /* Launder off through volatile → compiler emits
           map_ptr + w (addition) instead of
           map_ptr + 128 − name_len (subtraction). */
        write_off = off;
        long w = write_off;
        if (w < 0 || w >= MAX_PATH_LEN)
            break;

        /* Byte-by-byte copy from stack tmp into the map buffer.
           Each store is 1 byte at a bounds-checked offset. */
        #pragma unroll
        for (int j = 0; j < MAX_DNAME_LEN; j++) {
            if (j < copy_len) {
                long dest = w + (long)j;
                if (dest >= 0 && dest < MAX_PATH_LEN)
                    buf->path[dest] = tmp[j];
            }
        }

        off--;
        if (off < 0 || off >= MAX_PATH_LEN)
            break;
        write_off = off;
        w = write_off;
        if (w < 0 || w >= MAX_PATH_LEN)
            break;
        char slash = '/';
        bpf_probe_read_kernel(buf->path + w, 1, &slash);

        dentry = parent;
    }

    if (off == (long)MAX_PATH_LEN)
        return -1;
    if (off < 0 || off >= MAX_PATH_LEN)
        return -1;

    char first = '\0';
    bpf_probe_read_kernel(&first, 1, buf->path + off);
    if (first != '/') {
        off--;
        if (off < 0)
            return -1;
        char slash = '/';
        bpf_probe_read_kernel(buf->path + off, 1, &slash);
    }

    *out_off = off;
    *out_len = (int)((long)MAX_PATH_LEN - off);
    if (*out_len <= 0)
        return -1;

    return 0;
}

/*
 * Concatenate CWD (from cwd_buf starting at byte cwd_off) with the
 * relative path rel, writing the result into out->path.
 * Both cwd_buf and out must be map-value pointers (not stack).
 */
static __always_inline int build_abs_path(const char *rel,
                                          struct path_key_t *cwd_buf,
                                          long cwd_off, int cwd_len,
                                          struct path_key_t *out) {
    long base_len = 0;
    long done = 0;
    long cwd_len_l = (long)cwd_len;

    /* Copy CWD to the beginning of out->path. */
    #pragma unroll
    for (long i = 0; i < MAX_PATH_LEN; i++) {
        if (i < cwd_len_l && i < MAX_PATH_LEN - 1) {
            long src = cwd_off + i;
            char c = '\0';
            if (src >= 0 && src < MAX_PATH_LEN)
                bpf_probe_read_kernel(&c, 1, &cwd_buf->path[src]);
            out->path[i] = c;
            base_len = i + 1;
        } else {
            out->path[i] = '\0';
        }
    }

    /* Ensure trailing slash after CWD. */
    if (base_len > 0 && base_len < MAX_PATH_LEN - 1) {
        long prev_idx = base_len - 1;
        if (prev_idx >= 0 && prev_idx < MAX_PATH_LEN) {
            char prev = out->path[prev_idx];
            if (prev != '/') {
                out->path[base_len] = '/';
                base_len++;
            }
        }
    }

    /* Append the relative path. */
    #pragma unroll
    for (long i = 0; i < MAX_PATH_LEN; i++) {
        long dst = base_len + i;
        if (dst >= 0 && dst < MAX_PATH_LEN - 1) {
            if (!done) {
                char c = rel[i];
                out->path[dst] = c;
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
    bpf_probe_read_user_str(rel_key.path, sizeof(rel_key.path),
                            (void *)filename);

    /* Obtain map-value scratch buffers (avoids stack-pointer
       subtraction issues in the verifier). */
    int zero = 0, one = 1;
    struct path_key_t *cwd_buf = scratch.lookup(&zero);
    struct path_key_t *key     = scratch.lookup(&one);
    if (!cwd_buf || !key)
        goto deny;

    if (rel_key.path[0] != '/') {
        /* Relative path — resolve against CWD. */
        if (dfd != AT_FDCWD)
            goto deny;

        long cwd_off = 0;
        int  cwd_len = 0;
        if (read_cwd(cwd_buf, &cwd_off, &cwd_len) < 0)
            goto deny;

        if (build_abs_path(rel_key.path, cwd_buf,
                           cwd_off, cwd_len, key) < 0)
            goto deny;
    } else {
        /* Absolute path — copy into map buffer for lookups. */
        #pragma unroll
        for (int i = 0; i < MAX_PATH_LEN; i++)
            key->path[i] = rel_key.path[i];
    }

    if (key->path[0] != '/')
        goto deny;

    /* ── Exact match ── */
    u32 *val = allowed_paths.lookup(key);
    if (val) {
        if (*val == 1)
            return 0;   /* explicitly allowed */
        goto deny;       /* explicitly denied (value 0) */
    }

    /* ── Prefix match ──
     * Progressively truncate the path from the right.  At each '/'
     * boundary, look the prefix up.  The first (most-specific) match
     * wins: value 1 → allow, value 0 → deny. */
    long len = 0;
    #pragma unroll
    for (long li = 0; li < MAX_PATH_LEN; li++) {
        if (key->path[li] != '\0')
            len = li + 1;
    }

    long decided = 0;
    long allowed = 0;
    #pragma unroll
    for (long lj = 1; lj < MAX_PATH_LEN; lj++) {
        if (!decided) {
            long idx = len - lj;
            if (idx >= 1 && idx < MAX_PATH_LEN) {
                key->path[idx] = '\0';
                if (key->path[idx - 1] == '/') {
                    u32 *pval = allowed_paths.lookup(key);
                    if (pval) {
                        decided = 1;
                        if (*pval == 1)
                            allowed = 1;
                    }
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
