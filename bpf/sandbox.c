#include <uapi/linux/ptrace.h>
#include <linux/dcache.h>
#include <linux/fs_struct.h>
#include <linux/sched.h>
#include <linux/path.h>
#include <linux/fcntl.h>

#define MAX_PATH_LEN 128
#define MAX_DNAME_LEN 32
#define MAX_DEPTH 4

struct sandbox_params_t {
    uint64_t file_list_index;
    uint64_t syscall_filter0;
    uint64_t syscall_filter1;
    uint64_t syscall_filter2;
    uint64_t syscall_filter3;
    uint64_t syscall_filter4;
    uint64_t syscall_filter5;
};

struct path_key_t {
    char path[MAX_PATH_LEN];
};

BPF_HASH(sandboxed_cgroups, uint64_t, struct sandbox_params_t);
BPF_HASH(pid_to_params, uint64_t, struct sandbox_params_t, 100);
BPF_HASH(pid_to_cgroups, uint64_t, uint64_t, 100);
BPF_HASH(file_list0, struct path_key_t, uint32_t, 200);
BPF_HASH(file_list1, struct path_key_t, uint32_t, 200);
BPF_HASH(file_list2, struct path_key_t, uint32_t, 200);
BPF_HASH(file_list3, struct path_key_t, uint32_t, 200);
BPF_HASH(file_list4, struct path_key_t, uint32_t, 200);
BPF_HASH(file_list5, struct path_key_t, uint32_t, 200);
BPF_HASH(file_list6, struct path_key_t, uint32_t, 200);
BPF_HASH(file_list7, struct path_key_t, uint32_t, 200);
BPF_HASH(file_list8, struct path_key_t, uint32_t, 200);
BPF_HASH(file_list9, struct path_key_t, uint32_t, 200);
BPF_HASH(file_list10, struct path_key_t, uint32_t, 200);
BPF_HASH(file_list11, struct path_key_t, uint32_t, 200);
BPF_HASH(file_list12, struct path_key_t, uint32_t, 200);
BPF_HASH(file_list13, struct path_key_t, uint32_t, 200);
BPF_HASH(file_list14, struct path_key_t, uint32_t, 200);
BPF_HASH(file_list15, struct path_key_t, uint32_t, 200);
BPF_HASH_OF_MAPS(file_lists, uint64_t, "file_list0", 9999);

/* Scratch buffers for CWD/path resolution (see ebpf_sandbox.c). */
BPF_PERCPU_ARRAY(scratch, struct path_key_t, 2);

// returns NULL if the cgroup is not sandboxed, otherwise will return a pointer to a the sandbox params
static struct sandbox_params_t* get_sandbox_params_cgroup(uint64_t cgroup_id) {
    return sandboxed_cgroups.lookup(&cgroup_id);
}

static struct sandbox_params_t* get_current_sandbox_params() {
    // https://docs.ebpf.io/linux/helper-function/bpf_get_current_cgroup_id/
    return get_sandbox_params_cgroup(bpf_get_current_cgroup_id());
}

static __always_inline void *get_file_list_map(uint64_t file_list_index) {
    return file_lists.lookup(&file_list_index);
}

/* Build the CWD path by walking the dentry tree right-to-left into a map buffer. */
static __always_inline int read_cwd(struct path_key_t *buf,
                                    long *out_off, int *out_len) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct fs_struct *fs = NULL;
    struct path pwd = {};
    struct dentry *dentry = NULL;
    long off = (long)MAX_PATH_LEN;

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

        long name_len = (long)(unsigned int)d_name.len;
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

        char tmp[MAX_DNAME_LEN];
        __builtin_memset(tmp, 0, sizeof(tmp));
        bpf_probe_read_kernel(tmp, copy_len, (void *)d_name.name);

        write_off = off;
        long w = write_off;
        if (w < 0 || w >= MAX_PATH_LEN)
            break;

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

    write_off = off;
    off = write_off;
    if (off < 0 || off >= MAX_PATH_LEN)
        return -1;

    char first = '\0';
    bpf_probe_read_kernel(&first, 1, buf->path + off);
    if (first != '/') {
        off--;
        write_off = off;
        off = write_off;
        if (off < 0 || off >= MAX_PATH_LEN)
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

/* Concatenate CWD with a relative path into out->path. */
static __always_inline int build_abs_path(const char *rel,
                                          struct path_key_t *cwd_buf,
                                          long cwd_off, int cwd_len,
                                          struct path_key_t *out) {
    long base_len = 0;
    long done = 0;
    long cwd_len_l = (long)cwd_len;

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


// test

int syscall__execve(struct pt_regs *ctx) {
    uint64_t cgid = bpf_get_current_cgroup_id();
    uint64_t pid = bpf_get_current_pid_tgid() & 0xffffffff;

    struct sandbox_params_t* params = pid_to_params.lookup(&pid);
    if (params != NULL) {
        sandboxed_cgroups.insert(&cgid, params);
        pid_to_cgroups.insert(&pid, &cgid);
        pid_to_params.delete(&pid);
        bpf_trace_printk("%d", bpf_get_current_cgroup_id());
    }

    return 1;
}


int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) {
    struct sandbox_params_t *params = get_current_sandbox_params();
    if (!params)
        return 0;

    void *file_list = get_file_list_map(params->file_list_index);
    if (!file_list)
        return 0;

    struct path_key_t rel_key = {};
    bpf_probe_read_user_str(rel_key.path, sizeof(rel_key.path), (void *)filename);

    int zero = 0, one = 1;
    struct path_key_t *cwd_buf = scratch.lookup(&zero);
    struct path_key_t *key = scratch.lookup(&one);
    if (!cwd_buf || !key)
        goto deny;

    if (rel_key.path[0] != '/') {
        if (dfd != AT_FDCWD)
            goto deny;

        long cwd_off = 0;
        int cwd_len = 0;
        if (read_cwd(cwd_buf, &cwd_off, &cwd_len) < 0)
            goto deny;

        if (build_abs_path(rel_key.path, cwd_buf, cwd_off, cwd_len, key) < 0)
            goto deny;
    } else {
        #pragma unroll
        for (int i = 0; i < MAX_PATH_LEN; i++)
            key->path[i] = rel_key.path[i];
    }

    if (key->path[0] != '/')
        goto deny;

    u32 *val = bpf_map_lookup_elem(file_list, key);
    if (val) {
        if (*val == 1)
            return 0;
        goto deny;
    }

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
                    u32 *pval = bpf_map_lookup_elem(file_list, key);
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