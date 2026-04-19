// #include <stdint.h>
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_PATH_LEN 128

struct sandbox_params_t {
    uint64_t t;
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

// returns NULL if the cgroup is not sandboxed, otherwise will return a pointer to a the sandbox params
static struct sandbox_params_t* get_sandbox_params_cgroup(uint64_t cgroup_id) {
    return sandboxed_cgroups.lookup(&cgroup_id);
}

static struct sandbox_params_t* get_current_sandbox_params() {
    // https://docs.ebpf.io/linux/helper-function/bpf_get_current_cgroup_id/
    return get_sandbox_params_cgroup(bpf_get_current_cgroup_id());
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
    // bpf_trace_printk("%d", bpf_get_current_cgroup_id());
    return 1;
}