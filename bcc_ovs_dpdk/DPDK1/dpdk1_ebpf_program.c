#include <linux/sched.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char name[80];
};

// Declare a BPF map to transmit data to user space
BPF_PERF_OUTPUT(events);

int trace__page_cache_alloc(struct pt_regs *ctx)
{
    struct data_t data = {};

    u64 id =  bpf_get_current_pid_tgid();
    u32 pid = id >> 32;                     // PID is higher part
    data.pid = pid;

    char name[80] = "__page_cache_alloc";
    bpf_probe_read(data.name, sizeof(name), (void *)&name);


    // get current process name
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
   
    events.perf_submit(ctx, &data, sizeof(data));
 
    return 0;
}



int trace__pmd_alloc(struct pt_regs *ctx)
{
    struct data_t data = {};

    u64 id =  bpf_get_current_pid_tgid();
    u32 pid = id >> 32;                     // PID is higher part
    data.pid = pid;

    char name[80] = "__pmd_alloc";
    bpf_probe_read(data.name, sizeof(name), (void *)&name);


    // get current process name
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}



