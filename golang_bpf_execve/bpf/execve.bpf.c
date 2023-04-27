#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define FNAME_LEN 32

struct exec_data_t {
    u32 pid;
    u8 fname[FNAME_LEN];   // name of the process being called
    u8 comm[FNAME_LEN];    // process calling execve
};

struct exec_data_t _edt {0};

struct {
    _uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    _uint(key_size, sizeof(u32));
    _uint(value_size, sizeof(u32));
} events SEC(".maps");

struct execve_entry_args_t {
    u64 _unused;
    u64 _unused2;

    const char* filename;
    const char* const* argv;
    const char* const* envp;
};

/*
cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
name: sys_enter_execve
ID: 678
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:const char * filename;	offset:16;	size:8;	signed:0;
	field:const char *const * argv;	offset:24;	size:8;	signed:0;
	field:const char *const * envp;	offset:32;	size:8;	signed:0;

print fmt: "filename: 0x%08lx, argv: 0x%08lx, envp: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long)(REC->argv)), ((unsigned long)(REC->envp))
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*/

#define LAST_32_BITS(x) x & 0xFFFFFFFF
#define FIRST_32_BITS(x) x >> 32

SEC("tracepoint/syscalls/sys_enter_execve")
int enter_execve(struct execve_entry_args_t *args)
{
    struct exec_data_t exec_data = {};
    u64 pid_tgid;

    pid_tgid = bpf_get_current_pid_tgid();
    exec_data.pid = LAST_32_BITS(pid_tgid);

    bpf_probe_read_user_str(exec_data.fname,
                            sizeof(exec_data.fname),
                            args->filename);

    bpf_get_current_comm(exec_data.comm, sizeof(exec_data.comm));

    bpf_perf_event_output(args,
                          &events,
                          BPF_F_CURRENT_CPU,
                          &exec_data,
                          sizeof(exec_data));

    bpf_printk("hali vilag\n");

    return 0;

}

char LICENSE[] SEC("license") = "GPL";
