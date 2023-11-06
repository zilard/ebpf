#!/usr/bin/python

from bcc import BPF
from time import strftime

# define BPF program
bpf_text = """
#include <linux/sched.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

int trace_whatever(struct pt_regs *ctx)
{
    struct data_t data = {};

    u64 id =  bpf_get_current_pid_tgid();
    u32 pid = id >> 32;                     // PID is higher part
    data.pid = pid;

    // get current process name
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
   
    events.perf_submit(ctx, &data, sizeof(data));
 
    return 0;
}
"""


# process event
def print_event(cpu, data, size):

    event = b["events"].event(data)

    print("%-9s %-16s %-8s" % (
           strftime("%H:%M:%S"),
           str(event.comm.decode('utf-8')),
           event.pid,
           ))



# initialize BPF
b = BPF(text=bpf_text)

b.attach_uprobe(
name="/usr/bin/qemu-system-x86_64",
sym="virtio_net_receive_rcu",
fn_name="trace_whatever")

# read events
# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll(timeout=1000)
    except KeyboardInterrupt:
        exit()



