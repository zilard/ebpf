#!/usr/bin/python

from bcc import BPF
from time import strftime

# define BPF program
bpf_text = """
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

BPF_HISTOGRAM(rx_entry_hist);
BPF_HISTOGRAM(tx_retval_hist);


struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u64 size;
};


BPF_PERF_OUTPUT(events);



int trace_virtio_net_receive_rcu(struct pt_regs *ctx) {

    u64 size;
    size = PT_REGS_PARM3(ctx);
    rx_entry_hist.increment(bpf_log2l(size));

    struct data_t data = {};

    u64 id =  bpf_get_current_pid_tgid();
    u32 pid = id >> 32;                     // PID is higher part
    data.pid = pid;

    // get current process name
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    data.size = size;

    events.perf_submit(ctx, &data, sizeof(data));
 
    return 0;

}


int trace_virtio_net_flush_tx(struct pt_regs *ctx) {

    int retval;
    retval = PT_REGS_RC(ctx);
    tx_retval_hist.increment(bpf_log2l(retval));
    return 0;

}

"""


# process event
def print_event(cpu, data, size):

    event = b["events"].event(data)

    print("%-9s %-16s %-8s %-4d" % (
           strftime("%H:%M:%S"),
           str(event.comm.decode('utf-8')),
           event.pid,
           event.size,
           ))



QEMU_PATH="/usr/bin/qemu-system-x86_64"

# initialize BPF
b = BPF(text=bpf_text)
b.attach_uprobe(name=QEMU_PATH,
                sym="virtio_net_receive_rcu",
                fn_name="trace_virtio_net_receive_rcu")
b.attach_uretprobe(name=QEMU_PATH,
                   sym="virtio_net_flush_tx",
                   fn_name="trace_virtio_net_flush_tx")



# Print header
print("Aggregating data from virtio-net RX & TX virtqueues... "
      "Hit Ctrl-C to end.\n")

# header
print("%-9s %-16s %-8s %-4s\n" % (
      "TIME", "COMM", "PID", "PACKET_SIZE"))



# read events
# loop with callback to print_event
# Process arguments
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll(timeout=1000)
    except KeyboardInterrupt:
        print("\n")
        break

# Output

print("Virtio-net RX (entry) log2 packet size histogram")
print("---------------------------------------------")
b["rx_entry_hist"].print_log2_hist("size")
print("\n")

print("virtio-net TX (return) log2 number of packets transmitted")
print("---------------------------------------------")
b["tx_retval_hist"].print_log2_hist("num_packets")
print("\n")



