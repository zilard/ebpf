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
    u8 buf;
    int link_down;
    char name[100];
    char model[100];
};


struct NetClientState {
    void *info;
    int link_down;
    struct NetClientState *next;
    struct NetClientState *peer;
    void *incoming_queue;
    char *model;
    char *name;
};


BPF_PERF_OUTPUT(events);



int trace_virtio_net_receive_rcu(struct pt_regs *ctx,
                                 struct NetClientState *nc,
                                 const uint8_t *buf,
                                 size_t size)
{

    struct data_t data = {};

    u64 a_size;
    bpf_probe_read_kernel(&a_size, sizeof(a_size), &size);
    data.size = a_size;

    // a_size = PT_REGS_PARM3(ctx);

    u8 a_buf;
    bpf_probe_read_kernel(&a_buf, sizeof(a_buf), &buf);
    data.buf = a_buf;

    int a_link_down;
    bpf_probe_read_kernel(&a_link_down, sizeof(a_link_down), &nc->link_down);
    data.link_down = a_link_down;

    bpf_probe_read_kernel(&data.name, sizeof(data.name), &nc->name);

    bpf_probe_read_kernel(&data.model, sizeof(data.model), &nc->model);


    rx_entry_hist.increment(bpf_log2l(a_size));


    u64 id =  bpf_get_current_pid_tgid();
    u32 pid = id >> 32;                     // PID is higher part
    data.pid = pid;

    // get current process name
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

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

def hexify(data):
    data_s = ""
    for d in data:
        data_s = data_s + format(d, '02x') + " "
    return data_s


# process event
def print_event(cpu, data, size):

    event = b["events"].event(data)

    print("%-9s %-16s %-8s %-8d %-8d %-10d %-20s %-20s" % (
           strftime("%H:%M:%S"),
           str(event.comm.decode('utf-8')),
           event.pid,
           event.size,
           event.buf,
           event.link_down,
           hexify(event.name),
           hexify(event.model),
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
print("%-9s %-16s %-8s %-8s %-8s %-10s %-20s %-20s\n" % (
      "TIME", "COMM", "PID", "SIZE", "BUF", "LinkDown?", "Name", "Model"))



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



