#!/usr/bin/python

from bcc import BPF
from time import strftime

# define BPF program
bpf_head = """
#include <linux/sched.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char name[80];
};

// Declare a BPF map to transmit data to user space
BPF_PERF_OUTPUT(events);
"""


bpf_trace = """
int trace_SYM(struct pt_regs *ctx)
{
    struct data_t data = {};
  
    u64 id =  bpf_get_current_pid_tgid();
    u32 pid = id >> 32;                     // PID is higher part
    data.pid = pid;

    char name[80] = "SYM";
    bpf_probe_read(data.name, sizeof(name), (void *)&name);


    // get current process name
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
   
    events.perf_submit(ctx, &data, sizeof(data));
 
    return 0;
}
"""


# process event
def print_event(cpu, data, size):

    event = b["events"].event(data)

    '''
    print("%-9s %-16s %-8s" % (
           strftime("%H:%M:%S"),
           str(event.comm.decode('utf-8')),
           event.pid,
           ))
    '''

    print("%-16s %-8s %-16s" % (
           str(event.comm.decode('utf-8')),
           event.pid,
           str(event.name.decode('utf-8')),
           ))



symbols = ["__page_cache_alloc", "__pmd_alloc"]



# Print header
print("Start tracing... "
      "Hit Ctrl-C to end.\n")


bpf_text = bpf_head + '\n'

'''
symbol="__page_cache_alloc"
bpf_text += bpf_trace.replace('SYM', symbol) + '\n'

symbol="__pmd_alloc"
bpf_text += bpf_trace.replace('SYM', symbol) + '\n'
'''

for sym in symbols:
    bpf_text += bpf_trace.replace('SYM', sym) + '\n'


#print("%s" % bpf_text)


# initialize BPF
b = BPF(text=bpf_text)


'''
symbol="__page_cache_alloc"
b.attach_kprobe(event=symbol, fn_name="trace_" + symbol)

symbol="__pmd_alloc"
b.attach_kprobe(event=symbol, fn_name="trace_" + symbol)
'''

for sym in symbols:
    b.attach_kprobe(event=sym, fn_name="trace_" + sym)


"""
# initialize BPF
b = BPF(text=bpf_text1)

b.attach_kprobe(event=symbol, fn_name="trace_" + symbol) 



symbol="__pmd_alloc"
bpf_text2 = bpf_text.replace('SYM', symbol)
# initialize BPF
b = BPF(text=bpf_text2)
b.attach_kprobe(event=symbol, fn_name="trace_" + symbol)
"""



# read events
# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll(timeout=1000)
    except KeyboardInterrupt:
        exit()



