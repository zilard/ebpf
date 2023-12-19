#!/usr/bin/python

from bcc import BPF
from time import sleep, strftime

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

BPF_HASH(symbols);
"""


bpf_trace = """
int trace_SYMBOL(struct pt_regs *ctx)
{
    struct data_t data = {};

    u64 id =  bpf_get_current_pid_tgid();
    u32 pid = id >> 32;                     // PID is higher part
    data.pid = pid;

    char name[80] = "SYMBOL";
    bpf_probe_read(data.name, sizeof(name), (void *)&name);


    // get current process name
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
   
    events.perf_submit(ctx, &data, sizeof(data));


    u64 value = 0;
    u64 key = SYM_CODE;
 
    u64 *p = symbols.lookup(&key);
    if (p != 0) {
        value = *p;
    }
    value++;
    symbols.update(&key, &value);


    return 0;
}
"""


# process event
def print_event(cpu, data, size):

    event = b["events"].event(data)

    print("%-16s %-8s %-16s" % (
           str(event.comm.decode('utf-8')),
           event.pid,
           str(event.name.decode('utf-8')),
           ))



symbols = [
"__page_cache_alloc",
"__pmd_alloc",
"mempool_alloc_pages",
"alloc_skb_with_frags",
"skb_page_frag_refill",
"kmalloc_order",
"__get_free_pages",
"pcpu_create_chunk",
"kimage_alloc_pages",
"sgl_alloc_order",
"pte_alloc_one",
"__change_page_attr",
"kvm_arch_hardware_setup",
"kvm_arch_vcpu_create",
"vmx_setup_l1d_flush",
"alloc_coherent",
"intel_svm_alloc_pasid_tables",
"intel_svm_enable_prq",
"intel_alloc_coherent",
"alloc_pages_current",
"alloc_pages_vma",
"alloc_page_interleave",
"get_page_from_freelist",
"alloc_huge_page_nodemask",
"__alloc_pages_nodemask",
]




# Print header
print("Start tracing... "
      "Hit Ctrl-C to end.\n")


bpf_text = bpf_head + '\n'


for sym in symbols:
    bpf_aux = bpf_trace.replace('SYMBOL', sym)
    bpf_aux = bpf_aux.replace('SYM_CODE', str(symbols.index(sym)))
    bpf_text += bpf_aux + '\n'



# initialize BPF
b = BPF(text=bpf_text)


for sym in symbols:
    b.attach_kprobe(event=sym, fn_name="trace_" + sym)




while True:
    try:
        sleep(1)
        for k, v in b["symbols"].items():
            name = symbols[k.value]
            print("{}: {}".format(name, v.value))
        print('-'*40 + '\n')
    except KeyboardInterrupt:
        print("\n")
        break




sym_dict = {}
for sym in symbols:
    i = symbols.index(sym)
    sym_dict[i] = 0

for k, v in b["symbols"].items():
    sym_dict[k.value] = v.value

for sym in symbols:
    i = symbols.index(sym)
    print("%-3d: %-30s %-10d\n" % (
           i,
           symbols[i],
           sym_dict[i],
           ))



b["symbols"].print_linear_hist("sym_idx")


