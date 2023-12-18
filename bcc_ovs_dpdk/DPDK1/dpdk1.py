#!/usr/bin/python

from bcc import BPF
import ctypes as ct
from time import strftime

TASK_COMM_LEN = 16


class EventInfo(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("name", ct.c_char * 80),
    ]



# process event
def print_event(cpu, data, size):

    e = ct.cast(data, ct.POINTER(EventInfo)).contents
    # print(f"event: {e.name}  |  comm: {e.comm.decode()}  |  pid: {e.pid}")

    print("%-30s %-20s %-8s" % (
           str(e.name.decode()),
           str(e.comm.decode()),
           e.pid,
           ))



def main():

    # Define the eBPF program as a string
    with open("dpdk1_ebpf_program.c", "r") as f:
        bpf_program = f.read()


    # Load the eBPF program
    b = BPF(text=bpf_program)


    # Attach the kprobes defined in the eBPF program 
    b.attach_kprobe(event="__page_cache_alloc", fn_name="trace__page_cache_alloc")
    b.attach_kprobe(event="__pmd_alloc", fn_name="trace__pmd_alloc")


    # Loop and print the output of the eBPF program
    b["events"].open_perf_buffer(print_event)


    try:
        print("Attaching probes... Press Ctrl+C to exit.")
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        pass



    # Print header
    '''
    print("Start tracing... "
          "Hit Ctrl-C to end.\n")
    '''

    # read events
    # loop with callback to print_event
    '''
    b["events"].open_perf_buffer(print_event, page_cnt=64)
    while 1:
        try:
            b.perf_buffer_poll(timeout=1000)
        except KeyboardInterrupt:
            exit()
    '''


if __name__ == "__main__":
    main()




