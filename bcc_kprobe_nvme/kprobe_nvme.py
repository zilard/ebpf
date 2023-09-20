#!/usr/bin/python

from bcc import BPF
from bcc.utils import printb
from time import strftime

# define BPF program
bpf_text = """

#include <linux/blkdev.h>
#include <linux/stddef.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u8 opcode;
    u16 command_id;
    u32 nsid;
    u32 cdw10;
};

struct nvme_sgl_desc {
        __le64  addr;
        __le32  length;
        __u8    rsvd[3];
        __u8    type;
};

struct nvme_keyed_sgl_desc {
        __le64  addr;
        __u8    length[3];
        __u8    key[4];
        __u8    type;
};

union nvme_data_ptr {
        struct {
                __le64  prp1;
                __le64  prp2;
        };
        struct nvme_sgl_desc    sgl;
        struct nvme_keyed_sgl_desc ksgl;
};

struct nvme_common_command {
        __u8                    opcode;
        __u8                    flags;
        __u16                   command_id;
        __le32                  nsid;
        __le32                  cdw2[2];
        __le64                  metadata;
        union nvme_data_ptr     dptr;
        struct_group(cdws,
        __le32                  cdw10;
        __le32                  cdw11;
        __le32                  cdw12;
        __le32                  cdw13;
        __le32                  cdw14;
        __le32                  cdw15;
        );
};


struct nvme_command {
    union {
        struct nvme_common_command common;
    };
};


BPF_PERCPU_ARRAY(unix_data, struct data_t, 1);
BPF_PERF_OUTPUT(events);

/*
static int nvme_submit_user_cmd

static int nvme_submit_user_cmd(struct request_queue *q,
                struct nvme_command *cmd, u64 ubuffer,
                unsigned bufflen, void __user *meta_buffer, unsigned meta_len,
                u32 meta_seed, u64 *result, unsigned timeout, bool vec)
*/


int trace_nvme_submit_user_cmd(struct pt_regs *ctx,
                               void *q,
                               struct nvme_command *cmd
                              )
{
    struct data_t data = {};

    u64 id =  bpf_get_current_pid_tgid();
    u32 pid = id >> 32;                     // PID is higher part
    data.pid = pid;

    // get current process name
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
   
    __u8 a_opcode;
    bpf_probe_read_kernel(&a_opcode, sizeof(a_opcode), &cmd->common.opcode);
    data.opcode = a_opcode; 

    __u16 a_command_id;
    bpf_probe_read_kernel(&a_command_id, sizeof(a_command_id), &cmd->common.command_id);
    data.command_id = a_command_id;

    __le32 a_nsid;
    bpf_probe_read_kernel(&a_nsid, sizeof(a_nsid), &cmd->common.nsid);
    data.nsid = a_nsid;

    __le32 a_cdw10;
    bpf_probe_read_kernel(&a_cdw10, sizeof(a_cdw10), &cmd->common.cdws.cdw10);
    data.cdw10 = a_cdw10;

    events.perf_submit(ctx, &data, sizeof(data));
 
    return 0;
}
"""


# process event
def print_event(cpu, data, size):

    event = b["events"].event(data)


    print("%-9s %-9s %-7s %-8x %-12x %-6x %-6x" % (
           strftime("%H:%M:%S"),
           event.comm,
           event.pid,
           event.opcode,
           event.command_id,
           event.nsid,
           event.cdw10,
           ))


# initialize BPF
b = BPF(text=bpf_text)

b.attach_kprobe(event="nvme_submit_user_cmd", fn_name="trace_nvme_submit_user_cmd")


# header
print("%-9s %-9s %-7s %-8s %-12s %-6s %-6s" % (
      "TIME", "COMM", "PID", "OPCODE", "COMMAND-ID", "NSID", "CDW10"))


# read events
# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll(timeout=1000)
    except KeyboardInterrupt:
        exit()
