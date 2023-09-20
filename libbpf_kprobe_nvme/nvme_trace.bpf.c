#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/stddef.h>
#include "nvme_trace.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/nvme_submit_user_cmd")
int BPF_KPROBE(do_nvme_submit_user_cmd, void *q, struct nvme_command *cmd)
{
    pid_t pid;
    char comm[16];
    __u8  opcode;
    __u16 command_id;
    __le32 nsid;
    __le32 cdw10;

    pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
 
    opcode = BPF_CORE_READ(cmd, common.opcode);
    command_id = BPF_CORE_READ(cmd, common.command_id);
    nsid = BPF_CORE_READ(cmd, common.nsid);
    cdw10 = BPF_CORE_READ(cmd, common.cdws.cdw10);

    /*
    // __________ALTERNATIVE____________
    struct nvme_common_command common = {};
    bpf_core_read(&common, sizeof(common), &cmd->common);
    bpf_core_read(&opcode, sizeof(opcode), &common.opcode);
    bpf_core_read(&command_id, sizeof(command_id), &common.command_id);
    bpf_core_read(&nsid, sizeof(nsid), &common.nsid);
    bpf_core_read(&cdw10, sizeof(cdw10), &common.cdws.cdw10);
    */

    bpf_printk("KPROBE ENTRY pid = %d, comm = %s, opcode = %x, command_id = %x, nsid = %x, cdw10 = %x", 
               pid, comm, opcode, command_id, nsid, cdw10);

    return 0;
}
