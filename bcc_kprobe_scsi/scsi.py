#!/usr/bin/python

from bcc import BPF
from bcc.utils import printb
from time import strftime

# define BPF program
bpf_text = """

#include <linux/blkdev.h>
#include <linux/stddef.h>


const int ISCSI_DATA_LEN = 32;


struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    int len;
    unsigned char data[ISCSI_DATA_LEN];
};




struct scsi_vpd {
        struct rcu_head rcu;
        int             len;
        unsigned char   data[];
};



struct scsi_device {
        struct Scsi_Host *host;
        struct request_queue *request_queue;

        /* the next two are protected by the host->host_lock */
        struct list_head    siblings;   /* list of all devices on this host */
        struct list_head    same_target_siblings; /* just the devices sharing same target id */

        atomic_t device_busy;           /* commands actually active on LLDD */
        atomic_t device_blocked;        /* Device returned QUEUE_FULL. */

        spinlock_t list_lock;
        struct list_head cmd_list;      /* queue of in use SCSI Command structures */
        struct list_head starved_entry;
        unsigned short queue_depth;     /* How deep of a queue we want */
        unsigned short max_queue_depth; /* max queue depth */
        unsigned short last_queue_full_depth; /* These two are used by */
        unsigned short last_queue_full_count; /* scsi_track_queue_full() */
        unsigned long last_queue_full_time;     /* last queue full time */
        unsigned long queue_ramp_up_period;     /* ramp up period in jiffies */

        unsigned long last_queue_ramp_up;       /* last queue ramp up time */

        unsigned int id, channel;
        u64 lun;
        unsigned int manufacturer;      /* Manufacturer of device, for using 
                                         * vendor-specific cmd's */
        unsigned sector_size;   /* size in bytes */

        void *hostdata;         /* available to low-level driver */
        unsigned char type;
        char scsi_level;
        char inq_periph_qual;   /* PQ from INQUIRY data */
        struct mutex inquiry_mutex;
        unsigned char inquiry_len;      /* valid bytes in 'inquiry' */
        unsigned char * inquiry;        /* INQUIRY response data */
        const char * vendor;            /* [back_compat] point into 'inquiry' ... */
        const char * model;             /* ... after scan; point to static string */
        const char * rev;               /* ... "nullnullnullnull" before scan */


        struct scsi_vpd __rcu *vpd_pg83;
};



BPF_PERCPU_ARRAY(unix_data, struct data_t, 1);
BPF_PERF_OUTPUT(events);


int trace_scsi_ioctl(struct pt_regs *ctx,
                     struct scsi_device *sdev
                     )
{
    struct data_t data = {};

    u64 id =  bpf_get_current_pid_tgid();
    u32 pid = id >> 32;                     // PID is higher part
    data.pid = pid;

    // get current process name
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
   
    int a_len;
    bpf_probe_read_kernel(&a_len, sizeof(a_len), &sdev->vpd_pg83->len);
    data.len = a_len;
 
    //unsigned char a_data[32];
    bpf_probe_read_kernel(&data.data, sizeof(data.data), &sdev->vpd_pg83->data);
    //data.data[20] = a_data[20];

    events.perf_submit(ctx, &data, sizeof(data));
 
    return 0;
}
"""


# process event
def print_event(cpu, data, size):

    event = b["events"].event(data)

    data_s = ""
    for d in event.data:
        data_s = data_s + format(d, '02x') + " "

    print("%-9s %-16s %-8s %-4d %-60s" % (
           strftime("%H:%M:%S"),
           str(event.comm.decode('utf-8')),
           event.pid,
           event.len,
           data_s,
           ))




# initialize BPF
b = BPF(text=bpf_text)

b.attach_kprobe(event="scsi_ioctl", fn_name="trace_scsi_ioctl")





# header
print("%-9s %-16s %-8s %-4s %-4s\n" % (
       "TIME", "COMM", "PID", "LEN", "DATA"))



# read events
# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll(timeout=1000)
    except KeyboardInterrupt:
        exit()

