
#define struct_group(NAME, MEMBERS...)  \
        __struct_group(/* no tag */, NAME, /* no attrs */, MEMBERS)


struct nvme_sgl_desc {
        __le64  addr;
        __le32  length;
        __u8    rsvd[3];
        __u8    type;
} __attribute__((preserve_access_index));

struct nvme_keyed_sgl_desc {
        __le64  addr;
        __u8    length[3];
        __u8    key[4];
        __u8    type;
} __attribute__((preserve_access_index));

union nvme_data_ptr {
        struct {
                __le64  prp1;
                __le64  prp2;
        };
        struct nvme_sgl_desc    sgl;
        struct nvme_keyed_sgl_desc ksgl;
} __attribute__((preserve_access_index));

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
        ) __attribute__((preserve_access_index));
} __attribute__((preserve_access_index));


struct nvme_command {
    union {
        struct nvme_common_command common;
    };
} __attribute__((preserve_access_index));

