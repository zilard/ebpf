# Table of Contents

- [eBPF program using the libbpf framework](https://github.com/zilard/ebpf/edit/main/README.md#ebpf-program-using-the-libbpf-framework)
- [eBPF program using the BCC framework loaded with Python script](https://github.com/zilard/ebpf/edit/main/README.md#ebpf-program-using-the-bcc-framework-loaded-with-python-script)
- [eBPF oneliner with bpftrace for tracing NVMe driver data structure members](https://github.com/zilard/ebpf/edit/main/README.md#ebpf-oneliner-with-bpftrace-for-tracing-nvme-driver-data-structure-members)




# eBPF program using the libbpf framework

<br />
In order to make eBPF programs portable across different versions of the Kernel, we have to write our eBPF programs using the CO-RE approach (compile once, run everywhere)<br />
CO-RE allows eBPF programs to include information about the layout of data structures they were compile with, and has a mechanism for adjusting how fields (members) are accessed in the data structure layout<br />
The Linux Kernel source code headers can change between version of Linux and an eBPF program can&nbsp; include several individual header files, but we can also use bpftool to generate vmlinux.h header file from a running system containing all the data structure information of the Kernel that an eBPF program might need to use.<br />
<br />
There are a few libraries that take care of the CO-RE relocation capability, and&nbsp; libbpf being the original C library takes care of this relocation capability<br />
<br />
We use the Clang compiler with the &quot;-g&quot; flag to compile eBPF programs, and Clang includes the CO-RE relocations, derived from the BTF information describing the Kernel data structures<br />
BTF (BPF Type Format) is a format for expressing the layout of data structures and functions signatures, in CO-RE this is used to determine the differences between structures used at compile time and structures present on the system&#39;s Kernel during runtime, because data structures might be different when the eBPF program was compiled on a system with a certain Kernel version from the layout of data structures (having same name) available on the system with another Kernel version where we intend to run the eBPF program, that be build earlier on the other system.<br />
<br />
When a use space program loads an eBPF program into the Kernel, the CO-RE mechanism requires the bytecode to be adjusted, using the CO-RE relocation information compiled into the object, in order to compensate the differences of data structure layout between data structures that were present when the eBPF program was compiled and data structures that are currently available on the machine where we are running the eBPF program<br />
<br />
Clone the Lunar Kernel
<pre class="ckeditor_codeblock">
git clone https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/lunar</pre>
<br />
Search needed NVMe Kernel driver funcion definitions and datastructures<br />
<br />
Now let&#39;s see in the Kernel code how does the &nbsp;&quot;nvme_submit_user_cmd&quot; function definition look like, what arguments does it have and what can we extract from these arguments which are passed to the &nbsp;&quot;nvme_submit_user_cmd&quot; function<br />
<br />
We can see in the Kernel source that it has a number of arguments and the second argument is a pointer of type &quot;struct nvme_command&quot;<br />
&nbsp;
<pre class="ckeditor_codeblock">
grep -rnI &quot; nvme_submit_user_cmd(&quot; lunar/

lunar/drivers/nvme/host/ioctl.c:141

static int nvme_submit_user_cmd(struct request_queue *q,
                struct nvme_command *cmd, u64 ubuffer,
                unsigned bufflen, void __user *meta_buffer, unsigned meta_len,
                u32 meta_seed, u64 *result, unsigned timeout, bool vec)
{
</pre>
<br />
Let&#39;s check what members does the &quot;struct nvme_command&quot;&nbsp; have?<br />
&nbsp;
<pre class="ckeditor_codeblock">
grep -rnI &quot;struct nvme_command {&quot; lunar/

lunar/include/linux/nvme.h:1740

struct nvme_command {
        union {
                struct nvme_common_command common;
                struct nvme_rw_command rw;
                struct nvme_identify identify;
                struct nvme_features features;
                struct nvme_create_cq create_cq;
                struct nvme_create_sq create_sq;
                struct nvme_delete_queue delete_queue;
                struct nvme_download_firmware dlfw;
                struct nvme_format_cmd format;
                struct nvme_dsm_cmd dsm;
                struct nvme_write_zeroes_cmd write_zeroes;
                struct nvme_zone_mgmt_send_cmd zms;
                struct nvme_zone_mgmt_recv_cmd zmr;
                struct nvme_abort_cmd abort;
                struct nvme_get_log_page_command get_log_page;
                struct nvmf_common_command fabrics;
                struct nvmf_connect_command connect;
                struct nvmf_property_set_command prop_set;
                struct nvmf_property_get_command prop_get;
                struct nvmf_auth_common_command auth_common;
                struct nvmf_auth_send_command auth_send;
                struct nvmf_auth_receive_command auth_receive;
                struct nvme_dbbuf dbbuf;
                struct nvme_directive_cmd directive;
        };
};
</pre>
<br />
Within &quot;struct nvme_command&quot; we would like to access the &quot;struct nvme_common_command common&quot; member<br />
Now let&#39;s check the layout of the &quot;struct nvme_common_command&quot; data structure in the Kernel source code
<pre class="ckeditor_codeblock">
grep -rnI &quot;struct nvme_common_command {&quot; lunar/

lunar/include/linux/nvme.h:907

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
</pre>
<br />
&quot;struct nvme_common_command&quot; has this &quot;opcode&quot; member plus a number of other member like command_id, nsid (Namespace ID) , cdw10 (Command Dword 10 is an NVMe command specific field) which values we want to trace with out eBPF program<br />
<br />
<br />
<br />
Clone the libbpf-bootstrap repository and submodules and install dependencies
<pre class="ckeditor_codeblock">
sudo apt install clang libelf1 libelf-dev zlib1g-dev</pre>
&nbsp;

<pre class="ckeditor_codeblock">
git clone --recurse-submodules https://github.com/libbpf/libbpf-bootstrap</pre>
<br />
This will also clone the submodule repositories
<pre class="ckeditor_codeblock">
https://github.com/libbpf/blazesym
https://github.com/libbpf/bpftool
https://github.com/libbpf/libbpf</pre>
<br />
Create eBPF program development directory and copy here all the utility files and directories from libbpf-boostrap<br />
&nbsp;
<pre class="ckeditor_codeblock">
mkdir nvme_ebpf
cd  nvme_ebpf</pre>
&nbsp;

<pre class="ckeditor_codeblock">
cp -r ../libbpf-bootstrap/{blazesym,bpftool,libbpf} .
cp ../libbpf-bootstrap/examples/c/Makefile .</pre>
<br />
The eBPF program needs the definitions of any kernel data structures and types that it is going to refer to<br />
BTF-enabled tools like &quot;bpftool&quot; can generate an appropriate header file from the BTF information included in the kernel, and this file &nbsp;is conventionally called vmlinux.h, this vmlinux.h file defines all the kernel&#39;s data types<br />
&nbsp;
<pre class="ckeditor_codeblock">
bpftool btf dump file /sys/kernel/btf/vmlinux format c &gt; vmlinux.h</pre>
<br />
When you compile the source into an eBPF object file, that object will include BTF information that matches the definitions used in this header file. Later, when the program is run on a target machine, the user space program that loads it into the kernel will make adjustments to account for differences between this build-time BTF information and the BTF information for the kernel that&#39;s running on that target machine<br />
<br />
modify the Makefile you copied from &quot;libbpf-bootstrap/examples/c/Makefile&quot; according to the below patch
<pre class="ckeditor_codeblock">
--- ~/libbpf-bootstrap/examples/c/Makefile	2023-09-08 10:52:53.242558117 +0200
+++ Makefile	2023-09-08 11:42:08.759224020 +0200
@@ -1,12 +1,12 @@
 # SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
 OUTPUT := .output
 CLANG ?= clang
-LIBBPF_SRC := $(abspath ../../libbpf/src)
-BPFTOOL_SRC := $(abspath ../../bpftool/src)
+LIBBPF_SRC := $(abspath libbpf/src)
+BPFTOOL_SRC := $(abspath bpftool/src)
 LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
 BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
 BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
-LIBBLAZESYM_SRC := $(abspath ../../blazesym/)
+LIBBLAZESYM_SRC := $(abspath blazesym/)
 LIBBLAZESYM_INC := $(abspath $(LIBBLAZESYM_SRC)/include)
 LIBBLAZESYM_OBJ := $(abspath $(OUTPUT)/libblazesym.a)
 ARCH ?= $(shell uname -m | sed &#39;s/x86_64/x86/&#39; \
@@ -16,15 +16,16 @@
 			 | sed &#39;s/mips.*/mips/&#39; \
 			 | sed &#39;s/riscv64/riscv/&#39; \
 			 | sed &#39;s/loongarch64/loongarch/&#39;)
-VMLINUX := ../../vmlinux/$(ARCH)/vmlinux.h
+#VMLINUX := ../../vmlinux/$(ARCH)/vmlinux.h
+VMLINUX := vmlinux.h
 # Use our own libbpf API headers and Linux UAPI headers distributed with
 # libbpf to avoid dependency on system-wide headers, which could be missing or
 # outdated
-INCLUDES := -I$(OUTPUT) -I../../libbpf/include/uapi -I$(dir $(VMLINUX)) -I$(LIBBLAZESYM_INC)
+INCLUDES := -I$(OUTPUT) -Ilibbpf/include/uapi -I$(dir $(VMLINUX)) -I$(LIBBLAZESYM_INC)
 CFLAGS := -g -Wall
 ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)
 
-APPS = minimal minimal_legacy bootstrap uprobe kprobe fentry usdt sockfilter tc ksyscall
+APPS = nvme_trace
 
 CARGO ?= $(shell which cargo)
 ifeq ($(strip $(CARGO)),)</pre>
<br />
The final version of the Makefile will look like this:
<pre class="ckeditor_codeblock">
vi Makefile
-----------------------------------------------------------------------------------------------
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
LIBBPF_SRC := $(abspath libbpf/src)
BPFTOOL_SRC := $(abspath bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
LIBBLAZESYM_SRC := $(abspath blazesym/)
LIBBLAZESYM_INC := $(abspath $(LIBBLAZESYM_SRC)/include)
LIBBLAZESYM_OBJ := $(abspath $(OUTPUT)/libblazesym.a)
ARCH ?= $(shell uname -m | sed &#39;s/x86_64/x86/&#39; \
			 | sed &#39;s/arm.*/arm/&#39; \
			 | sed &#39;s/aarch64/arm64/&#39; \
			 | sed &#39;s/ppc64le/powerpc/&#39; \
			 | sed &#39;s/mips.*/mips/&#39; \
			 | sed &#39;s/riscv64/riscv/&#39; \
			 | sed &#39;s/loongarch64/loongarch/&#39;)
#VMLINUX := ../../vmlinux/$(ARCH)/vmlinux.h
VMLINUX := vmlinux.h
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I$(OUTPUT) -Ilibbpf/include/uapi -I$(dir $(VMLINUX)) -I$(LIBBLAZESYM_INC)
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

APPS = nvme_trace

CARGO ?= $(shell which cargo)
ifeq ($(strip $(CARGO)),)
BZS_APPS :=
else
BZS_APPS := profile
APPS += $(BZS_APPS)
# Required by libblazesym
ALL_LDFLAGS += -lrt -ldl -lpthread -lm
endif

# Get Clang&#39;s default includes on this system. We&#39;ll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be &quot;missing&quot; on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use &#39;-idirafter&#39;: Don&#39;t interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - &lt;/dev/null 2&gt;&amp;1 \
	| sed -n &#39;/&lt;...&gt; search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }&#39;)

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf &#39;  %-8s %s%s\n&#39;					\
		      &quot;$(1)&quot;						\
		      &quot;$(patsubst $(abspath $(OUTPUT))/%,%,$(2))&quot;	\
		      &quot;$(if $(3), $(3))&quot;;
	MAKEFLAGS += --no-print-directory
endif

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap


$(LIBBLAZESYM_SRC)/target/release/libblazesym.a::
	$(Q)cd $(LIBBLAZESYM_SRC) &amp;&amp; $(CARGO) build --release

$(LIBBLAZESYM_OBJ): $(LIBBLAZESYM_SRC)/target/release/libblazesym.a | $(OUTPUT)
	$(call msg,LIB, $@)
	$(Q)cp $(LIBBLAZESYM_SRC)/target/release/libblazesym.a $@

# Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)		      \
		     -c $(filter %.c,$^) -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $&lt; &gt; $@

# Build user-space code
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(patsubst %,$(OUTPUT)/%.o,$(BZS_APPS)): $(LIBBLAZESYM_OBJ)

$(BZS_APPS): $(LIBBLAZESYM_OBJ)

# Build application binary
$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
-----------------------------------------------------------------------------------------------</pre>
<br />
Now write the C application which will load the eBPF program into the Kernel
<pre class="ckeditor_codeblock">
vi nvme_trace.c
-----------------------------------------------------------------------------------------------
#include &lt;stdio.h&gt;
#include &lt;unistd.h&gt;
#include &lt;signal.h&gt;
#include &lt;string.h&gt;
#include &lt;errno.h&gt;
#include &lt;sys/resource.h&gt;
#include &lt;bpf/libbpf.h&gt;
#include &quot;nvme_trace.skel.h&quot;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}

int main(int argc, char **argv)
{
	struct nvme_trace_bpf *skel;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open load and verify BPF application */
	skel = nvme_trace_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, &quot;Failed to open BPF skeleton\n&quot;);
		return 1;
	}

	/* Attach tracepoint handler */
	err = nvme_trace_bpf__attach(skel);
	if (err) {
		fprintf(stderr, &quot;Failed to attach BPF skeleton\n&quot;);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, &quot;can&#39;t set signal handler: %s\n&quot;, strerror(errno));
		goto cleanup;
	}

	printf(&quot;Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` &quot;
	       &quot;to see output of the BPF programs.\n&quot;);

	while (!stop) {
		fprintf(stderr, &quot;.&quot;);
		sleep(1);
	}

cleanup:
	nvme_trace_bpf__destroy(skel);
	return -err;
}
-----------------------------------------------------------------------------------------------
</pre>
<br />
Now write the eBPF program:
<pre class="ckeditor_codeblock">
vi nvme_trace.bpf.c
-----------------------------------------------------------------------------------------------
#include &quot;vmlinux.h&quot;
#include &lt;bpf/bpf_helpers.h&gt;
#include &lt;bpf/bpf_tracing.h&gt;
#include &lt;bpf/bpf_core_read.h&gt;
#include &lt;linux/stddef.h&gt;
#include &quot;nvme_trace.h&quot;

char LICENSE[] SEC(&quot;license&quot;) = &quot;Dual BSD/GPL&quot;;

SEC(&quot;kprobe/nvme_submit_user_cmd&quot;)
int BPF_KPROBE(do_nvme_submit_user_cmd, void *q, struct nvme_command *cmd)
{
    pid_t pid;
    char comm[16];
    __u8  opcode;
    __u16 command_id;
    __le32 nsid;
    __le32 cdw10;

    pid = bpf_get_current_pid_tgid() &gt;&gt; 32;

    bpf_get_current_comm(&amp;comm, sizeof(comm));
 
    opcode = BPF_CORE_READ(cmd, common.opcode);
    command_id = BPF_CORE_READ(cmd, common.command_id);
    nsid = BPF_CORE_READ(cmd, common.nsid);
    cdw10 = BPF_CORE_READ(cmd, common.cdws.cdw10);

    /*
    // __________ALTERNATIVE____________
    struct nvme_common_command common = {};
    bpf_core_read(&amp;common, sizeof(common), &amp;cmd-&gt;common);
    bpf_core_read(&amp;opcode, sizeof(opcode), &amp;common.opcode);
    bpf_core_read(&amp;command_id, sizeof(command_id), &amp;common.command_id);
    bpf_core_read(&amp;nsid, sizeof(nsid), &amp;common.nsid);
    bpf_core_read(&amp;cdw10, sizeof(cdw10), &amp;common.cdws.cdw10);
    */

    bpf_printk(&quot;KPROBE ENTRY pid = %d, comm = %s, opcode = %x, command_id = %x, nsid = %x, cdw10 = %x&quot;, 
               pid, comm, opcode, command_id, nsid, cdw10);

    return 0;
}
-----------------------------------------------------------------------------------------------
</pre>
<br />
Also create this extra header file which will include some of the needed NVMe Kernel driver data structure declarations that we extracted from the Kernel source:<br />
&nbsp;
<pre class="ckeditor_codeblock">
vi nvme_trace.h
-----------------------------------------------------------------------------------------------
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
-----------------------------------------------------------------------------------------------
</pre>
<br />
<br />
At this moment this is the content of our eBPF development directory will look as shown below:
<pre class="ckeditor_codeblock">
~/nvme_ebpf$ ls
blazesym  bpftool  libbpf  Makefile  nvme_trace.bpf.c  nvme_trace.c  vmlinux.h</pre>
<br />
Now lets compile the eBPF program and userspace loading program with &quot;make all&quot;
<pre class="ckeditor_codeblock">
make all

  MKDIR    .output
  MKDIR    .output/libbpf
  LIB      libbpf.a
  MKDIR    /home/zilard/nvme_ebpf/.output//libbpf/staticobjs
  CC       /home/zilard/nvme_ebpf/.output//libbpf/staticobjs/bpf.o
  CC       /home/zilard/nvme_ebpf/.output//libbpf/staticobjs/btf.o
  CC       /home/zilard/nvme_ebpf/.output//libbpf/staticobjs/libbpf.o
  CC       /home/zilard/nvme_ebpf/.output//libbpf/staticobjs/libbpf_errno.o
  CC       /home/zilard/nvme_ebpf/.output//libbpf/staticobjs/netlink.o
  CC       /home/zilard/nvme_ebpf/.output//libbpf/staticobjs/nlattr.o
  CC       /home/zilard/nvme_ebpf/.output//libbpf/staticobjs/str_error.o
  CC       /home/zilard/nvme_ebpf/.output//libbpf/staticobjs/libbpf_probes.o
  CC       /home/zilard/nvme_ebpf/.output//libbpf/staticobjs/bpf_prog_linfo.o
  CC       /home/zilard/nvme_ebpf/.output//libbpf/staticobjs/btf_dump.o
  CC       /home/zilard/nvme_ebpf/.output//libbpf/staticobjs/hashmap.o
  CC       /home/zilard/nvme_ebpf/.output//libbpf/staticobjs/ringbuf.o
  CC       /home/zilard/nvme_ebpf/.output//libbpf/staticobjs/strset.o
  CC       /home/zilard/nvme_ebpf/.output//libbpf/staticobjs/linker.o
  CC       /home/zilard/nvme_ebpf/.output//libbpf/staticobjs/gen_loader.o
  CC       /home/zilard/nvme_ebpf/.output//libbpf/staticobjs/relo_core.o
  CC       /home/zilard/nvme_ebpf/.output//libbpf/staticobjs/usdt.o
  CC       /home/zilard/nvme_ebpf/.output//libbpf/staticobjs/zip.o
  AR       /home/zilard/nvme_ebpf/.output//libbpf/libbpf.a
  INSTALL  bpf.h libbpf.h btf.h libbpf_common.h libbpf_legacy.h bpf_helpers.h bpf_helper_defs.h bpf_tracing.h bpf_endian.h bpf_core_read.h skel_internal.h libbpf_version.h usdt.bpf.h
  INSTALL  /home/zilard/nvme_ebpf/.output//libbpf/libbpf.pc
  INSTALL  /home/zilard/nvme_ebpf/.output//libbpf/libbpf.a 
  MKDIR    bpftool
  BPFTOOL  bpftool/bootstrap/bpftool
...                        libbfd: [ on  ]
...               clang-bpf-co-re: [ on  ]
...                          llvm: [ on  ]
...                        libcap: [ OFF ]
  MKDIR    /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/include/bpf
  INSTALL  /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/include/bpf/hashmap.h
  INSTALL  /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/include/bpf/relo_core.h
  INSTALL  /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/include/bpf/libbpf_internal.h
  MKDIR    /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/
  MKDIR    /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/
  MKDIR    /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs
  CC       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/bpf.o
  CC       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/btf.o
  CC       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/libbpf.o
  CC       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/libbpf_errno.o
  CC       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/netlink.o
  CC       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/nlattr.o
  CC       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/str_error.o
  CC       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/libbpf_probes.o
  CC       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/bpf_prog_linfo.o
  CC       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/btf_dump.o
  CC       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/hashmap.o
  CC       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/ringbuf.o
  CC       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/strset.o
  CC       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/linker.o
  CC       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/gen_loader.o
  CC       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/relo_core.o
  CC       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/usdt.o
  AR       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/libbpf.a
  INSTALL  bpf.h libbpf.h btf.h libbpf_common.h libbpf_legacy.h bpf_helpers.h bpf_helper_defs.h bpf_tracing.h bpf_endian.h bpf_core_read.h skel_internal.h libbpf_version.h usdt.bpf.h
  CC       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/main.o
  CC       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/common.o
  CC       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/json_writer.o
  CC       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/gen.o
  CC       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/btf.o
  CC       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/xlated_dumper.o
  CC       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/btf_dumper.o
  CC       /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/disasm.o
  LINK     /home/zilard/nvme_ebpf/.output/bpftool/bootstrap/bpftool
  BPF      .output/nvme_trace.bpf.o
  GEN-SKEL .output/nvme_trace.skel.h
  CC       .output/nvme_trace.o
  BINARY   nvme_trace</pre>
<br />
If the compilation was successful we are going to see thee &quot;nvme_trace&quot; created in our directory and a hidden directory called &quot;.output&quot;
<pre class="ckeditor_codeblock">
~/nvme_ebpf$ ls
blazesym  bpftool  libbpf  Makefile  nvme_trace  nvme_trace.bpf.c  nvme_trace.c  vmlinux.h   .output</pre>
the eBPF program object file &quot;nvme_trace.bpf.o&quot;&nbsp;is found in the .output hidden folder, and also a bunch of eBPF header files and libbpf object files

<pre class="ckeditor_codeblock">
~/nvme_ebpf$ ls -a .output/
.   bpf      libbpf    nvme_trace.bpf.o  nvme_trace.skel.h     pkgconfig
..  bpftool  libbpf.a  nvme_trace.o      nvme_trace.tmp.bpf.o

~/nvme_ebpf$ ls -a .output/pkgconfig/
.  ..  libbpf.pc

~/nvme_ebpf$ ls -a .output/bpf
.                bpf.h              btf.h            libbpf_version.h
..               bpf_helper_defs.h  libbpf_common.h  skel_internal.h
bpf_core_read.h  bpf_helpers.h      libbpf.h         usdt.bpf.h
bpf_endian.h     bpf_tracing.h      libbpf_legacy.h

~/nvme_ebpf$ ls -a .output/libbpf
.  ..  libbpf.a  libbpf.pc  staticobjs

~/nvme_ebpf$ ls -a .output/libbpf/staticobjs/
.                 btf_dump.o    libbpf_errno.o   netlink.o    str_error.o
..                btf.o         libbpf.o         nlattr.o     strset.o
bpf.o             gen_loader.o  libbpf_probes.o  relo_core.o  usdt.o
bpf_prog_linfo.o  hashmap.o     linker.o         ringbuf.o    zip.o

~/nvme_ebpf$ ls -a .output/bpftool/
.  ..  bootstrap

~/nvme_ebpf$ ls -a .output/bpftool/bootstrap/
.        btf_dumper.d  common.o  gen.o          main.d
..       btf_dumper.o  disasm.d  json_writer.d  main.o
bpftool  btf.o         disasm.o  json_writer.o  xlated_dumper.d
btf.d    common.d      gen.d     libbpf         xlated_dumper.o</pre>
<br />
Now lets run the eBPF loading application which loads the eBPF program into the Kernel<br />
&nbsp;
<pre class="ckeditor_codeblock">
sudo ./nvme_trace 
libbpf: loading object &#39;nvme_trace_bpf&#39; from buffer
libbpf: elf: section(2) .symtab, size 168, link 1, flags 0, type=2
libbpf: elf: section(3) kprobe/nvme_submit_user_cmd, size 472, link 0, flags 6, type=1
libbpf: sec &#39;kprobe/nvme_submit_user_cmd&#39;: found program &#39;do_nvme_submit_user_cmd&#39; at insn offset 0 (0 bytes), code size 59 insns (472 bytes)
libbpf: elf: section(4) license, size 13, link 0, flags 3, type=1
libbpf: license of nvme_trace_bpf is Dual BSD/GPL
libbpf: elf: section(5) .rodata, size 86, link 0, flags 2, type=1
libbpf: elf: section(6) .relkprobe/nvme_submit_user_cmd, size 16, link 2, flags 40, type=9
libbpf: elf: section(7) .BTF, size 2334, link 0, flags 0, type=1
libbpf: elf: section(8) .BTF.ext, size 492, link 0, flags 0, type=1
libbpf: looking for externs among 7 symbols...
libbpf: collected 0 externs total
libbpf: map &#39;nvme_tra.rodata&#39; (global data): at sec_idx 5, offset 0, flags 80.
libbpf: map 0 is &quot;nvme_tra.rodata&quot;
libbpf: sec &#39;.relkprobe/nvme_submit_user_cmd&#39;: collecting relocation for section(3) &#39;kprobe/nvme_submit_user_cmd&#39;
libbpf: sec &#39;.relkprobe/nvme_submit_user_cmd&#39;: relo #0: insn #52 against &#39;.rodata&#39;
libbpf: prog &#39;do_nvme_submit_user_cmd&#39;: found data map 0 (nvme_tra.rodata, sec 5, off 0) for insn 52
libbpf: loading kernel BTF &#39;/sys/kernel/btf/vmlinux&#39;: 0
libbpf: map &#39;nvme_tra.rodata&#39;: created successfully, fd=4
libbpf: sec &#39;kprobe/nvme_submit_user_cmd&#39;: found 5 CO-RE relocations
libbpf: CO-RE relocating [2] struct pt_regs: found target candidate [184] struct pt_regs in [vmlinux]
libbpf: prog &#39;do_nvme_submit_user_cmd&#39;: relo #0: &lt;byte_off&gt; [2] struct pt_regs.si (0:13 @ offset 104)
libbpf: prog &#39;do_nvme_submit_user_cmd&#39;: relo #0: matching candidate #0 &lt;byte_off&gt; [184] struct pt_regs.si (0:13 @ offset 104)
libbpf: prog &#39;do_nvme_submit_user_cmd&#39;: relo #0: patched insn #0 (LDX/ST/STX) off 104 -&gt; 104
libbpf: CO-RE relocating [7] struct nvme_command: found target candidate [127897] struct nvme_command in [nvme_core]
libbpf: CO-RE relocating [7] struct nvme_command: found target candidate [127890] struct nvme_command in [nvme]
libbpf: prog &#39;do_nvme_submit_user_cmd&#39;: relo #1: &lt;byte_off&gt; [7] struct nvme_command.common.opcode (0:0:0:0 @ offset 0)
libbpf: prog &#39;do_nvme_submit_user_cmd&#39;: relo #1: matching candidate #0 &lt;byte_off&gt; [127897] struct nvme_command.common.opcode (0:0:0:0 @ offset 0)
libbpf: prog &#39;do_nvme_submit_user_cmd&#39;: relo #1: matching candidate #1 &lt;byte_off&gt; [127890] struct nvme_command.common.opcode (0:0:0:0 @ offset 0)
libbpf: prog &#39;do_nvme_submit_user_cmd&#39;: relo #1: patched insn #8 (ALU/ALU64) imm 0 -&gt; 0
libbpf: prog &#39;do_nvme_submit_user_cmd&#39;: relo #2: &lt;byte_off&gt; [7] struct nvme_command.common.command_id (0:0:0:2 @ offset 2)
libbpf: prog &#39;do_nvme_submit_user_cmd&#39;: relo #2: matching candidate #0 &lt;byte_off&gt; [127897] struct nvme_command.common.command_id (0:0:0:2 @ offset 2)
libbpf: prog &#39;do_nvme_submit_user_cmd&#39;: relo #2: matching candidate #1 &lt;byte_off&gt; [127890] struct nvme_command.common.command_id (0:0:0:2 @ offset 2)
libbpf: prog &#39;do_nvme_submit_user_cmd&#39;: relo #2: patched insn #15 (ALU/ALU64) imm 2 -&gt; 2
libbpf: prog &#39;do_nvme_submit_user_cmd&#39;: relo #3: &lt;byte_off&gt; [7] struct nvme_command.common.nsid (0:0:0:3 @ offset 4)
libbpf: prog &#39;do_nvme_submit_user_cmd&#39;: relo #3: matching candidate #0 &lt;byte_off&gt; [127897] struct nvme_command.common.nsid (0:0:0:3 @ offset 4)
libbpf: prog &#39;do_nvme_submit_user_cmd&#39;: relo #3: matching candidate #1 &lt;byte_off&gt; [127890] struct nvme_command.common.nsid (0:0:0:3 @ offset 4)
libbpf: prog &#39;do_nvme_submit_user_cmd&#39;: relo #3: patched insn #24 (ALU/ALU64) imm 4 -&gt; 4
libbpf: prog &#39;do_nvme_submit_user_cmd&#39;: relo #4: &lt;byte_off&gt; [7] struct nvme_command.common.cdws.cdw10 (0:0:0:7:1:0 @ offset 40)
libbpf: prog &#39;do_nvme_submit_user_cmd&#39;: relo #4: matching candidate #0 &lt;byte_off&gt; [127897] struct nvme_command.common.cdws.cdw10 (0:0:0:7:1:0 @ offset 40)
libbpf: prog &#39;do_nvme_submit_user_cmd&#39;: relo #4: matching candidate #1 &lt;byte_off&gt; [127890] struct nvme_command.common.cdws.cdw10 (0:0:0:7:1:0 @ offset 40)
libbpf: prog &#39;do_nvme_submit_user_cmd&#39;: relo #4: patched insn #32 (ALU/ALU64) imm 40 -&gt; 40
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.
...........................................</pre>
<br />
We&#39;re using bpf_printk to print a message in the kernel tracing log, you can find this log in /sys/kernel/debug/tracing/trace_pipe.<br />
bpf_printk() helper function in the kernel always sends output to the same predefined pseudofile location: /sys/kernel/debug/tracing/trace_pipe.<br />
You need root privileges to access and continue reading the content of this file<br />
<br />
We have to install nvme-cli so we can trigger the invocation of this &quot;nvme_submit_user_cmd&quot; kernel function<br />
<br />
Now let&#39;s install nvme-cli &nbsp;in order to send an admin command to one of the NVME SSD devices
<pre class="ckeditor_codeblock">
sudo apt install nvme-cli</pre>
<br />
<br />
As soon as we start executing the nvme-cli tool to list NVMe devices on the system
<pre class="ckeditor_codeblock">
sudo nvme list

Node                  Generic               SN                   Model                                    Namespace Usage                      Format           FW Rev  
--------------------- --------------------- -------------------- ---------------------------------------- --------- -------------------------- ---------------- --------
/dev/nvme0n1          /dev/ng0n1            S4DYNX0R756769       SAMSUNG MZVLB512HBJQ-000L2               1          93.20  GB / 512.11  GB    512   B +  0 B   3L1QEXF7
</pre>
<br />
The &nbsp;&quot;nvme_submit_user_cmd&quot; function is invoked in the NVMe Kernel driver level, and the kprobe attached by our eBPF program will trace the NVMe data structure members that we are hooked onto, opcode, command-id, nsid, cdw10<br />
<br />
This means that the nvme-cli tool triggers the &quot;nvme_submit_user_cmd&quot; nvme kernel driver function 2 times, same opcode, 0x6 (HEX) &nbsp;which in terms of NVMe admin commands it means &quot;Identify&quot;<br />
&nbsp;
<pre class="ckeditor_codeblock">
sudo cat /sys/kernel/debug/tracing/trace_pipe

            nvme-4943    [010] d..31  1967.763968: bpf_trace_printk: KPROBE ENTRY pid = 4943, comm = nvme, opcode = 6, command_id = 0, nsid = 1, cdw10 = 0
            nvme-4943    [010] d..31  1967.764521: bpf_trace_printk: KPROBE ENTRY pid = 4943, comm = nvme, opcode = 6, command_id = 0, nsid = 1, cdw10 = 3
</pre>
<br />
Now let&#39;s run an NVME admin passthru command to trigger a short device selt-test in the NVME SSD<br />
&nbsp;
<pre class="ckeditor_codeblock">
sudo nvme admin-passthru /dev/nvme0 -n 0x1 --opcode=0x14 --cdw10=0x1 -r
Admin Command Device Self-test is Success and result: 0x00000000</pre>
<br />
Now our eBPF program and kprobe captures the struct data members and the Python script prints out the following data:<br />
&nbsp;
<pre class="ckeditor_codeblock">
sudo cat /sys/kernel/debug/tracing/trace_pipe
...
            nvme-4946    [004] d..31  2026.971492: bpf_trace_printk: KPROBE ENTRY pid = 4946, comm = nvme, opcode = 14, command_id = 0, nsid = 1, cdw10 = 1
</pre>
<br />
Opcode 0x14 (HEX) means &quot;Device Self-test&quot; according to &quot;NVM Express Base Specification Revision 2.0a&quot; &nbsp;&quot;Figure 138: Opcodes for Admin Commands&quot;<br />
cdw10 &nbsp;Command Dword 10 is a command specific field<br />
Namespace ID is 0x1<br />
<br />
<br />
<strong>Related Documents</strong><br />
blog:&nbsp;<a href="https://nakryiko.com" target="_blank">Andrii Nakryiko&#39;s Blog</a><br />
book:&nbsp;<a href="https://www.oreilly.com/library/view/learning-ebpf/9781098135119/" target="_blank">Liz Rice - Learning eBPF</a><br />
book:&nbsp;<a href="https://www.oreilly.com/library/view/linux-observability-with/9781492050193/" target="_blank">David Calavera, Lorenzo Fontana - Linux Observability with BPF</a><br />
tutorial:&nbsp;<a href="https://mdaverde.com/posts/cap-bpf/" target="_blank">Introduction to CAP_BPF</a><br />
specification:&nbsp;<a href="https://nvmexpress.org/wp-content/uploads/NVMe-NVM-Express-2.0a-2021.07.26-Ratified.pdf" target="_blank">NVM Express Base Specification Revision 2.0a&nbsp;</a><br />
manual:&nbsp;<a href="https://manpages.ubuntu.com/manpages/lunar/en/man1/nvme.1.html" target="_blank">nvme</a><br />
manual:&nbsp;<a href="https://manpages.ubuntu.com/manpages/lunar/man1/nvme-admin-passthru.1.html" target="_blank">nvme-admin-passthru</a>
<br />
<br />





# eBPF program using the BCC framework loaded with Python script

<br />
What is the most easiest way you can start writing eBPF programs?<br />
How you can write an easy eBPF program which can trace specific Data Structure members in the Kernel used by Kernel functions, and how can you attach this eBPF program of yours to specific events, syscalls and kernel functions that you aim to trace<br />
<br />
There are several different libraries and frameworks that you can use to write eBPF applications<br />
The most easiest and most accessible way to write an eBPF program from scratch is to use the BCC Python Framework<br />
<br />
The BCC project at https://github.com/iovisor/bcc contains a great number of CLI tools for tracing the Linux system and Kernel, the tools directory contains a lot of Python-based eBPF examples https://github.com/iovisor/bcc/tree/master/tools<br />
<br />
Although BCC was the first popular project for implementing eBPF programs, providing framework for both user space and kernel space aspect, this way making eBPF development relatively easy for programmers without much kernel experience, still it is not recommended for production level eBPF development, but it is awesome for taking the first steps in eBPF development<br />
<br />
eBPF programs can be used to dynamically change the behavior of the system, the eBPF code starts taking effect as soon as it is attached to an event which can be a syscall or kernel function<br />
<br />
The main objective of this article is to teach you how to write an eBPF program in the possibly most easiest way, still I would like to give you a bit more serious example, where we trace the Kernel Data Structure members used by a Kernel function<br />
<br />
I have a Python application which contains the eBPF program and it&#39;s using the BCC framework to compile and load it into the Kernel
<pre class="ckeditor_codeblock">
vi kprobe_nvme.py
--------------------------------------------------------------------
#!/usr/bin/python

from bcc import BPF
from bcc.utils import printb
from time import strftime

# define BPF program
bpf_text = &quot;&quot;&quot;

#include &lt;linux/blkdev.h&gt;
#include &lt;linux/stddef.h&gt;

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


int trace_nvme_submit_user_cmd(struct pt_regs *ctx,
                               void *q,
                               struct nvme_command *cmd
                              )
{
    struct data_t data = {};

    u64 id =  bpf_get_current_pid_tgid();
    u32 pid = id &gt;&gt; 32;                     // PID is higher part
    data.pid = pid;

    // get current process name
    bpf_get_current_comm(&amp;data.comm, sizeof(data.comm));
   
    __u8 a_opcode;
    bpf_probe_read_kernel(&amp;a_opcode, sizeof(a_opcode), &amp;cmd-&gt;common.opcode);
    data.opcode = a_opcode; 

    __u16 a_command_id;
    bpf_probe_read_kernel(&amp;a_command_id, sizeof(a_command_id), &amp;cmd-&gt;common.command_id);
    data.command_id = a_command_id;

    __le32 a_nsid;
    bpf_probe_read_kernel(&amp;a_nsid, sizeof(a_nsid), &amp;cmd-&gt;common.nsid);
    data.nsid = a_nsid;

    __le32 a_cdw10;
    bpf_probe_read_kernel(&amp;a_cdw10, sizeof(a_cdw10), &amp;cmd-&gt;common.cdws.cdw10);
    data.cdw10 = a_cdw10;

    events.perf_submit(ctx, &amp;data, sizeof(data));
 
    return 0;
}
&quot;&quot;&quot;


# process event
def print_event(cpu, data, size):

    event = b[&quot;events&quot;].event(data)


    print(&quot;%-9s %-9s %-7s %-8x %-12x %-6x %-6x&quot; % (
           strftime(&quot;%H:%M:%S&quot;),
           event.comm,
           event.pid,
           event.opcode,
           event.command_id,
           event.nsid,
           event.cdw10,
           ))


# initialize BPF
b = BPF(text=bpf_text)

b.attach_kprobe(event=&quot;nvme_submit_user_cmd&quot;, fn_name=&quot;trace_nvme_submit_user_cmd&quot;)


# header
print(&quot;%-9s %-9s %-7s %-8s %-12s %-6s %-6s&quot; % (
      &quot;TIME&quot;, &quot;COMM&quot;, &quot;PID&quot;, &quot;OPCODE&quot;, &quot;COMMAND-ID&quot;, &quot;NSID&quot;, &quot;CDW10&quot;))


# read events
# loop with callback to print_event
b[&quot;events&quot;].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll(timeout=1000)
    except KeyboardInterrupt:
        exit()
--------------------------------------------------------------------</pre>
<br />
More specifically our Python code will load the wrapped eBPF program written in C, into the Kernel and will attach a kprobe to trace &quot;nvme_submit_user_cmd&quot; NVMe Kernel driver function<br />
<br />
We have to installe nvme-cli so we can trigger the invocation of this&nbsp;&quot;nvme_submit_user_cmd&quot;&nbsp;kernel function<br />
<br />
Now let&#39;s install nvme-cli&nbsp; in order to send an admin command to one of the NVME SSD devices
<pre class="ckeditor_codeblock">
sudo apt install nvme-cli</pre>

<pre>

&nbsp;</pre>
Now let&#39;s see in the Kernel code how does the &nbsp;&quot;nvme_submit_user_cmd&quot; function definition look like, what arguments does it have and what can we extract from these arguments which are passed to the &nbsp;&quot;nvme_submit_user_cmd&quot; function<br />
<br />
We can see in the Kernel source that it has a number of arguments and the second argument is a pointer of type &quot;struct nvme_command&quot;
<pre class="ckeditor_codeblock">
drivers/nvme/host/ioctl.c:141

static int nvme_submit_user_cmd(struct request_queue *q,
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_command *cmd, u64 ubuffer,
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; unsigned bufflen, void __user *meta_buffer, unsigned meta_len,
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; u32 meta_seed, u64 *result, unsigned timeout, bool vec)</pre>
<br />
Let&#39;s check in the Kernel source code what members does the &quot;struct nvme_command&quot; &nbsp;have?<br />
&nbsp;
<pre class="ckeditor_codeblock">
grep -rnI &quot;struct nvme_command {&quot; kernel_src/
include/linux/nvme.h:1531

struct nvme_command {
&nbsp; &nbsp; &nbsp; &nbsp; union {
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_common_command common;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_rw_command rw;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_identify identify;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_features features;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_create_cq create_cq;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_create_sq create_sq;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_delete_queue delete_queue;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_download_firmware dlfw;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_format_cmd format;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_dsm_cmd dsm;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_write_zeroes_cmd write_zeroes;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_zone_mgmt_send_cmd zms;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_zone_mgmt_recv_cmd zmr;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_abort_cmd abort;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_get_log_page_command get_log_page;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvmf_common_command fabrics;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvmf_connect_command connect;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvmf_property_set_command prop_set;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvmf_property_get_command prop_get;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_dbbuf dbbuf;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_directive_cmd directive;
&nbsp; &nbsp; &nbsp; &nbsp; };
};
</pre>
<br />
Within &quot;struct nvme_command&quot; we would like to access the &quot;struct nvme_common_command common&quot; member<br />
Now let&#39;s check the layout of the &quot;struct nvme_common_command&quot; data structure in the Kernel source code<br />
&nbsp;
<pre class="ckeditor_codeblock">
grep -rnI &quot;struct nvme_common_command {&quot; kernel_src/

./include/linux/nvme.h:901

struct nvme_common_command {
&nbsp; &nbsp; &nbsp; &nbsp; __u8 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;opcode;
&nbsp; &nbsp; &nbsp; &nbsp; __u8 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;flags;
&nbsp; &nbsp; &nbsp; &nbsp; __u16 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; command_id;
&nbsp; &nbsp; &nbsp; &nbsp; __le32 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;nsid;
&nbsp; &nbsp; &nbsp; &nbsp; __le32 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;cdw2[2];
&nbsp; &nbsp; &nbsp; &nbsp; __le64 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;metadata;
&nbsp; &nbsp; &nbsp; &nbsp; union nvme_data_ptr &nbsp; &nbsp; dptr;
&nbsp; &nbsp; &nbsp; &nbsp; struct_group(cdws,
&nbsp; &nbsp; &nbsp; &nbsp; __le32 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;cdw10;
&nbsp; &nbsp; &nbsp; &nbsp; __le32 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;cdw11;
&nbsp; &nbsp; &nbsp; &nbsp; __le32 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;cdw12;
&nbsp; &nbsp; &nbsp; &nbsp; __le32 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;cdw13;
&nbsp; &nbsp; &nbsp; &nbsp; __le32 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;cdw14;
&nbsp; &nbsp; &nbsp; &nbsp; __le32 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;cdw15;
&nbsp; &nbsp; &nbsp; &nbsp; );
};
</pre>
<br />
&quot;struct nvme_common_command&quot; has this &quot;opcode&quot; member plus a number of other member like command_id, nsid (Namespace ID) , cdw10 (Command Dword 10 is an NVMe command specific field) which values we want to trace with out eBPF program<br />
<br />
Now let&#39;s load the eBPF program into the Kernel<br />
The Python script using the BCC Python Framework will load our eBPF program, for that we need to run the python script with sudo<br />
&nbsp;
<pre class="ckeditor_codeblock">
sudo ./kprobe_nvme.py </pre>
<br />
As soon as we start executing the nvme-cli tool to list NVMe devices on the system
<pre class="ckeditor_codeblock">
sudo nvme list
Node                  Generic               SN                   Model                                    Namespace Usage                      Format           FW Rev  
--------------------- --------------------- -------------------- ---------------------------------------- --------- -------------------------- ---------------- --------
/dev/nvme0n1          /dev/ng0n1            S4DYNX0R756769       SAMSUNG MZVLB512HBJQ-000L2               1          93.05  GB / 512.11  GB    512   B +  0 B   3L1QEXF7
</pre>
<br />
The&nbsp; &quot;nvme_submit_user_cmd&quot;&nbsp;function is invoked in the NVMe Kernel driver level, and the kprobe attached by our eBPF program will trace the NVMe data structure members that we are hooked onto, opcode, command-id, nsid, cdw10<br />
&nbsp;
<pre class="ckeditor_codeblock">
sudo ./kprobe_nvme.py 
TIME      COMM      PID     OPCODE   COMMAND-ID   NSID   CDW10 
02:34:13  b&#39;nvme&#39;   32086   6        0            1      0     
02:34:13  b&#39;nvme&#39;   32086   6        0            1      3     
</pre>
<br />
This means that the nvme-cli tool triggers the &quot;nvme_submit_user_cmd&quot; nvme kernel driver function 2 times, same opcode, 0x6 (HEX)&nbsp; which in terms of&nbsp;NVMe admin commands it means &quot;Identify&quot;<br />
&nbsp;<br />
Now let&#39;s run an NVME admin passthru command to trigger a short device selt-test in the NVME SSD
<pre class="ckeditor_codeblock">
sudo nvme admin-passthru /dev/nvme0 -n 0x1 --opcode=0x14 --cdw10=0x1 -r
Admin Command Device Self-test is Success and result: 0x00000000</pre>
<br />
Now our eBPF program and kprobe captures the struct data members and the Python script prints out the following data:
<pre class="ckeditor_codeblock">
sudo ./kprobe_nvme.py 
TIME      COMM      PID     OPCODE   COMMAND-ID   NSID   CDW10 
...
02:34:47  b&#39;nvme&#39;   32094   14       0            1      1   </pre>
<br />
Opcode 0x14 (HEX) means &quot;Device Self-test&quot; according to &quot;NVM Express Base Specification Revision 2.0a&quot;&nbsp; &quot;Figure 138: Opcodes for Admin Commands&quot;<br />
cdw10&nbsp;&nbsp;Command Dword 10 is a command specific field<br />
Namespace ID is 0x1<br />
<br />
So in conclusion we were able to capture these Data Structure members of &quot;nvme_common_command&quot; structure embedded in the &quot;nvme_command&quot; structure just by writing a simple eBPF program which is built and loaded&nbsp; into the Kernel using a Python script and BCC framework, and it&#39;s attached to the kprobe of&nbsp; the &quot;nvme_submit_user_cmd&quot; function, and whenever the &quot;nvme-cli&quot; utility triggers the&nbsp; &quot;nvme_submit_user_cmd&quot; function on the NVMe Kernel driver level,&nbsp;&nbsp;the eBPF program, writes a line of trace into a perf buffer and the Python program reads the trace message from the perf buffer and displays it to the user.<br />
<br />
For this we use the&nbsp;BPF_PERF_OUTPUT&nbsp;BCC macro, which let you write data in a structure of your choosing into a perf ring buffer map.<br />
<br />
BCC defines the macro BPF_PERF_OUTPUT for creating a map that will be used to pass messages from the kernel to user space<br />
<br />
<br />
<strong>Related Documents</strong><br />
reference guide:&nbsp;<a href="https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md" target="_blank">bcc Reference Guide</a><br />
tutorial:&nbsp;<a href="https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md" target="_blank">bcc Python Developer Tutorial</a><br />
tutorial:&nbsp;<a href="https://mdaverde.com/posts/cap-bpf/" target="_blank">Introduction to CAP_BPF</a><br />
examples: <a href="https://github.com/iovisor/bcc/tree/master/tools" target="_blank">bcc eBPF python exampless</a><br />
specification: <a href="https://nvmexpress.org/wp-content/uploads/NVMe-NVM-Express-2.0a-2021.07.26-Ratified.pdf" target="_blank">NVM Express Base Specification Revision 2.0a&nbsp;</a><br />
manual: <a href="https://manpages.ubuntu.com/manpages/lunar/en/man1/nvme.1.html" target="_blank">nvme</a><br />
manual: <a href="https://manpages.ubuntu.com/manpages/lunar/man1/nvme-admin-passthru.1.html" target="_blank">nvme-admin-passthru</a><br />
blog:&nbsp;<a href="https://nakryiko.com" target="_blank">Andrii Nakryiko&#39;s Blog</a><br />
book:&nbsp;<a href="https://www.oreilly.com/library/view/learning-ebpf/9781098135119/" target="_blank">Liz Rice - Learning eBPF</a><br />
book:&nbsp;<a href="https://www.oreilly.com/library/view/linux-observability-with/9781492050193/" target="_blank">David Calavera, Lorenzo Fontana - Linux Observability with BPF</a>
<br />
<br />





# eBPF oneliner with bpftrace for tracing NVMe driver data structure members

<br />
Tracing the Kernel and Kernel driver data is crucial when you need to analyze complex scenarios, performance issues, or driver issues<br />
<br />
bpftrace is a tool that provides a high level language that you can use to easily write eBPF programs for tracing Kernel data<br />
bpftrace is built on top of BCC and the bpftrace scripts written in this high level language get converted into BCC programs which are then compiled at runtime using the LLVM and Clang toolchain<br />
You can use bpftrace to write eBPF one-liners or short eBPF programs<br />
Although bpftrace high level language is limited and cannot be used to write complex eBPF programs, there are still a lot scenarios where bpftrace comes handy<br />
bpftrace contains a lot of built-in functionality for aggregating information and creating histograms<br />
bpftrace converts programs written in the high-level language into eBPF kernel code and also provides some output formatting functionality that can be very useful to effectively show tracing results in the terminal.<br />
With bpftrace you can attach to tracing events such as kprobes, uprobes and tracepoints<br />
<br />
You can list all the tracing event that bpftrace is able to attach with:
<pre class="ckeditor_codeblock">
sudo bpftrace -l</pre>

<pre class="ckeditor_codeblock">
man bpftrace
&nbsp; &nbsp; -l [search] &nbsp; &nbsp;list probes</pre>
<br />
For example to list all the NVME driver commands:
<pre class="ckeditor_codeblock">
sudo bpftrace -l | grep nvme.*cmd

kfunc:nvme_core:__traceiter_nvme_setup_cmd
kfunc:nvme_core:nvme_cleanup_cmd
kfunc:nvme_core:nvme_cmd_allowed
kfunc:nvme_core:nvme_dev_uring_cmd
kfunc:nvme_core:nvme_ns_chr_uring_cmd
kfunc:nvme_core:nvme_ns_chr_uring_cmd_iopoll
kfunc:nvme_core:nvme_ns_head_chr_uring_cmd
kfunc:nvme_core:nvme_ns_head_chr_uring_cmd_iopoll
kfunc:nvme_core:nvme_ns_uring_cmd
kfunc:nvme_core:nvme_setup_cmd
kfunc:nvme_core:nvme_submit_sync_cmd
kfunc:nvme_core:nvme_trace_parse_admin_cmd
kfunc:nvme_core:nvme_trace_parse_fabrics_cmd
kfunc:nvme_core:nvme_trace_parse_nvm_cmd
kfunc:nvme_core:nvme_uring_cmd_end_io
kfunc:nvme_core:nvme_uring_cmd_end_io_meta
kfunc:nvme_core:nvme_uring_cmd_io
kfunc:nvme_core:nvme_user_cmd64
kprobe:__nvme_submit_sync_cmd
kprobe:__traceiter_nvme_setup_cmd
kprobe:nvme_cleanup_cmd
kprobe:nvme_cmd_allowed
kprobe:nvme_dev_uring_cmd
kprobe:nvme_ns_chr_uring_cmd
kprobe:nvme_ns_chr_uring_cmd_iopoll
kprobe:nvme_ns_head_chr_uring_cmd
kprobe:nvme_ns_head_chr_uring_cmd_iopoll
kprobe:nvme_ns_uring_cmd
kprobe:nvme_setup_cmd
kprobe:nvme_submit_sync_cmd
kprobe:nvme_submit_user_cmd
kprobe:nvme_trace_parse_admin_cmd
kprobe:nvme_trace_parse_fabrics_cmd
kprobe:nvme_trace_parse_nvm_cmd
kprobe:nvme_uring_cmd_end_io
kprobe:nvme_uring_cmd_end_io_meta
kprobe:nvme_uring_cmd_io
kprobe:nvme_user_cmd.constprop.0
kprobe:nvme_user_cmd64
tracepoint:nvme:nvme_setup_cmd</pre>
<br />
As an example we will attach a kprobe to the &quot;nvme_submit_user_cmd&quot; function in order to capture some data structure members, one of the arguments of the function which has a sepcific NVME data structure type<br />
<br />
First you need to install bpftrace with:
<pre class="ckeditor_codeblock">
sudo apt install bpftrace
</pre>
<br />
Now let&#39;s see in the Kernel code how does the&nbsp; &quot;nvme_submit_user_cmd&quot; function definition look like, what arguments does it have and what can we extract from these arguments which are passed to the&nbsp; &quot;nvme_submit_user_cmd&quot; function<br />
<br />
We can see in the Kernel source that it has a number of arguments and second argument is a pointer of type &quot;struct nvme_command&quot;
<pre class="ckeditor_codeblock">
drivers/nvme/host/ioctl.c:141

static int nvme_submit_user_cmd(struct request_queue *q,
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_command *cmd, u64 ubuffer,
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; unsigned bufflen, void __user *meta_buffer, unsigned meta_len,
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; u32 meta_seed, u64 *result, unsigned timeout, bool vec)</pre>
<br />
Let&#39;s check what members does the &quot;struct nvme_command&quot;&nbsp; have?
<pre class="ckeditor_codeblock">
grep -rnI &quot;struct nvme_command {&quot; kernel_src/</pre>

<pre class="ckeditor_codeblock">
include/linux/nvme.h:1531

struct nvme_command {
&nbsp; &nbsp; &nbsp; &nbsp; union {
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_common_command common;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_rw_command rw;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_identify identify;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_features features;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_create_cq create_cq;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_create_sq create_sq;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_delete_queue delete_queue;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_download_firmware dlfw;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_format_cmd format;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_dsm_cmd dsm;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_write_zeroes_cmd write_zeroes;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_zone_mgmt_send_cmd zms;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_zone_mgmt_recv_cmd zmr;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_abort_cmd abort;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_get_log_page_command get_log_page;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvmf_common_command fabrics;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvmf_connect_command connect;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvmf_property_set_command prop_set;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvmf_property_get_command prop_get;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_dbbuf dbbuf;
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; struct nvme_directive_cmd directive;
&nbsp; &nbsp; &nbsp; &nbsp; };
};</pre>
<br />
Within &quot;struct nvme_command&quot; we would like to access the &quot;struct nvme_common_command common&quot; member<br />
Now let&#39;s check the layout of the &quot;struct nvme_common_command&quot; data structure in the Kernel code<br />
&nbsp;
<pre class="ckeditor_codeblock">
grep -rnI &quot;struct nvme_common_command {&quot; kernel_src/

./include/linux/nvme.h:901

struct nvme_common_command {
&nbsp; &nbsp; &nbsp; &nbsp; __u8 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;opcode;
&nbsp; &nbsp; &nbsp; &nbsp; __u8 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;flags;
&nbsp; &nbsp; &nbsp; &nbsp; __u16 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; command_id;
&nbsp; &nbsp; &nbsp; &nbsp; __le32 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;nsid;
&nbsp; &nbsp; &nbsp; &nbsp; __le32 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;cdw2[2];
&nbsp; &nbsp; &nbsp; &nbsp; __le64 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;metadata;
&nbsp; &nbsp; &nbsp; &nbsp; union nvme_data_ptr &nbsp; &nbsp; dptr;
&nbsp; &nbsp; &nbsp; &nbsp; struct_group(cdws,
&nbsp; &nbsp; &nbsp; &nbsp; __le32 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;cdw10;
&nbsp; &nbsp; &nbsp; &nbsp; __le32 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;cdw11;
&nbsp; &nbsp; &nbsp; &nbsp; __le32 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;cdw12;
&nbsp; &nbsp; &nbsp; &nbsp; __le32 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;cdw13;
&nbsp; &nbsp; &nbsp; &nbsp; __le32 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;cdw14;
&nbsp; &nbsp; &nbsp; &nbsp; __le32 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;cdw15;
&nbsp; &nbsp; &nbsp; &nbsp; );
};
</pre>
<br />
&quot;struct nvme_common_command&quot; has this &quot;opcode&quot; member which value we want to capture using bpftrace<br />
<br />
Now let&#39;s write the bpftrace oneliner using the high level language provided by bpftrace
<pre class="ckeditor_codeblock">
sudo bpftrace -e &#39;kprobe:nvme_submit_user_cmd {&nbsp;
printf(&quot;opcode: %x\n&quot;, ((struct nvme_command *)arg1)-&gt;common.opcode);
printf(&quot;command_id: %x\n&quot;, ((struct nvme_command *)arg1)-&gt;common.command_id);&nbsp;
printf(&quot;nsid: %x\n&quot;, ((struct nvme_command *)arg1)-&gt;common.nsid);&nbsp;
printf(&quot;cdw10: %x\n&quot;, ((struct nvme_command *)arg1)-&gt;common.cdw10);&nbsp;
}&#39;
</pre>
<br />
As you can see the oneliner attaches a kprobe to the &quot;nvme_submit_user_cmd&quot; function<br />
<br />
arg0 is the first argument, arg1 is the second argument and so on and so forth...<br />
<br />
So in order to refer to the second argument of the &quot;nvme_submit_user_cmd&quot; function, that is &quot;struct nvme_command *cmd&quot; we must write arg1 in the oneliner<br />
<br />
We have to do typecasting of arg1 to &quot;struct nvme_command&quot; pointer as in the function signature, since arg1 is the second argument which takes a pointer to&nbsp;&quot;struct nvme_command&quot;.<br />
Also in order to access the data members of pointer&nbsp;&quot;struct nvme_command&quot; we use the arrow operator just like in C/C++ and since &quot;nvme_command&quot; has a data member called &quot;common&quot; which is of type &quot;struct nvme_common_command&quot; and not a pointer then we use the dot operator to access all of &quot;nvme_common_command&quot; data members<br />
<br />
&quot;-e&quot;&nbsp; parameter in bpftrace means&nbsp; that we wish bpftrace to execute this or that eBPF program
<pre class="ckeditor_codeblock">
man bpftrace
&nbsp; &nbsp; -e &#39;program&#39; &nbsp; execute this program</pre>
Now let&#39;s install nvme-cli&nbsp; in order to send an admin command to one of the NVME SSD devices

<pre class="ckeditor_codeblock">
sudo apt install nvme-cli</pre>
<br />
Then start running the eBPF oneliner through bpftrace
<pre class="ckeditor_codeblock">
sudo bpftrace -e &#39;kprobe:nvme_submit_user_cmd {&nbsp;
printf(&quot;opcode: %x\n&quot;, ((struct nvme_command *)arg1)-&gt;common.opcode);
printf(&quot;command_id: %x\n&quot;, ((struct nvme_command *)arg1)-&gt;common.command_id);&nbsp;
printf(&quot;nsid: %x\n&quot;, ((struct nvme_command *)arg1)-&gt;common.nsid);&nbsp;
printf(&quot;cdw10: %x\n&quot;, ((struct nvme_command *)arg1)-&gt;common.cdw10);&nbsp;
}&#39;
Attaching 1 probe...</pre>
<br />
Here the printout says that 1 kprobe is now attached<br />
<br />
And we can also check this fact with:
<pre class="ckeditor_codeblock">
sudo cat /sys/kernel/debug/kprobes/list
ffffffffc077a380 &nbsp;k &nbsp;nvme_submit_user_cmd+0x0 &nbsp;nvme_core [FTRACE]</pre>
<br />
Now let&#39;s list the NVME devices&nbsp;
<pre class="ckeditor_codeblock">
sudo nvme list
Node &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;Generic &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; SN &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; Model &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;Namespace Usage &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;Format &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; FW Rev &nbsp;
--------------------- --------------------- -------------------- ---------------------------------------- --------- -------------------------- ---------------- --------
/dev/nvme0n1 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;/dev/ng0n1 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;S4DYNX0R756769 &nbsp; &nbsp; &nbsp; SAMSUNG MZVLB512HBJQ-000L2 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; 1 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;94.17 &nbsp;GB / 512.11 &nbsp;GB &nbsp; &nbsp;512 &nbsp; B + &nbsp;0 B &nbsp; 3L1QEXF7</pre>
<br />
As soon as we shuffle the nvme-cli command ,&nbsp; bptrace is capturing and printing the following data:
<pre class="ckeditor_codeblock">
sudo bpftrace -e &#39;kprobe:nvme_submit_user_cmd {&nbsp;
printf(&quot;opcode: %x\n&quot;, ((struct nvme_command *)arg1)-&gt;common.opcode);
printf(&quot;command_id: %x\n&quot;, ((struct nvme_command *)arg1)-&gt;common.command_id);&nbsp;
printf(&quot;nsid: %x\n&quot;, ((struct nvme_command *)arg1)-&gt;common.nsid);&nbsp;
printf(&quot;cdw10: %x\n&quot;, ((struct nvme_command *)arg1)-&gt;common.cdw10);&nbsp;
}&#39;
Attaching 1 probe...</pre>

<pre class="ckeditor_codeblock">
opcode: 6
command_id: 0
nsid: 1
cdw10: 0

opcode: 6
command_id: 0
nsid: 1
cdw10: 3</pre>
<br />
This means that the nvme-cli tool triggers the &quot;nvme_submit_user_cmd&quot; nvme kernel driver function 2 times, same opcode, 0x6 (HEX)&nbsp; which in terms of&nbsp;NVMe admin commands it means &quot;Identify&quot;<br />
&nbsp;<br />
Now let&#39;s run an NVME admin passthru command to trigger a short device selt-test in the NVME SSD
<pre class="ckeditor_codeblock">
sudo nvme admin-passthru /dev/nvme0 -n 0x1 --opcode=0x14 --cdw10=0x1 -r

Admin Command Device Self-test is Success and result: 0x00000000</pre>
<br />
Now bpftrace captures and prints out the following data:
<pre class="ckeditor_codeblock">
opcode: 14
command_id: 0
nsid: 1
cdw10: 1
</pre>
<br />
Opcode 0x14 (HEX) means &quot;Device Self-test&quot; according to &quot;NVM Express Base Specification Revision 2.0a&quot;&nbsp; &quot;Figure 138: Opcodes for Admin Commands&quot;<br />
cdw10&nbsp;&nbsp;Command Dword 10 is a command specific field<br />
Namespace ID is 0x1<br />
<br />
So in conclusion we were able to capture these Data Structure members of &quot;nvme_common_command&quot; structure embedded in the &quot;nvme_command&quot; structure just by writing a simple eBPF one-liner program and load it through bpftrace as a kprobe attached to the &quot;nvme_submit_user_cmd&quot; function.<br />
<br />
<strong>Related Documents:</strong><br />
specification:&nbsp;<a href="https://nvmexpress.org/wp-content/uploads/NVMe-NVM-Express-2.0a-2021.07.26-Ratified.pdf" target="_blank">NVM Express Base Specification Revision 2.0a</a><br />
reference guide:&nbsp;<a href="https://github.com/iovisor/bpftrace/blob/master/docs/reference_guide.md" target="_blank">bpftrace Reference Guide</a><br />
manual: <a href="https://manpages.ubuntu.com/manpages/lunar/en/man1/nvme.1.html" target="_blank">nvme</a><br />
manual: <a href="https://manpages.ubuntu.com/manpages/lunar/man1/nvme-admin-passthru.1.html" target="_blank">nvme-admin-passthru</a><br />
tutorial: <a href="https://github.com/iovisor/bpftrace/blob/master/docs/tutorial_one_liners.md" target="_blank">The bpftrace One-Liner Tutorial</a><br />
cheat sheet: <a href="https://www.brendangregg.com/BPF/bpftrace-cheat-sheet.html" target="_blank">bpftrace Cheat Sheet</a><br />
intro: <a href="https://www.brendangregg.com/blog/2019-08-19/bpftrace.html" target="_blank">Brendan Gregg - A thorough introduction to bpftrace</a><br />
blog:&nbsp;<a href="https://nakryiko.com" target="_blank">Andrii Nakryiko&#39;s Blog</a><br />
book:&nbsp;<a href="https://www.oreilly.com/library/view/learning-ebpf/9781098135119/" target="_blank">Liz Rice - Learning eBPF</a><br />
book:&nbsp;<a href="https://www.oreilly.com/library/view/linux-observability-with/9781492050193/" target="_blank">David Calavera, Lorenzo Fontana - Linux Observability with BPF</a><br />
<br />
&nbsp;
