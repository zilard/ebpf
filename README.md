# How to write eBPF program using the libbpf framework
<br />
<strong>Problem Description</strong><br />
<br />
In order to make eBPF programs portable across different versions of the Kernel, we have to write our eBPF programs using the CO-RE approach (compile once, run everywhere)<br />
CO-RE allows eBPF programs to include information about the layout of data structures they were compile with, and has a mechanism for adjusting how fields (members) are accessed in the data structure layout<br />
The Linux Kernel source code headers can change between version of Linux and an eBPF program can&nbsp; include several individual header files, but we can also use bpftool to generate vmlinux.h header file from a running system containing all the data structure information of the Kernel that an eBPF program might need to use.<br />
<br />
<strong>Solution</strong><br />
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
  MKDIR    /home/szilard/nvme_ebpf/.output//libbpf/staticobjs
  CC       /home/szilard/nvme_ebpf/.output//libbpf/staticobjs/bpf.o
  CC       /home/szilard/nvme_ebpf/.output//libbpf/staticobjs/btf.o
  CC       /home/szilard/nvme_ebpf/.output//libbpf/staticobjs/libbpf.o
  CC       /home/szilard/nvme_ebpf/.output//libbpf/staticobjs/libbpf_errno.o
  CC       /home/szilard/nvme_ebpf/.output//libbpf/staticobjs/netlink.o
  CC       /home/szilard/nvme_ebpf/.output//libbpf/staticobjs/nlattr.o
  CC       /home/szilard/nvme_ebpf/.output//libbpf/staticobjs/str_error.o
  CC       /home/szilard/nvme_ebpf/.output//libbpf/staticobjs/libbpf_probes.o
  CC       /home/szilard/nvme_ebpf/.output//libbpf/staticobjs/bpf_prog_linfo.o
  CC       /home/szilard/nvme_ebpf/.output//libbpf/staticobjs/btf_dump.o
  CC       /home/szilard/nvme_ebpf/.output//libbpf/staticobjs/hashmap.o
  CC       /home/szilard/nvme_ebpf/.output//libbpf/staticobjs/ringbuf.o
  CC       /home/szilard/nvme_ebpf/.output//libbpf/staticobjs/strset.o
  CC       /home/szilard/nvme_ebpf/.output//libbpf/staticobjs/linker.o
  CC       /home/szilard/nvme_ebpf/.output//libbpf/staticobjs/gen_loader.o
  CC       /home/szilard/nvme_ebpf/.output//libbpf/staticobjs/relo_core.o
  CC       /home/szilard/nvme_ebpf/.output//libbpf/staticobjs/usdt.o
  CC       /home/szilard/nvme_ebpf/.output//libbpf/staticobjs/zip.o
  AR       /home/szilard/nvme_ebpf/.output//libbpf/libbpf.a
  INSTALL  bpf.h libbpf.h btf.h libbpf_common.h libbpf_legacy.h bpf_helpers.h bpf_helper_defs.h bpf_tracing.h bpf_endian.h bpf_core_read.h skel_internal.h libbpf_version.h usdt.bpf.h
  INSTALL  /home/szilard/nvme_ebpf/.output//libbpf/libbpf.pc
  INSTALL  /home/szilard/nvme_ebpf/.output//libbpf/libbpf.a 
  MKDIR    bpftool
  BPFTOOL  bpftool/bootstrap/bpftool
...                        libbfd: [ on  ]
...               clang-bpf-co-re: [ on  ]
...                          llvm: [ on  ]
...                        libcap: [ OFF ]
  MKDIR    /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/include/bpf
  INSTALL  /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/include/bpf/hashmap.h
  INSTALL  /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/include/bpf/relo_core.h
  INSTALL  /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/include/bpf/libbpf_internal.h
  MKDIR    /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/
  MKDIR    /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/
  MKDIR    /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs
  CC       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/bpf.o
  CC       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/btf.o
  CC       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/libbpf.o
  CC       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/libbpf_errno.o
  CC       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/netlink.o
  CC       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/nlattr.o
  CC       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/str_error.o
  CC       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/libbpf_probes.o
  CC       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/bpf_prog_linfo.o
  CC       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/btf_dump.o
  CC       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/hashmap.o
  CC       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/ringbuf.o
  CC       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/strset.o
  CC       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/linker.o
  CC       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/gen_loader.o
  CC       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/relo_core.o
  CC       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/staticobjs/usdt.o
  AR       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/libbpf/libbpf.a
  INSTALL  bpf.h libbpf.h btf.h libbpf_common.h libbpf_legacy.h bpf_helpers.h bpf_helper_defs.h bpf_tracing.h bpf_endian.h bpf_core_read.h skel_internal.h libbpf_version.h usdt.bpf.h
  CC       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/main.o
  CC       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/common.o
  CC       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/json_writer.o
  CC       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/gen.o
  CC       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/btf.o
  CC       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/xlated_dumper.o
  CC       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/btf_dumper.o
  CC       /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/disasm.o
  LINK     /home/szilard/nvme_ebpf/.output/bpftool/bootstrap/bpftool
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
