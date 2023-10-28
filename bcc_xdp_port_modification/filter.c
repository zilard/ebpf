#define KBUILD_MODNAME "filter"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>

// udpfilter will get called each time a new packet comes in on our network interface.
// The packet is contained in the xdp_md struct that gets passed into our function.

int udpfilter(struct xdp_md *ctx) { 

    // we want to print that we received a packet
    // Messages from bpf_trace_printk() will be passed 
    // to b.trace_print() in our loader program
    bpf_trace_printk("got a packet\n"); 

    // we pull pointers to the start and end of the packet out of the xdp_md struct.
    void *data = (void *)(long)ctx->data; 
    void *data_end = (void *)(long)ctx->data_end; 


    // we create an Ethernet header struct pointer and point it at the start of the packet data.
    // This lets us use offsets provided in the Ethernet header struct to reference packet fields.
    // It's a common technique used in low-level networking code.

    struct ethhdr *eth = data;


    // before we do anything with the ethernet header, 
    // we need to verify that there is actually enough data present to fill the header.
    if ((void*)eth + sizeof(*eth) <= data_end) { 

        struct iphdr *ip = data + sizeof(*eth); 

        // The same is true for the IPv4 header
        // verify that there is actually enough data present to fill the header.
        if ((void*)ip + sizeof(*ip) <= data_end) { 

            // In this example, I am making an assumption that the packets we receive 
            // will be IPv4 packets and not IPv6 packets.
            // code will break if any IPv6 packets traverse the network interface.

            if (ip->protocol == IPPROTO_UDP) { 
    
                // After doing additional bounds checking and mapping the udphdr struct to the data, 
                struct udphdr *udp = (void*)ip + sizeof(*ip); 

                if ((void*)udp + sizeof(*udp) <= data_end) { 

                    // we check to see if the packet's destination port is 7999
                    // Because the literal 7999 is represented in host byte order (little-endian, 0x3f1f) 
                    // while the port number is represented in network byte order (big-endian, 0x1f3f), 
                    // we use the htons function ("host to network short") to properly compare them.
                    if (udp->dest == htons(7999)) { 

                        bpf_trace_printk("udp port 7999\n"); 
 
                        // If the packet's UDP destination port was in fact 7999,
                        // then we modify the destination port value to 7998. 
                        // Note that because the udp struct pointer still points to an offset from the original data pointer,
                        // we are modifying the raw bytes of the packet itself, not a copy.
                        udp->dest = htons(7998); 

                    } 

                } 

            } 

        } 

    } 

    // regardless of whether we modified the packet or not, 
    // we return XDP_PASS to pass the packet up to the normal network stack for further processing.
    return XDP_PASS; 

}

