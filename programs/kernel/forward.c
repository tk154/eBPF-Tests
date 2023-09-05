#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/socket.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "common_xdp_tc.h"


#define SRC_ADDR (192 | 168 << 8 | 1 << 16 | 2 << 24)
#define DST_ADDR (192 | 168 << 8 | 2 << 16 | 2 << 24)

#define IFINDEX 11
#define IF_MAC  { 0x50, 0x6b, 0x4b, 0x9f, 0x04, 0x51 }
#define DST_MAC { 0x00, 0x0e, 0x0c, 0x32, 0xf8, 0x6a }


SEC("forward")
int forward_func(struct BPF_CTX* ctx) {
    void* data     = (void*)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;

    void* p = data;
    parse_header(struct ethhdr, *ethh, p, data_end);

    if (ethh->h_proto == bpf_htons(ETH_P_IP)) {
		parse_header(struct iphdr, *iph, p, data_end);

        if ((iph->saddr) == SRC_ADDR && (iph->daddr) == DST_ADDR) {
            unsigned char src[ETH_ALEN] = IF_MAC;
            unsigned char dst[ETH_ALEN] = DST_MAC;

            memcpy(ethh->h_source, src, ETH_ALEN);
            memcpy(ethh->h_dest, dst, ETH_ALEN);

            return bpf_redirect(IFINDEX, 0);
        }
    }

    return BPF_PASS;
}

char _license[] SEC("license") = "GPL";
