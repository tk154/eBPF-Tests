#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/socket.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "common_xdp_tc.h"


#define SRC_ADDR (192 | 168 << 8 | 1 << 16 | 2 << 24)
#define DST_ADDR (192 | 168 << 8 | 2 << 16 | 2 << 24)

#define REDIRECT_IFINDEX 11
#define IFINDEX_MAC { 0x50, 0x6b, 0x4b, 0x9f, 0x04, 0x51 }
#define DST_MAC     { 0x00, 0x0e, 0x0c, 0x32, 0xf8, 0x6a }


SEC("forward")
int forward_func(struct BPF_CTX* ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

    void* p = data;

    struct ethhdr* eth = p;
    int hdrsize = sizeof(*eth);

    if (p + hdrsize > data_end)
		return BPF_DROP;

	p += hdrsize;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr* iph = p;
		hdrsize = sizeof(*iph);

		if (p + hdrsize > data_end)
			return BPF_DROP;

        if ((iph->saddr) == SRC_ADDR && (iph->daddr) == DST_ADDR) {
            unsigned char src[ETH_ALEN] = IFINDEX_MAC;
            unsigned char dst[ETH_ALEN] = DST_MAC;

            memcpy(eth->h_source, src, ETH_ALEN);
            memcpy(eth->h_dest, dst, ETH_ALEN);

            return bpf_redirect(REDIRECT_IFINDEX, 0);
        }
    }

    return BPF_PASS;
}

char _license[] SEC("license") = "GPL";
