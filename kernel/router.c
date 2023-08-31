#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include <arpa/inet.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "common_xdp_tc.h"
#include "../common_router.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, struct ip_pair);
	__type(value, struct datarec);
	__uint(max_entries, ROUT_STATS_MAP_MAX_ENTRIES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ROUT_STATS_MAP SEC(".maps");


int save_packet_data(__u32 src, __u32 dst, __u64 bytes) {
    struct ip_pair key = { .src = src, .dst = dst };

    struct datarec* rec = bpf_map_lookup_elem(&ROUT_STATS_MAP, &key);
    if (!rec) {
		struct datarec new_rec = { .packets = 1, .bytes = bytes };
		bpf_map_update_elem(&ROUT_STATS_MAP, &key, &new_rec, BPF_NOEXIST);
	}
	else {
		rec->packets++;
		rec->bytes += bytes;
	}

    return 0;
}


SEC("router")
int router_func(struct BPF_CTX *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

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

		if (iph->ttl <= 1)
			return BPF_PASS;

		struct bpf_fib_lookup fib_params = {};
		fib_params.family = AF_INET;
		fib_params.l4_protocol = iph->protocol;
		fib_params.sport = 0;
		fib_params.dport = 0;
		fib_params.tot_len = bpf_ntohs(iph->tot_len);
		fib_params.tos = iph->tos;
		fib_params.ipv4_src = iph->saddr;
		fib_params.ipv4_dst = iph->daddr;
		fib_params.ifindex = ctx->ingress_ifindex;

		int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
		//bpf_printk("bpf_fib_lookup: %d", rc);

		switch (rc) { 
			case BPF_FIB_LKUP_RET_SUCCESS:      // lookup successful
				save_packet_data(iph->saddr, iph->daddr, data_end - data);

				memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
				memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);

				// Decrement the TTL, adjust the checksum
				iph->ttl--;
				iph->check += 0x01;

				return bpf_redirect(fib_params.ifindex, 0);

			case BPF_FIB_LKUP_RET_BLACKHOLE:    // dest is blackholed; can be dropped 
			case BPF_FIB_LKUP_RET_UNREACHABLE:  // dest is unreachable; can be dropped 
			case BPF_FIB_LKUP_RET_PROHIBIT:     // dest not allowed; can be dropped 
				return BPF_DROP;

			case BPF_FIB_LKUP_RET_NOT_FWDED:    // packet is not forwarded 
			case BPF_FIB_LKUP_RET_FWD_DISABLED: // fwding is not enabled on ingress 
			case BPF_FIB_LKUP_RET_UNSUPP_LWT:   // fwd requires encapsulation 
			case BPF_FIB_LKUP_RET_NO_NEIGH:     // no neighbor entry for nh 
			case BPF_FIB_LKUP_RET_FRAG_NEEDED:  // fragmentation required to fwd 
				// PASS
				break;
		}
	}

    return BPF_PASS;
}

char _license[] SEC("license") = "GPL";
