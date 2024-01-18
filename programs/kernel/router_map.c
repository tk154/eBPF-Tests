#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include <arpa/inet.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define DEBUG 0
#include "common_xdp_tc.h"


enum {
	ACTION_PASS = 1,
	ACTION_DROP,
	ACTION_REDIRECT
};

struct rout_key {
	__u32  ifindex;
	__be32 src_ip, dst_ip;
};

struct rout_val {
	__u32 ifindex;
	__u8 src_mac[ETH_ALEN];
	__u8 dst_mac[ETH_ALEN];
	__u8 action;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct rout_key);
	__type(value, struct rout_val);
	__uint(max_entries, 64);
	//__uint(pinning, LIBBPF_PIN_BY_NAME);
} rt_map SEC(".maps");


__always_inline void make_routing_decision(struct BPF_CTX *ctx, struct iphdr* iph, struct rout_val* rt_val) {
	// Fill the lookup key
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

	// Do a loopkup in the kernel routing table
	long rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
	BPF_DEBUG("bpf_fib_lookup: %d", rc);
	BPF_DEBUG("ifindex: %d", fib_params.ifindex);

	switch (rc) { 
		case BPF_FIB_LKUP_RET_SUCCESS:      // lookup successful
			// Save the MAC addresses inside the map
			memcpy(rt_val->src_mac, fib_params.smac, ETH_ALEN);
			memcpy(rt_val->dst_mac, fib_params.dmac, ETH_ALEN);

			rt_val->ifindex = fib_params.ifindex;
			rt_val->action  = ACTION_REDIRECT;
		break;

		case BPF_FIB_LKUP_RET_BLACKHOLE:    // dest is blackholed; can be dropped 
		case BPF_FIB_LKUP_RET_UNREACHABLE:  // dest is unreachable; can be dropped 
		case BPF_FIB_LKUP_RET_PROHIBIT:     // dest not allowed; can be dropped 
			rt_val->action  = ACTION_DROP;
		break;

		case BPF_FIB_LKUP_RET_NOT_FWDED:    // packet is not forwarded 
		case BPF_FIB_LKUP_RET_FWD_DISABLED: // fwding is not enabled on ingress 
		case BPF_FIB_LKUP_RET_UNSUPP_LWT:   // fwd requires encapsulation 
		case BPF_FIB_LKUP_RET_NO_NEIGH:     // no neighbor entry for nh
		case BPF_FIB_LKUP_RET_FRAG_NEEDED:  // fragmentation required to fwd
		default:
			rt_val->action  = ACTION_PASS;
	}
}

__always_inline long redirect_package(struct ethhdr* ethh, struct iphdr* iph, struct rout_val* rt_val) {
	// Decrement the TTL
	iph->ttl--;

	// Copied from net/ip.h
	__u32 check = (__u32)iph->check;
	check += (__u32)bpf_htons(0x0100);
	iph->check = (__sum16)(check + (check >= 0xFFFF));

	// Adjust the MAC addresses
	memcpy(ethh->h_source, rt_val->src_mac, ETH_ALEN);
	memcpy(ethh->h_dest,   rt_val->dst_mac, ETH_ALEN);

	// Redirect the package
	return bpf_redirect(rt_val->ifindex, 0);
}


SEC("router")
int router_map(struct BPF_CTX *ctx) {
	void* data 	   = (void*)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;

	void* p = data;
	parse_header(struct ethhdr, *ethh, p, data_end);

	if (ethh->h_proto == bpf_htons(ETH_P_IP)) {
		BPF_DEBUG("---------- New package received ----------");

		parse_header(struct iphdr, *iph, p, data_end);

		BPF_DEBUG_IP("Source IP: ", 	 iph->saddr);
		BPF_DEBUG_IP("Destination IP: ", iph->daddr);

		struct rout_key rt_key = {};
		rt_key.ifindex = ctx->ingress_ifindex;
		rt_key.src_ip  = iph->saddr;
		rt_key.dst_ip  = iph->daddr;

		struct rout_val* rt_val = bpf_map_lookup_elem(&rt_map, &rt_key);
		if (!rt_val) {
			struct rout_val new_rt = {};

			make_routing_decision(ctx, iph, &new_rt);
			bpf_map_update_elem(&rt_map, &rt_key, &new_rt, BPF_NOEXIST);
			
			rt_val = bpf_map_lookup_elem(&rt_map, &rt_key);
			if (!rt_val)
				return BPF_DROP;
		}

		switch (rt_val->action) {
			case ACTION_REDIRECT:
				if (iph->ttl <= 1)
					return BPF_PASS;

				return redirect_package(ethh, iph, rt_val);

			case ACTION_PASS:
				return BPF_PASS;

			default:
				return BPF_DROP;
		}
	}

	return BPF_PASS;
}

char _license[] SEC("license") = "GPL";
