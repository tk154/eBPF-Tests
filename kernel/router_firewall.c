#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>

#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// Controls wether there should be debug messages about received packages
#define DEBUG 1
#include "common_xdp_tc.h"
#include "../common_router_firewall.h"


// rout_stats_map
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, struct ip_pair);
	__type(value, struct datarec);
	__uint(max_entries, ROUT_STATS_MAP_MAX_ENTRIES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ROUT_STATS_MAP SEC(".maps");

// if_rules_map
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, unsigned int);
	__type(value, if_rule);
	__uint(max_entries, IF_RULES_MAP_MAX_ENTRIES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} IF_RULES_MAP SEC(".maps");

// if_vlans_map
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, unsigned int);
	__type(value, struct if_vlans);
	__uint(max_entries, IF_VLANS_MAP_MAX_ENTRIES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} IF_VLANS_MAP SEC(".maps");


// Declare the VLAN header struct manually since it is not included in my <linux/if_vlan.h>
struct vlan_hdr {
	__be16 h_vlan_TCI;					// priority and VLAN ID
	__be16 h_vlan_encapsulated_proto;	// packet type ID or len
};

/**
 * Saves the packet data inside rout_stats_map
 * @param src Source IPv4 address of the routed package
 * @param dst Destination IPv4 address of the routed package
 * @param bytes Size of the routed package in Bytes
 * @returns 0 on success, or a negative error in case of failure (e.g. Max. entries reached)
**/
int save_packet_data(__u32 src, __u32 dst, __u64 bytes) {
	// Create an IP pair from src and dst IP
    struct ip_pair key = { .src = src, .dst = dst };
	int rc = 0;

	// Lookup if there are already stats for the IP pair
    struct datarec* rec = bpf_map_lookup_elem(&ROUT_STATS_MAP, &key);
    if (!rec) {
		// If not create a new stats entry and save it
		struct datarec new_rec = { .packets = 1, .bytes = bytes };
		rc = bpf_map_update_elem(&ROUT_STATS_MAP, &key, &new_rec, BPF_NOEXIST);
	}
	else {
		// Update the routing stats entry
		rec->packets++;
		rec->bytes += bytes;
	}

    return rc;
}

/**
 * Checks if the VLAN ID of the package matches any VLAN ID of the interface.
 * A packet VLAN ID 0 means that package doesn't have a VLAN header
 * @param ifindex The index of the to-be-checked interface VLANs
 * @param packet_vlan The VLAN ID of the received package
 * @returns 1 if the VLAN ID matches with one of the interface, 0 otherwise
**/
int isVlanMatch(unsigned int ifindex, __u16 packet_vlan) {
	// Lookup the VLAN IDs of the interface
	struct if_vlans* vlans = bpf_map_lookup_elem(&IF_VLANS_MAP, &ifindex);

	// If the interface doesn't have a VLAN, the package must also have no VLAN to match
	if (vlans == NULL)
		return packet_vlan == 0;

	// Unroll the loop to avoid BPF verifier errors
	// Only constant loops can be unrolled
	#pragma unroll
	for (int i = 0; i < IF_MAX_VLANS; i++) {
		// Break out if there is no more VLAN on the interface
		if (i == vlans->count)
			break;

		// If one of the VLANs match
		if (vlans->vlans[i] == packet_vlan)
			return 1;
	}

	// If none of the VLANs matched
	return 0;
}

/**
 * Check the interface rules map if the to-be-executed package operation(s) is allowed
 * @param ifindex The index of the to-be-checked rule
 * @param rule The Bitmask of the to-be-executed operation(s)
 * @returns 1 if the operations is allowed, 0 otherwise
**/
int isAllowed(unsigned int ifindex, if_rule rule) {
	// Lookup the rules of the interface, if there are none default to as if nothing is allowed
    if_rule* firewall_rule = bpf_map_lookup_elem(&IF_RULES_MAP, &ifindex);
    if (firewall_rule == NULL)
        return 0;

	// Check if all the Bits are set
    return (*firewall_rule & rule) == rule;
}


SEC("router_firewall")
/**
 * Entry point of the BPF program executed when a new package is received on the hook
 * @param ctx The package contents and some metadata. Type is xdp_md for XDP and __sk_buff for TC programs.
 * @returns The action to be executed on the received package
**/
int router_firewall_func(struct BPF_CTX *ctx) {
	BPF_DEBUG("---------- New package received ----------");

	// Save the first and last Byte of the received package
	void* data 	   = (void*)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;

	// A pointer to save the cuurent position inside the package
	void* p = data;

	// Parse the Ethernet header, will drop the package if out-of-bounds
	parse_header(struct ethhdr, *ethh, p, data_end);

	// Save the packet type ID, default to no VLAN ID
    __be16 h_proto = ethh->h_proto;
    __u16 vlan_id = 0;

	// Check if there is a VLAN header
    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
		// Parse the VLAN header, will drop the package if out-of-bounds
		parse_header(struct vlan_hdr, *vlan_h, p, data_end);

		// Save the VLAN ID (last 12 Byte)
        vlan_id = bpf_htons(vlan_h->h_vlan_TCI) & 0x0FFF;
		BPF_DEBUG("VLAN ID: %d", vlan_id);

		// Save the packet type ID of the next header
		h_proto = vlan_h->h_vlan_encapsulated_proto;
    }

	// If an IPv4 package has been received
	if (h_proto == bpf_htons(ETH_P_IP)) {
		// Parse the IPv4 header, will drop the package if out-of-bounds
		parse_header(struct iphdr, *iph, p, data_end);

		BPF_DEBUG_IP("Source IP: ", iph->saddr);
		BPF_DEBUG_IP("Destination IP: ", iph->daddr);

		// Pass the package if the TTL is exceeded
		if (iph->ttl <= 1) {
			BPF_DEBUG("Time to live exceeded");
			return BPF_PASS;
		}

		// Save the source and destination port if there is a TCP or UDP header
		__be16 sport = 0, dport = 0;
        if (iph->protocol == IPPROTO_TCP) {
			// Parse the TCP header, will drop the package if out-of-bounds
            parse_header(struct tcphdr, *tcph, p, data_end);

            sport = tcph->source;
			dport = tcph->dest;
        }
        else if (iph->protocol == IPPROTO_UDP) {
			// Parse the UDP header, will drop the package if out-of-bounds
            parse_header(struct udphdr, *udph, p, data_end);

			sport = udph->source;
			dport = udph->dest;
        }

		// Do a FIB loopkup in the kernel tables
		struct bpf_fib_lookup fib_params = {};
		fib_params.family = AF_INET;
		fib_params.l4_protocol = iph->protocol;
		fib_params.sport = sport;
		fib_params.dport = dport;
		fib_params.tot_len = bpf_ntohs(iph->tot_len);
		fib_params.tos = iph->tos;
		fib_params.ipv4_src = iph->saddr;
		fib_params.ipv4_dst = iph->daddr;
		fib_params.ifindex = ctx->ingress_ifindex;

		long fib_lookup_rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
		BPF_DEBUG("bpf_fib_lookup: %d", fib_lookup_rc);

		switch (fib_lookup_rc) { 
			case BPF_FIB_LKUP_RET_SUCCESS:
				// Drop the package if its VLAN doesn't match with the one from incoming or outgoing interface
				if (!isVlanMatch(ctx->ingress_ifindex, vlan_id) || !isVlanMatch(fib_params.ifindex, vlan_id)) {
					BPF_DEBUG("VLANs don't match");
					return BPF_DROP;
				}

				// Drop the package if the incoming interface doesn't allow forwarding or if the outgoing doesn't allow to send packages
                if (!isAllowed(ctx->ingress_ifindex, IF_ACCEPT_FORWARD) || !isAllowed(fib_params.ifindex, IF_ACCEPT_OUTPUT)) {
					BPF_DEBUG("Rule doesn't allow forwarding");
                    return BPF_DROP;
				}

				// Save the package data inside the rout_stats_map
				save_packet_data(iph->saddr, iph->daddr, data_end - data);

				// Set the new MAC adresses inside the package
				memcpy(ethh->h_source, fib_params.smac, ETH_ALEN);
				memcpy(ethh->h_dest, fib_params.dmac, ETH_ALEN);

				// Decrement the TTL, adjust the checksum
				iph->ttl--;
				iph->check += 0x01;

				// Redirect the package to the interface
				return bpf_redirect(fib_params.ifindex, 0);

			case BPF_FIB_LKUP_RET_BLACKHOLE:  
			case BPF_FIB_LKUP_RET_UNREACHABLE:
			case BPF_FIB_LKUP_RET_PROHIBIT:   
				return BPF_DROP;

			case BPF_FIB_LKUP_RET_NOT_FWDED:   
			case BPF_FIB_LKUP_RET_FWD_DISABLED:
			case BPF_FIB_LKUP_RET_UNSUPP_LWT:  
			case BPF_FIB_LKUP_RET_NO_NEIGH:    
			case BPF_FIB_LKUP_RET_FRAG_NEEDED: 
				// Drop the package if its VLAN doesn't match with the one from the interface
				if (!isVlanMatch(ctx->ingress_ifindex, vlan_id)) {
					BPF_DEBUG("VLANs don't match");
					return BPF_DROP;
				}

				// Drop the package if the interface is not allowed to receive packages
                if (!isAllowed(ctx->ingress_ifindex, IF_ACCEPT_INPUT)) {
					BPF_DEBUG("Rule doesn't allow input");
                    return BPF_DROP;
				}
		}
	}

	// Let the package pass if it is allowed to or it doesn't have an IPv4 header
    return BPF_PASS;
}

char _license[] SEC("license") = "GPL";
