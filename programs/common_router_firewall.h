#ifndef COMMON_ROUTER_FIREWALL_H
#define COMMON_ROUTER_FIREWALL_H

#define STRINGIZE(x) #x
#define MAP_TO_STRING(map) STRINGIZE(map)           // Used to get the map name as a string (used for user space programs)


// if_rules_map
// Key is ifindex, value is a Bitmask
#define IF_RULES_MAP                if_rules_map    // Used to lookup wether incoming, outgoing or redirecting of packages are allowed on an interface
#define IF_RULES_MAP_MAX_ENTRIES    16              // Max. entries of if_rules_map (Can be set to the max. number of interfaces)

#define IF_ACCEPT_INPUT             0x1             // Bit which allows incoming packages on the interface
#define IF_ACCEPT_OUTPUT            0x2             // Bit which allows outgoing packages on the interface
#define IF_ACCEPT_FORWARD           0x4             // Bit which allows incoming packages to be redirected on the interface
#define IF_ACCEPT_ALL (IF_ACCEPT_INPUT | IF_ACCEPT_OUTPUT | IF_ACCEPT_FORWARD)      // Bits which allow all prior rules

typedef __u8 if_rule;                               // One Byte to store the rules Bitmask in if_rules_map


// if_vlans_map, key is ifindex
#define IF_VLANS_MAP                if_vlans_map    // Used to loopkup the VLANs of an interface
#define IF_VLANS_MAP_MAX_ENTRIES    16              // Max. entries of if_vlans_map (Can be set to the max. number of interfaces)
#define IF_MAX_VLANS                4               // Max. number of VLANS per network interface (This value should be at least 1)

struct if_vlans {                                   // Datastruct to store the VLANs of an interface inside if_vlans_map
    unsigned int count;                             // VLAN count
    __u16 vlans[IF_MAX_VLANS];                      // Used to store the VLAN IDs (only VLAN IDs at index < count are valid)
};


// rout_stats_map
// Key is hash of src and dst IP pair
#define ROUT_STATS_MAP              rout_stats_map  // Can be used to lookup how much packets and Bytes have been routed between a source and destination IP
#define ROUT_STATS_MAP_MAX_ENTRIES  16              // Max. entries of rout_stats_map

struct ip_pair {                                    // Key for rout_stats_map
	__be32 src;                                     // Source IPv4 address of the routed package
	__be32 dst;                                     // Destination IPv4 of the routed package
};

struct datarec {                                    // Datastruct to count the number routed of routed packages and Bytes between a source and destination IP
    __u64 packets;                                  // Number of routed packages
    __u64 bytes;                                    // Number of routed Bytes
};


#endif
