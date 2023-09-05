#ifndef COMMON_KERN_USER
#define COMMON_KERN_USER

#include <linux/in.h>

#define STRINGIZE(x) #x
#define MAP_TO_STRING(map) STRINGIZE(map)           // Used to get the map name as a string (used for user space programs)

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
