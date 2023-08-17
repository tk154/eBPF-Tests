#ifndef COMMON_KERN_USER
#define COMMON_KERN_USER

#include <linux/in.h>


struct ip_pair {
	__be32 src;
	__be32 dst;
};

struct datarec {
    __u64 packets;
    __u64 bytes;
};


#endif
