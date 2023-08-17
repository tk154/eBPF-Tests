#ifndef COMMON_XDP_TC
#define COMMON_XDP_TC

#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#ifndef TC_PROGRAM
#define BPF_PASS        XDP_PASS
#define BPF_DROP        XDP_DROP
#define BPF_REDIRECT    XDP_REDIRECT
#define BPF_CTX         xdp_md
#else
#define BPF_PASS        TC_ACT_OK
#define BPF_DROP        TC_ACT_SHOT
#define BPF_REDIRECT    TC_ACT_REDIRECT
#define BPF_CTX         __sk_buff
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy(dest, src, n)
#endif

#endif
