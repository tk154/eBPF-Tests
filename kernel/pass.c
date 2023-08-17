#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#include "common.h"

SEC("pass")
int pass_fun(struct BPF_CTX* ctx) {
    return BPF_PASS;
}
