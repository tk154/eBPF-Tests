#include <errno.h>

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "../../common_router.h"


int main(int argc, char* argv[]) {
    char map_path[32];
    snprintf(map_path, sizeof(map_path), "/sys/fs/bpf/%s", MAP_TO_STRING(ROUT_STATS_MAP));

    int fd = bpf_obj_get(map_path);
    if (fd < 0) {
        fprintf(stderr, "Error %d opening BPF object %s: %s\n", errno, map_path, strerror(errno));
        return 1;
    }

    int num_cpus = libbpf_num_possible_cpus();
	struct datarec values[num_cpus];

    struct ip_pair key;
    int rc = bpf_map_get_next_key(fd, NULL, &key);

    while (rc == 0) {
        if (bpf_map_lookup_elem(fd, &key, values) == 0) {
            struct datarec rec = {};
            for (int i = 0; i < num_cpus; i++) {
                rec.packets += values[i].packets;
                rec.bytes   += values[i].bytes;
            }

            char src[INET_ADDRSTRLEN];
            char dst[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &key.src, src, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &key.dst, dst, INET_ADDRSTRLEN);

            printf("Source: %s\n", src);
            printf("Destination: %s\n", dst);
            printf("Packets: %llu, %.2f GBytes\n\n", rec.packets, rec.bytes / 1024.0 / 1024.0 / 1024.0);
        }

        rc = bpf_map_get_next_key(fd, &key, &key);
    }

    return 0;
}
