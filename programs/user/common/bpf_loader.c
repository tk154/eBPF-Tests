#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>

#include "bpf_loader.h"

// For now, attach XDP programs in SKB/Generic mode
#define XDP_ATTACH_FLAGS XDP_FLAGS_SKB_MODE


/**
 * Used to check if a network interface is virtual
 * @param ifname Name of the network interface
 * @returns 1 if it is a virtual interface, 0 if it is physical
 * **/
int if_is_virtual(char* ifname) {
    char path[64];
    snprintf(path, sizeof(path), "/sys/class/net/%s/device", ifname);

    // Check if the device file is present, if not the interface is virtual
    return access(path, F_OK) != 0;
}

struct bpf_object_program* bpf_load_program(char* prog_path, char* prog_name, enum bpf_prog_type prog_type) {
    struct bpf_object_program* bpf = (struct bpf_object_program*)malloc(sizeof(struct bpf_object_program));

    // Try to open the BPF object file, return on error
    bpf->obj = bpf_object__open_file(prog_path, NULL);
    if (!bpf->obj) {
        fprintf(stderr, "Error %d opening BPF object file: %s\n", errno, strerror(errno));
        goto error;
    }

    // Try to find the program inside the object file, return on error
    bpf->prog = bpf_object__find_program_by_name(bpf->obj, prog_name);
    if (!bpf->prog) {
        fprintf(stderr, "Couldn't find program %s in %s\n", prog_name, prog_path);
        goto bpf_object__close;
    }
    
    bpf_program__set_type(bpf->prog, prog_type);

    // Try to load the BPF object into the kernel, return on error
    if (bpf_object__load(bpf->obj) != 0) {
        fprintf(stderr, "Error %d loading BPF program into kernel: %s\n", errno, strerror(errno));
        goto bpf_object__close;
    }

    return bpf;

bpf_object__close:
    bpf_object__close(bpf->obj);

error:
    free(bpf);

    return NULL;
}

void bpf_unload_program(struct bpf_object_program* bpf) {
    // Unpin the maps from /sys/fs/bpf
    bpf_object__unpin_maps(bpf->obj, NULL);
    bpf_object__close(bpf->obj);

    free(bpf);
}

int bpf_if_attach_program(struct bpf_program* prog, char* ifname) {
    // Get the interface index from the interface name
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Error %d finding network interface %s: %s\n", errno, ifname, strerror(errno));
        return errno;
    }
    
    enum bpf_prog_type prog_type = bpf_program__type(prog);
    switch (prog_type) {
        case BPF_PROG_TYPE_XDP:
            // Attach the program to the XDP hook
            if (bpf_xdp_attach(ifindex, bpf_program__fd(prog), XDP_ATTACH_FLAGS, NULL) != 0) {
                fprintf(stderr, "Error %d attaching XDP program: %s\n", errno, strerror(errno));
                return errno;
            }
        break;

        case BPF_PROG_TYPE_SCHED_CLS:
            DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
            DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = bpf_program__fd(prog));

            // Create a TC hook on the ingress of the interface
            // bpf_tc_hook_create will return an error and print an error message if the hook already exists
            int rc = bpf_tc_hook_create(&hook);
            if (rc == -EEXIST)
                fprintf(stderr, "TC hook already exists on %s. You can ignore the kernel error message.\n\n", ifname);
            else if (rc != 0) {
                fprintf(stderr, "Error %d creating TC hook: %s\n", errno, strerror(errno));
                return errno;
            }

            // Attach the TC prgram to the created hook
            if (bpf_tc_attach(&hook, &opts) != 0) {
                fprintf(stderr, "Error %d attaching TC program on %s: %s\n", errno, ifname, strerror(errno));
                hook.attach_point |= BPF_TC_EGRESS;
                bpf_tc_hook_destroy(&hook);

                return errno;
            }
        break;

        // If the program is not of type XDP or TC
        default:
            fprintf(stderr, "Error: BPF program type %d is not supported.\n", prog_type);
            return -1;
    }

    return 0;
}

void bpf_if_detach_program(struct bpf_program* prog, char* ifname) {
    // Get the interface index from the interface name
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Error %d finding network interface %s: %s\n", errno, ifname, strerror(errno));
        return;
    }

    enum bpf_prog_type prog_type = bpf_program__type(prog);
    switch (prog_type) {
        case BPF_PROG_TYPE_XDP:
            // Detach the program from the XDP hook
            bpf_xdp_detach(ifindex, XDP_ATTACH_FLAGS, NULL);
        break;

        case BPF_PROG_TYPE_SCHED_CLS:
            DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
            DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = bpf_program__fd(prog));

            /* It should be possible to detach the TC program from the hook, 
               check the hook if there is still another program attached to it
               and destroy the hook if not, but bpf_tc_detach always returns Invalid argument(-22)
               which means that TC programs cannot be detached so for now just destroy the hook
               although there might be other programs attached to it */
            //printf("detach: %d\n", bpf_tc_detach(&hook, &opts));

            //if (bpf_tc_query(&hook, NULL) == -ENOENT) {
                // Needed to really destroy the qdisc hook and not just detaching the programs from it
                hook.attach_point |= BPF_TC_EGRESS;
                bpf_tc_hook_destroy(&hook);
            //}
        break;

        // If the program is not of type XDP or TC
        default:
            fprintf(stderr, "Error: BPF program type %d is not supported.\n", prog_type);
    }
}

int bpf_ifs_attach_program(struct bpf_program* prog, char* ifnames[], unsigned int ifname_size) {
    // Iterate to all the given interfaces and attache the program to them
    for (int i = 0; i < ifname_size; i++) {
        int rc = bpf_if_attach_program(prog, ifnames[i]);
        if (rc != 0) {
            // If an error occured while attaching to one interface, detach all the already attached programs
            while (--i >= 0)
                bpf_if_detach_program(prog, ifnames[i]);

            return rc;
        }
    }

    return 0;
}

void bpf_ifs_detach_program(struct bpf_program* prog, char* ifnames[], unsigned int ifname_size) {
    // Iterate to all the given interfaces and detache the program from them
    for (int i = 0; i < ifname_size; i++)
        bpf_if_detach_program(prog, ifnames[i]);
}

int bpf_attach_program(struct bpf_program* prog) {
    // Retrieve the name and index of all network interfaces
    struct if_nameindex* ifaces = if_nameindex();
    if (ifaces == NULL) {
        fprintf(stderr, "Error %d retrieving network interfaces: %s\n", errno, strerror(errno));
        return errno;
    }

    int rc = 0;
    for (struct if_nameindex* iface = ifaces; iface->if_index != 0 && iface->if_name != NULL; iface++) {
        // Check if the device is not a virtual one
        if (!if_is_virtual(iface->if_name)) {
            rc = bpf_if_attach_program(prog, iface->if_name);

            if (rc != 0) {
                // If an error occured while attaching to one interface, detach all the already attached programs
                while (--iface >= ifaces)
                    bpf_if_detach_program(prog, iface->if_name);

                break;
            }
        }
    }

    // Retrieved interfaces are dynamically allocated, so they must be freed
    if_freenameindex(ifaces);
    return rc;
}

int bpf_detach_program(struct bpf_program* prog) {
    // Retrieve the name and index of all network interfaces
    struct if_nameindex* ifaces = if_nameindex();
    if (ifaces == NULL) {
        fprintf(stderr, "Error %d retrieving network interfaces: %s\n", errno, strerror(errno));
        return errno;
    }

    for (struct if_nameindex* iface = ifaces; iface->if_index != 0 && iface->if_name != NULL; iface++)
        // Check if the device is not a virtual one
        if (!if_is_virtual(iface->if_name))
            bpf_if_detach_program(prog, iface->if_name);

    // Retrieved interfaces are dynamically allocated, so they must be freed
    if_freenameindex(ifaces);
    return 0;
}
