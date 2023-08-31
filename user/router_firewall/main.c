#define _XOPEN_SOURCE 700   // Needed for sigaction
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "vlan.h"
#include "firewall.h"
#include "../common/bpf_loader.h"
#include "../../common_router_firewall.h"


// Currently not used
#define IFNAMES         (char*[]) { "eth0", "eth5" }                // The interfaces we want to attach to
#define IFNAMES_SIZE    (sizeof(IFNAMES) / sizeof(IFNAMES[0]))      // The number of interfaces

#define PROGNAME        "router_firewall_func"                      // Corresponds to the function name of the kernel program's main entry point


/**
 * Dummy signal interrupt handler
 * @param sig Occured signal
**/
void interrupt_handler(int sig) {}

int main(int argc, char* argv[]) {
    int rc = 1;

    // Check if the program type if provided in the command line
    if (argc < 2) {
        fputs("Missing program type argument: Must be either xdp or tc.\n", stderr);
        goto out;
    }

    // Parse the program type
    enum bpf_prog_type prog_type;
    char* prog_path;
    if (strcmp(argv[1], "xdp") == 0) {
        prog_type = BPF_PROG_TYPE_XDP;
        prog_path = "xdp_router_firewall.o";
    }
    else if (strcmp(argv[1], "tc") == 0) {
        prog_type = BPF_PROG_TYPE_SCHED_CLS;
        prog_path = "tc_router_firewall.o";
    }
    else {
        fprintf(stderr, "Program type %s is not allowed: Must be either xdp or tc.\n", argv[1]);
        goto out;
    }

    // Load the BPF object (including program and maps) into the kernel
    struct bpf_object_program* bpf = bpf_load_program(prog_path, PROGNAME, prog_type);
    if (bpf == NULL)
        goto out;

    // Retrieve all VLANs and save them inside the VLAN map
    if (get_and_save_vlans(bpf->obj) != 0)
        goto bpf_unload_program;

    // Save simple OpenWrt firewall rules inside the Rules map
    if (get_and_save_openwrt_firewall_rules(bpf->obj) != 0)
        goto bpf_unload_program;

    // Attach the program to all non-virtual interfaces
    if (bpf_attach_program(bpf->prog) != 0)
        goto bpf_unload_program;

    // Catch CTRL+C with the dummy handler
    struct sigaction act = { .sa_handler = interrupt_handler };
    sigaction(SIGINT, &act, NULL);

    // Wait until CTRL+C is pressed
    puts("Successfully loaded BPF program. Press CTRL+C to unload.");
    pause();
    puts("\nUnloading ...");

    // Detach the program from all interfaces
    bpf_detach_program(bpf->prog);

bpf_unload_program:
    // Unload the BPF object from the kernel
    bpf_unload_program(bpf);

    rc = 0;
out:
    return rc;
}
