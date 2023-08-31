#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_vlan.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <sys/socket.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "../../common_router_firewall.h"

// Path to the file where the VLAN names, IDs and interfaces are stored in
// Except for the two header lines, each line consists of: VLAN_NAME | VLAN_ID | VLAN_INTERFACE
#define VLAN_CONFIG_PATH "/proc/net/vlan/config"

/**
 * Assigns the VLAN ID to the interface inside IF_VLANS_MAP
 * @param vlan_map_fd Map fd for IF_VLANS_MAP
 * @param ifname Name of the interface
 * @param vlan_id VLAN ID
 * @returns 0 on success, -1 if the max. number of VLANs was reached on the interface, errno for other errors
 * **/
int add_vlan_to_map(int vlan_map_fd, char* ifname, __u16 vlan_id) {
    // Try to get the interface index from the interface name
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Error %d finding network interface %s: %s\n", errno, ifname, strerror(errno));
        return errno;
    }

    // Check if the interface already exists inside the map ...
    struct if_vlans vlans;
    if (bpf_map_lookup_elem(vlan_map_fd, &ifindex, &vlans) != 0) {
        // ... if not create a new single VLAN entry inside the map
		vlans.count = 1;
        vlans.vlans[0] = vlan_id;

		if (bpf_map_update_elem(vlan_map_fd, &ifindex, &vlans, BPF_NOEXIST) != 0) {
            fprintf(stderr, "Error %d adding VLAN to %s: %s\n", errno, ifname, strerror(errno));
            return errno;
        }
	}
	else {
        // Check if the max. number of VLANs is already reached for that interface
        if (vlans.count == IF_MAX_VLANS) {
            fprintf(stderr, "Error: Max. number of VLANs reached on interface %s\n", ifname);
            return -1;
        }

        vlans.vlans[vlans.count++] = vlan_id;
		if (bpf_map_update_elem(vlan_map_fd, &ifindex, &vlans, BPF_EXIST) != 0) {
            fprintf(stderr, "Error %d adding VLAN to %s: %s\n", errno, ifname, strerror(errno));
            return errno;
        }
	}

    return 0;
}

int get_and_save_vlans(struct bpf_object* obj) {
    // Get the string name of the VLAN map and try to open it
    char* map_str = MAP_TO_STRING(IF_VLANS_MAP);
    int map_fd = bpf_object__find_map_fd_by_name(obj, map_str);
    if (map_fd < 0) {
        fprintf(stderr, "Couldn't find map %s in %s\n", map_str, bpf_object__name(obj));
        return map_fd;
    }

    FILE* file = fopen(VLAN_CONFIG_PATH, "r");
    if (file == NULL) {
        fprintf(stderr, "Error %d while opening %s: %s\n", errno, VLAN_CONFIG_PATH, strerror(errno));
        return errno;
    }

    int rc = 0;
    char line[64];

    // Try to read the two header lines of the file
    for (int i = 0; i < 2; i++) {
        if (fgets(line, sizeof(line), file) == NULL) {
            fprintf(stderr, "Error reading header from %s: ", VLAN_CONFIG_PATH);

            if (feof(file)) {
                fputs("end of file reached\n", stderr);
                rc = EOF;
            }
            else {
                fprintf(stderr, "%s (%d)\n", strerror(errno), errno);
                rc = errno;
            }

            goto file_close;
        }
    }

    // Read the remaining list (each line contains one VLAN interface)
    while (fgets(line, sizeof(line), file) != NULL) {
        // Remove the newline character from the end of the string/line
        line[strcspn(line, "\n")] = '\0';

        // Split the string at every " | " and try to read the VLAN name
        const char* delim = " | ";
        char* vlan_name = strtok(line, delim);
        if (vlan_name == NULL) {
            fprintf(stderr, "Error: Couldn't read VLAN name from %s\n", VLAN_CONFIG_PATH);
            continue;
        }

        // Try to read the VLAN ID
        char* vlan_id_str = strtok(NULL, delim);
        if (vlan_id_str == NULL) {
            fprintf(stderr, "Error: Couldn't read VLAN ID of VLAN %s\n", vlan_name);
            continue;
        }

        // Try to parse the VLAN ID into an integer
        __u16 vlan_id = strtol(vlan_id_str, NULL, 10);
        if (vlan_id == 0) {
            fprintf(stderr, "Error: Couldn't parse VLAN ID %s of VLAN %s\n", vlan_id_str, vlan_name);
            continue;
        }

        // Try to read the interface of the VLAN
        char* vlan_if = strtok(NULL, delim);
        if (vlan_if == NULL) {
            fprintf(stderr, "Error: Couldn't read network interface of VLAN %s\n", vlan_name);
            continue;
        }

        // Add the VLAN to IF_VLANS_MAP
        add_vlan_to_map(map_fd, vlan_if, vlan_id);
    }

    // If there are no more lines to read but the EOF was also not reached -> error occured while reading
    if (!feof(file)) {
        printf("Error %d while reading from %s: %s\n", errno, VLAN_CONFIG_PATH, strerror(errno));
        rc = errno;
    }

file_close:
    fclose(file);

    return rc;
}
