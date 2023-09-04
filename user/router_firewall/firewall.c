#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if.h>

#include "firewall.h"
#include "../../common_router_firewall.h"

// Currently the uci command of OpenWrt is used to retrieve the zone rules from /etc/config/firewall
// Because of the sed command the output looks like: ZONE_INDEX,OPTION,VALUE1(,VALUE2)...
// The sed command has a bug since it only prints max. two interfaces (the fist and last) for a zone
#define UCI_ZONE_RULES_CMD "uci show firewall | sed -nE \"s/.*zone\\[(\\d+)\\]\\.(\\w+)='(\\w+)'(\\s'(\\w+)')*/\\1,\\2,\\3,\\5/p\""


/**
 * Assigns the rule Bitmask to the interface inside IF_RULES_MAP
 * @param vlan_map_fd Map fd for IF_RULES_MAP
 * @param ifname Name of the interface
 * @param vlan_id Rule Bitmask
 * @returns 0 on success, errno if an error occured
 * **/
int firewall_add_rule(int map_fd, char* ifname, __u8 rule) {
    // Try to get the interface index from the interface name
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Firewall Warning: Cannot find network interface %s: %s (Code: -%d)\n", ifname, strerror(errno), errno);
        return errno;
    }

    // Try to add the rule to the interface, a rule for the interface shouldn't already exist inside map
    if (bpf_map_update_elem(map_fd, &ifindex, &rule, BPF_NOEXIST) != 0) {
        fprintf(stderr, "Firewall Error: Cannot add rule to %s: %s (Code: -%d)\n", ifname, strerror(errno), errno);
        return errno;
    }

    return 0;
}

int firewall_apply_test_rules(struct bpf_object* obj) {
    // Simple struct to make the definition of the rules easier
    struct firewall_if_test_rule {
        char* ifname;
        __u8 rule;
    };

    // Define some test rules
    struct firewall_if_test_rule test_rules[] = {
        { .ifname = "eth0", .rule = IF_ACCEPT_ALL },
        { .ifname = "eth5", .rule = IF_ACCEPT_ALL | IF_ACCEPT_OUTPUT | IF_ACCEPT_FORWARD }
    };
    unsigned int test_rules_size = sizeof(test_rules) / sizeof(test_rules[0]);

    // Get the string name of the rules map and try to open it
    char* map_str = MAP_TO_STRING(IF_RULES_MAP);
    int map_fd = bpf_object__find_map_fd_by_name(obj, map_str);
    if (map_fd < 0) {
        fprintf(stderr, "Couldn't find map %s in %s\n", map_str, bpf_object__name(obj));
        return map_fd;
    }

    // Save the testing rules inside the map
    for (int i = 0; i < test_rules_size; i++) {
        int rc = firewall_add_rule(map_fd, test_rules[i].ifname, test_rules[i].rule);
        if (rc != 0)
            return rc;
    }

    return 0;
}

// Struct to create a linked list for the interface names
// Used to later apply a rule to them
struct if_node {
    char ifname[IFNAMSIZ];      // Interface name
    struct if_node* next;       // Pointer to the next entry of the list
};

/**
 * Dynamically allocates a new entry for the interface list
 * @param ifname Interface name
 * @returns On success a pointer to the newly created list entry, NULL if an allocation error occured
 * **/
struct if_node* create_if_node(char* ifname) {
    struct if_node* node = (struct if_node*)malloc(sizeof(struct if_node));
    if (node == NULL)
        return NULL;

    strncpy(node->ifname, ifname, sizeof(node->ifname));
    node->next = NULL;

    return node;
}

/**
 * Deallocates an entry of the interface list
 * @param node Pointer to the interface list entry
 * **/
void delete_if_node(struct if_node* node) {
    free(node);
}

/**
 * Saves the rule to all the interfaces given in the linked list inside IF_RULES_MAP
 * @param map_fd Map fd for IF_RULES_MAP
 * @param first_node Pointer to the start/first entry of the interface list
 * @param rule Rule to be applied to the interfaces
 * **/
void save_if_nodes_rules(int map_fd, struct if_node* first_node, if_rule rule) {
    struct if_node* next_node = first_node;

    // While the given linked list still has entries
    while (next_node != NULL) {
        // Save the rull of the curretn entry
        struct if_node* curr_node = next_node;
        firewall_add_rule(map_fd, curr_node->ifname, rule);

        // Move on the pointer and free the memory for the current entry
        next_node = curr_node->next;
        delete_if_node(curr_node);
    }
}

int get_and_save_openwrt_firewall_rules(struct bpf_object* obj) {
    // Get the string name of the rules map and try to open it
    char* map_str = MAP_TO_STRING(IF_RULES_MAP);
    int map_fd = bpf_object__find_map_fd_by_name(obj, map_str);
    if (map_fd < 0) {
        fprintf(stderr, "Couldn't find map %s in %s\n", map_str, bpf_object__name(obj));
        return map_fd;
    }

    // Execute the uci command and try to read its output
    FILE* uci = popen(UCI_ZONE_RULES_CMD, "r");
    if (uci == NULL) {
        fprintf(stderr, "Error %d executing uci: %s", errno, strerror(errno));
        return errno;
    }

    // Used to save index, interface list and rule of the current zone
    unsigned int last_zone_index = 0;
    struct if_node* first_node = NULL;
    if_rule rule = 0;

    char line[64];
    while (fgets(line, sizeof(line), uci) != NULL) {
        // Remove the newline character from the end of the string/line
        line[strcspn(line, "\n")] = '\0';

        // Split the string at every "," and try to read the zone index
        const char* delim = ",";
        char* zone_index_str = strtok(line, delim);
        if (zone_index_str == NULL) {
            fputs("Error reading firewall zone rule from uci", stderr);
            continue;
        }

        // Try to parse the zone index into an integer
        char* endptr = NULL;
        unsigned int zone_index = strtol(zone_index_str, &endptr, 10);
        if (endptr == NULL) {
            fprintf(stderr, "Error: Couldn't parse zone index %s from uci", zone_index_str);
            continue;
        }

        // If the zone index has changed (i.e. this line is the start of a new zone config)
        if (zone_index != last_zone_index) {
            // Save the rule for the interfaces inside the map
            save_if_nodes_rules(map_fd, first_node, rule);

            last_zone_index = zone_index;
            first_node = NULL;
            rule = 0;
        }

        // Try to read the option name
        char* option = strtok(NULL, delim);
        if (option == NULL) {
            fputs("Error reading option from firewall zone", stderr);
            continue;
        }

        // If the option name equals network i.e. the network interface names
        if (strcmp(option, "network") == 0) {
            // Try to split the remaining line and read the first network interface (there must be one at least)
            char* ifname = strtok(NULL, delim);
            if (ifname == NULL) {
                fputs("Error reading network interface from firewall zone", stderr);
                continue;
            }

            // Save the first interface inside the linked list
            // The interfaces can't be added to the map already
            // since we don't know if there are more rules to read
            struct if_node* curr_node = create_if_node(ifname);
            first_node = curr_node;

            struct if_node* prev_node = curr_node;
            ifname = strtok(NULL, delim);

            // If there are more interfaces, also add them to the list
            while (ifname != NULL) {
                curr_node = create_if_node(ifname);

                prev_node->next = curr_node;
                prev_node = curr_node;

                ifname = strtok(NULL, delim);
            }
        }
        // If the line contains the input rule
        else if (strcmp(option, "input") == 0) {
            char* value = strtok(NULL, delim);

            // Only set the rule to allowed if a valid ACCEPT was read
            if (strcmp(value, "ACCEPT") == 0)
                rule |= IF_ACCEPT_INPUT;
        }
        // If the line contains the output rule
        else if (strcmp(option, "output") == 0) {
            char* value = strtok(NULL, delim);

            // Only set the rule to allowed if a valid ACCEPT was read
            if (strcmp(value, "ACCEPT") == 0)
                rule |= IF_ACCEPT_OUTPUT;
        }
        // If the line contains the forward rule
        else if (strcmp(option, "forward") == 0) {
            char* value = strtok(NULL, delim);

            // Only set the rule to allowed if a valid ACCEPT was read
            if (strcmp(value, "ACCEPT") == 0)
                rule |= IF_ACCEPT_FORWARD;
        }
    }

    // If there are no more lines to read but the EOF was also not reached -> error occured while reading
    if (!feof(uci)) {
        fprintf(stderr, "Error %d while reading uci output: %s\n", errno, strerror(errno));
        pclose(uci);

        return errno;
    }

    // Since the last zone rule is not followed by another line, save it seperately at the end
    save_if_nodes_rules(map_fd, first_node, rule);    
    pclose(uci);

    return 0;
}
