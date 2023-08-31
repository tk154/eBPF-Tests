#ifndef VLAN_H
#define VLAN_H

/**
 * Retrieves all VLANs and saves them inside the IF_VLANS_MAP of the BPF object
 * @param obj BPF object containing the IF_VLANS_MAP where the VLAN IDs will be saved
 * @returns 0 on success, negative error if IF_VALNS_MAP couldn't be found inside the BPF object, errno for other errors
 * **/
int get_and_save_vlans(struct bpf_object* obj);

#endif
