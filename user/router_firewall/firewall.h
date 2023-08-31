#ifndef FIREWALL_RULES_H
#define FIREWALL_RULES_H


/**
 * For now, this functions reads the input, output and forward rules 
 * from each zone inside /etc/config/firewall and saves them inside the IF_RULES_MAP
 * @param obj The BPF object containing the IF_RULES_MAP
 * @returns 0 on success, negative error if IF_RULES_MAP couldn't be found inside the BPF object, errno for other errors
 * **/
int get_and_save_openwrt_firewall_rules(struct bpf_object* obj);

/**
 * This function saves some input, output and forward test rules defined in itself
 * @param obj The BPF object containing the IF_RULES_MAP
 * @returns 0 on success, negative error if IF_RULES_MAP couldn't be found inside the BPF object, errno for other errors
 * **/
int firewall_apply_test_rules(struct bpf_object* obj);


#endif
