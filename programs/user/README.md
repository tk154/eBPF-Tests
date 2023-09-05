# User(-space) programs
The user programs load and attach kernel programs to the XDP or TC hook, read and print package statistics from them (e.g., received bytes, source address), or communicate with them by reading and writing from their maps. The "libbpf" library, located at Libraries inside OpenWrts build system configuration interface, is needed to compile the programs.<br>
Since those programs primarily run on an x86 system running OpenWrt for this repository, a variable OPENWRT_DIR can be passed through the command line specifying the OpenWrt root directory to allow cross-compiling for x86, e.g.:
<pre>make OPENWRT_DIR=~/openwrt</pre>
<br>
When the compilation has finished, the user can execute the programs like any other binary program, e.g.:
<pre>./routing_stats</pre>
<br>

## routing_stats
This program reads and prints the number, the total GigaByte count, and the source and destination IPv4 address of routed packages between two clients from the rout_stats_map map provided by the kernel programs whose names start with "routing."
<br><br>

## router_firewall
When routing packages, BPF programs typically use the helper function bpf_fib_lookup to retrieve its next hop. Since this function does only a FIB lookup in the routing tables, it doesn't check for firewall rules configured by the user through "iptables" or "nftables." Additionally, two VLAN fields are inside the bpf_fib_lookup struct, but they are currently unused and always set to zero.<br>
This program retrieves all VLAN interfaces and (currently) some simple firewall rules and stores them inside the if_vlans_map and if_rules_map map, respectively. It reads the VLAN interfaces from the file "/proc/net/vlan/config" containing the VLAN name, ID, and (parent) interface. It currently only reads the input, output, and forward rules from OpenWrt's "uci" command and is therefore only compatible with OpenWrt.<br>
After it has finished filling the maps, it will try to attach the router_firewall BPF kernel program to all non-virtual interfaces of the device. Per a command line argument, the user must specify if the BPF program should be attached to the XDP or TC hook of the interfaces, e.g.:
<pre># ./router_firewall xdp
Successfully loaded BPF program. Press CTRL+C to unload</pre>
<br>

When the user enters CTRL+C now, it will detach the BPF program from the interfaces and unload it from the kernel. The following picture shows the sequence diagram of the program:
<br><br>
<img src="https://github.com/tk154/eBPF-Tests/blob/main/pictures/user_router_firewall.vpd.png">
