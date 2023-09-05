# Kernel programs
The kernel programs for both hooks are written in C code and afterward compiled into BPF objects.
The entry point for a BPF program is a function marked by the SEC("&lt;section name&gt;") macro found inside <bpf/bpf_helpers.h>. The return value of this function determines what to do with the received package, for example, if it should be passed or dropped. The programs for both hooks have the same logic inside their function bodies; the only things changing are:
  1. The parameter passed to the entry point function is in the case of XDP a raw xdp_md and for TC the allocated __sk_buf struct
  2. The return value which is defined by several macros is different e.g. for letting a packet pass there are XDP_PASS and TC_ACT_OK respectively (both also hold different integer values)
  3. Since the SKB buffer is available for TC programs it can be used to e.g. access already-processed VLAN metadata which have to be processed manually in an XDP program
<br>

Therefore the source code of a program inside this repository is written for both BPF hooks. The Makefile will set the macro XDP_PROGRAM and TC_PROGRAM respectively depending on which target has been selected when compiling the source files. The "common_xdp_tc.h" header file will use those macros to select the appropriate packet struct and return values. A TC program can also use that macro to access a field inside its SKB buffer which is not available inside the XDP buffer.
<br><br>
The macros defined in "common_xdp_tc.h" for the BPF programs hold the following values:
<br>

<table>
  <tr>
    <th></th>
    <th>Macro</th>
    <th>XDP</th>
    <th>TC</th>
  </tr>
  <tr>
    <th>Parameter</th>
    <td>BPF_CTX</td>
    <td>xdp_md</td>
    <td>__skb_buff</td>
  </tr>
  <tr>
    <th rowspan="0">Return value</th>
    <td>BPF_PASS</td>
    <td>XDP_PASS</td>
    <td>TC_ACT_OK</td>
  </tr>
  <tr>
    <td>BPF_DROP</td>
    <td>XDP_DROP</td>
    <td>TC_ACT_SHOT</td>
  </tr>
  <tr>
    <td>BPF_REDIRECT</td>
    <td>XDP_REDIRECT</td>
    <td>TC_ACT_REDIRECT</td>
  </tr>
</table>
<br>

Currently, the Makefile contains the following targets:
<br>

<table>
  <tr>
    <th>Target</th>
    <th>Description</th>
  </tr>
  <tr>
    <td>all</td>
    <td>Builds the xdp and tc target</td>
  </tr>
  <tr>
    <td>xdp</td>
    <td>Sets the XDP_PROGRAM macro, compiles all *.c source files and places the BPF object files in obj/xdp_*.o</td>
  </tr>
  <tr>
    <td>tc</td>
    <td>Sets the TC_PROGRAM macro, compiles all *.c source files and places the BPF object files in obj/tc_*.o</td>
  </tr>
  <tr>
    <td>clean</td>
    <td>Deletes all compiled BPF object files by deleting the obj folder</td>
  </tr>
</table>
<br>

For now, there are the following kernel programs:
<br>

<table>
  <tr>
    <th>Program/Section name</th>
    <th>C source code file</th>
    <th>Description</th>
  </tr>
  <tr>
    <td>forward</td>
    <td>forward.c</td>
    <td>Only forwards packages from a source IPv4 address SRC_ADDR to a destination IPv4 address DST_ADDR by using the helper function bpf_redirect to redirect them manually to another interface. The egress interface index IFINDEX, mac address IF_MAC, and mac address of the destination DST_MAC must be also set manually.</td>
  </tr>
  <tr>
    <td>router</td>
    <td>router.c</td>
    <td>Redirects all incoming IPv4 packages to another network interface, if possible. Uses the BPF helper function bpf_fib_lookup to determine the next hop. Depending on the return code of bpf_fib_lookup, the package might also be passed to the kernel or dropped. When a package is being redirected, its number of Bytes and the source and destination address are saved inside the rout_stats_map map which can be read by the user-space program routing_stats.</td>
  </tr>
  <tr>
    <td>router_iperf</td>
    <td>router_iperf.c</td>
    <td>Similar to the router program but only packages destined to the default iperf port (5001 TCP and UDP) are saved inside the rout_stats_map map.</td>
  </tr>
  <tr>
    <td>router_firewall</td>
    <td>router_firewall.c</td>
    <td>Is similar to the router program but it checks if the VLAN of the incoming package and interface(s) matches by reading from the if_vlans_map map and if the incoming package is allowed to be received, sent, and redirected on the interface(s) by reading from the if_rules_map map. Both maps are written by the user-space program router_firewall hence this program should be loaded by it.</td>
  </tr>
</table>
