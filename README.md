# High-performance networking with eBPF
## Table of Contents
1. [Motivation](#motivation)
2. [eBPF](#ebpf)
    1. [The XDP hook](#the-xdp-hook)
    2. [The TC hook](#the-tc-hook)
    3. [BPF programs](#bpf-programs)
<br>

## Motivation
The Linux operating system is often used for high-performance networking applications due to its stability, flexibility, and open-source innovations. One such application is the routing of network packages on a high-throughput network switch in cloud/data centers or storage environments.
The key role here plays the network stack which is divided into the following layers according to the TCP/IP model:

<img src=https://github.com/tk154/eBPF-Tests/blob/main/pictures/network-stack.png height=400px>
<br>

Typically when routing packages, only layers 1 to 4 are used while the application layer 5 can be used for monitoring or manipulating the routing tables. While the network stack evolved throughout the past years with support for new protocols and features, it becomes more and more complex, which introduces overhead and currently hampers its throughput potential to about 40Gb/s. Limitations/bottlenecks include memory (de-)allocations, data copy operations, (un-)lock operations, and scheduling in their respective layers. Over the past years several solution approaches have been proposed to overcome this, one of them is eBPF.
<br><br>

## eBPF
eBPF (extended Berkeley Packet Filter) is a technology within the Linux kernel that allows it to dynamically program the kernel without requiring modifications to its source code. Developers can write their programs in C code, compile them to BPF objects and attach them to several so-called hooks inside the network stack. It is typically used to implement efficient networking, improved tracing of data packets, and enhanced security. It is a flexible approach to add functionality without having to recompile or restart the kernel while also being stability-secure since all to-be-attached programs are verified to not crash the kernel.

As already mentioned, there are several hooks where a BPF program can be attached inside the network stack which can be found in the following picture:

<img src=https://github.com/tk154/eBPF-Tests/blob/main/pictures/bpf-kernel-hooks.png>
Source: https://cyral.com/blog/how-to-ebpf-accelerating-cloud-native/
<br><br><br>

The idea here with BPF is to intercept the data package as soon as possible before or inside the network stack to avoid unnecessary operations for a specific use case which should subsequentially benefit performance. While all hooks can be used to monitor certain events, only the two earliest hooks in the stack, namely XDP and TC, can filter and redirect incoming data packages.
<br><br>

### The XDP hook
XDP (eXpress Data Path) is the earliest hook inside the Linux kernel. Its programs are attached to the driver of the NIC hence it comes even before the network stack itself. Because of this, the XDP hook is considered the fastest BPF hook inside the Linux kernel.

<img src=https://github.com/tk154/eBPF-Tests/blob/main/pictures/linux-network-stack-with-xdp.png>
Source: https://blogs.igalia.com/dpino/2019/01/10/the-express-data-path/
<br><br><br>

But there is a catch: NIC drivers need to support this so-called "XDP native" mode otherwise they have to be attached through the so-called "XDP generic" mode inside the network stack. The problems here are that first, the packet data has already been copied to a pre-allocated SKB buffer, and second, this mode was never meant by the developers of XDP to be used in a production environment but rather in an experimental testbed environment.

This could result in such a big performance hit that the hoped-for gain might be zero or even lower. Luckily a <a href="https://lore.kernel.org/bpf/20220318123323.75973f84@kicinski-fedora-pc1c0hjn.dhcp.thefacebook.com/T/" target="_blank">patch</a> (thanks to ...) has been submitted which reduces unnecessary SKB re-allocations by reducing the mandatory XDP headroom that should retain the performance gains. Furthermore, XDP programs can only be attached to the ingress of a network interface and packets can only be redirected to the egress of an interface.
<br><br>

### The TC hook
The TC (traffic control) BPF hook comes right after the XDP hook but is already located inside the network stack. Therefore, like for the "XDP generic" mode, package contents have already been copied into a pre-allocated SKB buffer. Although this decreases performance, the SKB buffer has much more package metadata available than the raw XDP buffer. TC programs can also be attached to the egress of a network interface and packets can also be redirected to the ingress of an interface.
<br><br><br>

### BPF programs
This repository focuses on creating some XDP/TC programs, testing them by attaching them to their respective hooks (and in the case of XDP in its various modes), and comparing them in terms of performance. The <a href="https://github.com/tk154/eBPF-Tests/tree/main/kernel">kernel programs</a> are the actual to-be-attached BPF programs for filtering incoming packages whereas the <a href="https://github.com/tk154/eBPF-Tests/tree/main/user">user(-space) programs</a> monitor the packages and actions of the kernel programs. The "libbpf" library, located at Libraries inside OpenWrts build system configuration interface, is needed to compile both program types.
