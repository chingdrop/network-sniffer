from scapy.all import sr, srp, ARP, Ether, IP, ICMP, TCP, UDP

from network_sniffer.commands.local_network import LocalNetwork


def arp_ping(target):
    host_list = []
    ans, unans = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target), timeout=3, verbose=0
    )
    for s, r in ans:
        host = {"MAC": r[Ether].dst, "IP": r[ARP].psrc}
        host_list.append(host)
    return host_list


def icmp_ping(target):
    host_list = []
    ans, unans = sr(IP(dst=target) / ICMP(), timeout=3, verbose=0)
    for s, r in ans:
        host = {"MAC": r[Ether].dst, "IP": r[IP].dst}
        host_list.append(host)
    return host_list


def tcp_ping(target):
    host_list = []
    ans, unans = sr(IP(dst=target) / TCP(dport=80, flags="S"), timeout=3, verbose=0)
    for s, r in ans:
        host = {"MAC": r[Ether].dst, "IP": r[IP].dst}
        host_list.append(host)
    return host_list


def udp_ping(target):
    host_list = []
    ans, unans = sr(IP(dst=target) / UDP(dport=0), timeout=3, verbose=0)
    for s, r in ans:
        host = {"MAC": r[Ether].dst, "IP": r[IP].dst}
        host_list.append(host)
    return host_list


def quick_discover(iface):
    network_ip = LocalNetwork.get_network_ip(iface)
    arp_list = arp_ping(str(network_ip))


def full_discover(iface):
    network_ip = LocalNetwork.get_network_ip(iface)
    arp_list = arp_ping(str(network_ip))
    icmp_list = icmp_ping(str(network_ip))
    tcp_list = tcp_ping(str(network_ip))
    udp_list = udp_ping(str(network_ip))
