import socket
from scapy.all import ARP, Ether, IP

from network_sniffer.packet import (
    BroadcastAdapter,
    create_arp_pkt,
    create_icmp_pkt,
    create_tcp_pkt,
    create_udp_pkt,
)


bca = BroadcastAdapter()


def arp_ping(target: str) -> list[dict]:
    pkt = create_arp_pkt(target)
    ans, _ = bca.sendp(pkt, timeout=3, verbose=0)
    return [{"MAC": recv[Ether].dst, "IP": recv[ARP].psrc} for _, recv in ans]


def icmp_ping(target: str) -> list[dict]:
    pkt = create_icmp_pkt(target)
    ans, _ = bca.send(pkt, timeout=3, verbose=0)
    return [{"MAC": recv[Ether].dst, "IP": recv[IP].dst} for _, recv in ans]


def tcp_ping(target: str) -> list[dict]:
    pkt = create_tcp_pkt(target, dport=80, flags="S")
    ans, _ = bca.send(pkt, timeout=3, verbose=0)
    return [{"MAC": recv[Ether].dst, "IP": recv[IP].dst} for _, recv in ans]


def udp_ping(target: str) -> list[dict]:
    pkt = create_udp_pkt(target, dport=0)
    ans, _ = bca.send(pkt, timeout=3, verbose=0)
    return [{"MAC": recv[Ether].dst, "IP": recv[IP].dst} for _, recv in ans]


def ping_active_hosts(target: str) -> list[dict]:
    pkt = create_arp_pkt(target)
    ans, _ = bca.sendp(pkt, timeout=3, verbose=0)

    host_list = []
    for _, recv in ans:
        try:
            hostname = socket.gethostbyaddr(recv[ARP].psrc)[0]
        except socket.herror:
            hostname = ""
        host_list.append(
            {"HOSTNAME": hostname, "MAC": recv[Ether].src, "IP": recv[ARP].psrc}
        )
    return host_list
