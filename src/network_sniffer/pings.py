import socket
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP
from scapy.sendrecv import srp

from src.network_sniffer.packet import (
    BroadcastAdapter,
    create_arp_pkt,
    create_icmp_pkt,
    create_tcp_pkt,
    create_udp_pkt,
)


bca = BroadcastAdapter()


def arp_ping(target: str) -> list[dict]:
    pkt = create_arp_pkt(target)
    ans, _ = bca.send_eth(pkt, timeout=3, verbose=0)
    return [{"MAC": rcv[Ether].dst, "IP": rcv[ARP].psrc} for _, rcv in ans]


def icmp_ping(target: str) -> list[dict]:
    pkt = create_icmp_pkt(target)
    ans, _ = bca.send_ip(pkt, timeout=3, verbose=0)
    return [{"MAC": rcv[Ether].dst, "IP": rcv[IP].dst} for _, rcv in ans]


def tcp_ping(target: str) -> list[dict]:
    pkt = create_tcp_pkt(target, dport=80, flags="S")
    ans, _ = bca.send_ip(pkt, timeout=3, verbose=0)
    return [{"MAC": rcv[Ether].dst, "IP": rcv[IP].dst} for _, rcv in ans]


def udp_ping(target: str) -> list[dict]:
    pkt = create_udp_pkt(target, dport=0)
    ans, _ = bca.send_ip(pkt, timeout=3, verbose=0)
    return [{"MAC": rcv[Ether].dst, "IP": rcv[IP].dst} for _, rcv in ans]

    host_list = []
    # This definitely could be done better, but I don't want to nest try/excepts
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)

    try:
        ans, _ = srp(pkt, timeout=3, verbose=0)
    except Exception as e:
        print(e)

    for _, r in ans:
        try:
            hostname = socket.gethostbyaddr(r[ARP].psrc)[0]
        except socket.herror:
            hostname = ""
        host_list.append({"HOSTNAME": hostname, "MAC": r[Ether].src, "IP": r[ARP].psrc})

    if verbose:
        message = (
            "\n".join(
                f'{host["MAC"]} : {host["IP"]} : {host["HOSTNAME"] or "No hostname record found"}'
                for host in host_list
            )
            if host_list
            else "No active hosts found."
        )
        print(message)

    return host_list
